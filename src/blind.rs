use aho_corasick::AhoCorasick;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Secret blinding: replaces sensitive substrings with deterministic
/// tokens before the request leaves the machine, and can reverse them
/// in the upstream response.
///
/// Two detectors:
///   * `builtin` — regexes for common credential shapes (API keys,
///     tokens, JWTs, PEM blocks). Works at zero config.
///   * `custom`  — literal Aho-Corasick over user-configured strings
///     (project names, internal hostnames, anything literal).
///
/// Tokens are `⟦EG:xxxxxxxxxxxx⟧` where the hex is keyed on the
/// secret, so the same secret always blinds to the same token (dedup
/// stays intact) while different secrets never collide.
pub struct Blinder {
    builtin: Vec<Regex>,
    custom: Option<AhoCorasick>,
    /// token -> original secret, populated lazily per blind() call
    /// (regex matches are data-dependent, so the map is built at
    /// runtime, not construction).
    map: parking_lot::Mutex<HashMap<String, String>>,
    unblind: bool,
}

/// Credential shapes blinded at zero config.
const BUILTIN_PATTERNS: &[&str] = &[
    // OpenAI / Anthropic / generic API keys
    r"sk-[A-Za-z0-9_\-]{16,}",
    r"sk-ant-[A-Za-z0-9_\-]{16,}",
    // AWS
    r"AKIA[0-9A-Z]{16}",
    r"ASIA[0-9A-Z]{16}",
    // GitHub tokens
    r"gh[pousr]_[A-Za-z0-9]{20,}",
    r"github_pat_[A-Za-z0-9_]{20,}",
    // Slack
    r"xox[baprs]-[A-Za-z0-9\-]{10,}",
    // Google
    r"AIza[0-9A-Za-z_\-]{35}",
    // JWTs (header.payload.signature)
    r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    // PEM private keys
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    // Bearer tokens
    r"Bearer [A-Za-z0-9_\-\.=]{20,}",
    // Generic long hex secrets (32+ chars, e.g. webhook secrets)
    r"\b[0-9a-fA-F]{40,}\b",
];

impl Blinder {
    /// `custom`: literal substrings to blind on top of the builtins.
    /// `use_builtin`: master switch for the regex set.
    /// `unblind`: allow restoring secrets in upstream responses.
    pub fn new(custom: &[String], use_builtin: bool, unblind: bool) -> Self {
        let builtin = if use_builtin {
            BUILTIN_PATTERNS
                .iter()
                .map(|p| Regex::new(p).expect("builtin regex"))
                .collect()
        } else {
            Vec::new()
        };
        let pats: Vec<&String> = custom.iter().filter(|p| !p.is_empty()).collect();
        let custom_ac = if pats.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                    .build(pats.iter().map(|s| s.as_str()))
                    .expect("aho-corasick build"),
            )
        };
        Self {
            builtin,
            custom: custom_ac,
            map: parking_lot::Mutex::new(HashMap::new()),
            unblind,
        }
    }

    /// Blind all detected secrets in `text`. Returns (text, hits).
    pub fn blind(&self, text: &str) -> (String, usize) {
        let mut out = text.to_string();
        let mut hits = 0usize;

        for re in &self.builtin {
            let mut replaced = String::with_capacity(out.len());
            let mut last = 0;
            for m in re.find_iter(&out.clone()) {
                let secret = m.as_str();
                let token = self.register(secret);
                replaced.push_str(&out[last..m.start()]);
                replaced.push_str(&token);
                last = m.end();
                hits += 1;
            }
            replaced.push_str(&out[last..]);
            out = replaced;
        }

        if let Some(ac) = &self.custom {
            let mut replaced = String::with_capacity(out.len());
            let mut last = 0;
            for m in ac.find_iter(&out.clone()) {
                let secret = &out[m.start()..m.end()];
                let token = self.register(secret);
                replaced.push_str(&out[last..m.start()]);
                replaced.push_str(&token);
                last = m.end();
                hits += 1;
            }
            replaced.push_str(&out[last..]);
            out = replaced;
        }

        (out, hits)
    }

    fn register(&self, secret: &str) -> String {
        let token = token_for(secret);
        self.map.lock().insert(token.clone(), secret.to_string());
        token
    }

    /// Restore secrets in a response body. Only call on text destined
    /// for the original client.
    pub fn unblind(&self, text: &str) -> String {
        if !self.unblind {
            return text.to_string();
        }
        let mut out = text.to_string();
        for (token, secret) in self.map.lock().iter() {
            if out.contains(token.as_str()) {
                out = out.replace(token.as_str(), secret);
            }
        }
        out
    }

    pub fn is_active(&self) -> bool {
        !self.builtin.is_empty() || self.custom.is_some()
    }
}

fn token_for(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"edge_gate_blind_v1:");
    h.update(secret.as_bytes());
    let digest = h.finalize();
    format!("\u{27E6}EG:{}\u{27E7}", &hex::encode(digest)[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catches_openai_key() {
        let b = Blinder::new(&[], true, true);
        let (out, hits) = b.blind("key: sk-abcdefghijklmnop1234567890 here");
        assert_eq!(hits, 1);
        assert!(!out.contains("sk-abcdefghijklmnop1234567890"));
    }

    #[test]
    fn builtin_catches_jwt_and_aws() {
        let b = Blinder::new(&[], true, true);
        let (out, hits) =
            b.blind("jwt eyJhbGciOiJ9.eyJzdWIiOiIxIn0.signature AKIAIOSFODNN7EXAMPLE");
        assert!(hits >= 2, "hits={hits} out={out}");
        assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn builtin_disabled() {
        let b = Blinder::new(&[], false, true);
        let (out, hits) = b.blind("key: sk-abcdefghijklmnop1234567890");
        assert_eq!(hits, 0);
        assert!(out.contains("sk-abcdefghijklmnop1234567890"));
    }

    #[test]
    fn custom_literal_still_works() {
        let b = Blinder::new(&["proj-nightingale".to_string()], true, true);
        let (out, hits) = b.blind("deploy proj-nightingale tonight");
        assert_eq!(hits, 1);
        assert!(!out.contains("proj-nightingale"));
        let back = b.unblind(&out);
        assert!(back.contains("proj-nightingale"));
    }

    #[test]
    fn unblind_off_means_off() {
        let b = Blinder::new(&["secret".to_string()], false, false);
        let (out, _) = b.blind("the secret thing");
        let back = b.unblind(&out);
        assert_eq!(back, out);
    }

    #[test]
    fn same_secret_same_token() {
        let b = Blinder::new(&["hunter2".to_string()], false, true);
        let (a, _) = b.blind("hunter2");
        let (c, _) = b.blind("hunter2");
        assert_eq!(a, c);
    }
}
