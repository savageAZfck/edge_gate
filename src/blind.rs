use aho_corasick::AhoCorasick;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Secret blinding: replaces configured sensitive substrings with
/// deterministic tokens before the request leaves the machine, and can
/// reverse them in the upstream response.
///
/// Tokens are `⟦EG:xxxxxxxxxxxx⟧` where the hex is keyed on the secret, so
/// the same secret always blinds to the same token (dedup stays intact)
/// while different secrets never collide.
pub struct Blinder {
    ac: Option<AhoCorasick>,
    /// token -> original secret, for unblinding responses.
    map: HashMap<String, String>,
}

impl Blinder {
    pub fn new(patterns: &[String]) -> Self {
        let patterns: Vec<&String> = patterns.iter().filter(|p| !p.is_empty()).collect();
        let ac = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                    .build(patterns.iter().map(|s| s.as_str()))
                    .expect("aho-corasick build"),
            )
        };
        let mut map = HashMap::new();
        for p in &patterns {
            map.insert(token_for(p), (*p).clone());
        }
        Self { ac, map }
    }

    /// Blind all configured secrets in `text`.
    pub fn blind(&self, text: &str) -> (String, usize) {
        let Some(ac) = &self.ac else {
            return (text.to_string(), 0);
        };
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        let mut hits = 0;
        for m in ac.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            out.push_str(&token_for(&text[m.start()..m.end()]));
            last = m.end();
            hits += 1;
        }
        out.push_str(&text[last..]);
        (out, hits)
    }

    /// Restore secrets in a response body. Only call on text destined
    /// for the original client.
    pub fn unblind(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (token, secret) in &self.map {
            if out.contains(token.as_str()) {
                out = out.replace(token.as_str(), secret);
            }
        }
        out
    }

    pub fn is_active(&self) -> bool {
        self.ac.is_some()
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
    fn blinds_and_unblinds() {
        let b = Blinder::new(&["sk-live-abc123".to_string()]);
        let (blinded, hits) = b.blind("my key is sk-live-abc123 ok");
        assert_eq!(hits, 1);
        assert!(!blinded.contains("sk-live-abc123"));
        assert!(blinded.contains("\u{27E6}EG:"));
        let back = b.unblind(&format!("echo: {}", blinded));
        assert!(back.contains("sk-live-abc123"));
    }

    #[test]
    fn same_secret_same_token() {
        let b = Blinder::new(&["hunter2".to_string()]);
        let (a, _) = b.blind("hunter2");
        let (c, _) = b.blind("hunter2");
        assert_eq!(a, c);
    }

    #[test]
    fn inactive_when_no_patterns() {
        let b = Blinder::new(&[]);
        assert!(!b.is_active());
        let (out, hits) = b.blind("nothing");
        assert_eq!(out, "nothing");
        assert_eq!(hits, 0);
    }
}
