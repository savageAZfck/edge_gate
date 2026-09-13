use parking_lot::Mutex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// Append-only hash-chained audit ledger. Same shape as the sovereign
/// ledger format: {ts, type, data, prev_hash, hash} where
/// hash = sha256(canonical(ts|type|data|prev_hash)).
/// A verifier walks the file and recomputes — truncation, rewrite, or
/// reorder all break the chain.
pub struct Audit {
    writer: Mutex<BufWriter<std::fs::File>>,
    prev: Mutex<String>,
    path: PathBuf,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl Audit {
    /// Open (or create) the ledger. Recovers the tail hash so appends
    /// continue the existing chain.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let prev = tail_hash(path).unwrap_or_else(|| GENESIS.to_string());
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            prev: Mutex::new(prev),
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append an entry. `data` should be already redacted — the audit
    /// layer does not decide what is safe to persist.
    pub fn record(&self, kind: &str, data: Value) {
        let ts = chrono_now();
        let prev = self.prev.lock().clone();
        let hash = entry_hash(&ts, kind, &data, &prev);
        let line = json!({
            "ts": ts,
            "type": kind,
            "data": data,
            "prev_hash": prev,
            "hash": hash,
        });
        let mut w = self.writer.lock();
        let _ = serde_json::to_writer(&mut *w, &line);
        let _ = w.write_all(b"\n");
        let _ = w.flush();
        *self.prev.lock() = hash;
    }
}

fn chrono_now() -> String {
    // unix seconds float — no chrono dep for one timestamp
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    format!("{secs:.6}")
}

fn entry_hash(ts: &str, kind: &str, data: &Value, prev: &str) -> String {
    let mut h = Sha256::new();
    h.update(ts.as_bytes());
    h.update(b"|");
    h.update(kind.as_bytes());
    h.update(b"|");
    h.update(serde_json::to_string(data).unwrap_or_default().as_bytes());
    h.update(b"|");
    h.update(prev.as_bytes());
    hex::encode(h.finalize())
}

fn tail_hash(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let last = text.lines().rfind(|l| !l.trim().is_empty())?;
    let v: Value = serde_json::from_str(last).ok()?;
    v.get("hash")?.as_str().map(|s| s.to_string())
}

/// Generate an ed25519 keypair for checkpoint signing.
/// Returns (secret_hex, public_hex). Store the secret somewhere safe —
/// anyone holding it can forge checkpoint signatures.
pub fn keygen() -> (String, String) {
    use ed25519_dalek::Signer;
    let mut rng = rand::rngs::OsRng;
    let kp = ed25519_dalek::SigningKey::generate(&mut rng);
    let _ = kp.sign(b""); // force trait import usage clarity
    (
        hex::encode(kp.to_bytes()),
        hex::encode(kp.verifying_key().to_bytes()),
    )
}

/// Write a tamper-evident checkpoint: the entry count and tip hash of
/// the ledger at this moment. If `secret_hex` is given, the checkpoint
/// is ed25519-signed and carries the public key — store the checkpoint
/// off-box and an attacker who rewrites history can't produce a
/// checkpoint that still verifies.
pub fn checkpoint(ledger: &Path, out: &Path, secret_hex: Option<&str>) -> std::io::Result<Value> {
    let (n, bad) = verify(ledger)?;
    if let Some(line) = bad {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("refusing to checkpoint a broken chain (bad line {line})"),
        ));
    }
    let tip = tail_hash(ledger).unwrap_or_else(|| GENESIS.to_string());
    let file_bytes = std::fs::read(ledger).unwrap_or_default();
    let file_sha = hex::encode(Sha256::digest(&file_bytes));
    let mut cp = json!({
        "ledger": ledger.display().to_string(),
        "entries": n,
        "tip_hash": tip,
        "file_sha256": file_sha,
        "checkpointed_at": chrono_now(),
    });
    if let Some(secret) = secret_hex {
        let bytes = hex::decode(secret)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "secret must be 32 bytes")
        })?;
        let key = ed25519_dalek::SigningKey::from_bytes(&arr);
        use ed25519_dalek::Signer;
        let payload = canonical_payload(&cp);
        let sig = key.sign(payload.as_bytes());
        cp["public_key"] = json!(hex::encode(key.verifying_key().to_bytes()));
        cp["signature"] = json!(hex::encode(sig.to_bytes()));
    }
    std::fs::write(out, serde_json::to_string_pretty(&cp)?)?;
    Ok(cp)
}

/// Canonical signed payload: the checkpoint fields minus signature
/// material, serialized deterministically.
fn canonical_payload(cp: &Value) -> String {
    format!(
        "{}|{}|{}|{}",
        cp["entries"], cp["tip_hash"], cp["file_sha256"], cp["checkpointed_at"]
    )
}

/// Verify a checkpoint file's signature (if present) and confirm the
/// checkpointed tip is still in the chain.
pub fn checkpoint_holds(ledger: &Path, checkpoint: &Path) -> std::io::Result<bool> {
    let cp: Value = serde_json::from_str(&std::fs::read_to_string(checkpoint)?)?;
    // signature check first — a forged checkpoint should fail loudly
    if let (Some(sig_hex), Some(pub_hex)) = (cp["signature"].as_str(), cp["public_key"].as_str()) {
        use ed25519_dalek::Verifier;
        let pk_bytes = hex::decode(pub_hex).unwrap_or_default();
        let sig_bytes = hex::decode(sig_hex).unwrap_or_default();
        let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap_or([0; 32]);
        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap_or([0; 64]);
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        pk.verify(canonical_payload(&cp).as_bytes(), &sig)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "checkpoint signature invalid",
                )
            })?;
    }
    let tip = cp["tip_hash"].as_str().unwrap_or("");
    let text = std::fs::read_to_string(ledger)?;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            if v["hash"].as_str() == Some(tip) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Verify a ledger file. Returns (entries_checked, first_bad_line).
pub fn verify(path: &Path) -> std::io::Result<(u64, Option<u64>)> {
    let text = std::fs::read_to_string(path)?;
    let mut prev = GENESIS.to_string();
    let mut n = 0u64;
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        n += 1;
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Ok((n - 1, Some(i as u64 + 1))),
        };
        let ts = v["ts"].as_str().unwrap_or("");
        let kind = v["type"].as_str().unwrap_or("");
        let data = &v["data"];
        let stored_prev = v["prev_hash"].as_str().unwrap_or("");
        let stored_hash = v["hash"].as_str().unwrap_or("");
        if stored_prev != prev || entry_hash(ts, kind, data, stored_prev) != stored_hash {
            return Ok((n - 1, Some(i as u64 + 1)));
        }
        prev = stored_hash.to_string();
    }
    Ok((n, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_verifies_and_detects_tamper() {
        let dir = std::env::temp_dir().join(format!("eg_audit_{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let a = Audit::open(&dir).unwrap();
        a.record("test", json!({"n": 1}));
        a.record("test", json!({"n": 2}));
        drop(a);
        let (ok, bad) = verify(&dir).unwrap();
        assert_eq!(ok, 2);
        assert!(bad.is_none());
        // tamper: corrupt line 1
        let text = std::fs::read_to_string(&dir).unwrap();
        let tampered = text.replacen("\"n\":1", "\"n\":9", 1);
        std::fs::write(&dir, tampered).unwrap();
        let (_, bad) = verify(&dir).unwrap();
        assert_eq!(bad, Some(1));
        let _ = std::fs::remove_file(&dir);
    }
}
