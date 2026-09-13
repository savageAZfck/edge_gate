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
