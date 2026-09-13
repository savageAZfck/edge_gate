use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Semantic dedup: feature-set Jaccard similarity over normalized
/// prompt text. Two prompts sharing >= min_similarity of their hashed
/// word features are treated as the same request and the cached
/// response is replayed.
///
/// Deterministic — no model, no embeddings. The cache is a bounded
/// LRU; a lookup scans entries comparing feature sets, which is cheap
/// at the configured sizes (~1024 entries × ~20 features).
struct Entry {
    features: Arc<Vec<u64>>,
    response: Arc<serde_json::Value>,
}

pub struct Deduper {
    min_similarity: f64,
    inner: Mutex<LruCache<u64, Entry>>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl Deduper {
    pub fn new(min_similarity: f64, cache_size: usize) -> Self {
        Self {
            min_similarity,
            inner: Mutex::new(LruCache::new(NonZeroUsize::new(cache_size.max(1)).unwrap())),
            hits: 0.into(),
            misses: 0.into(),
        }
    }

    /// Look up a cached response for this prompt text.
    pub fn get(&self, prompt_text: &str) -> Option<Arc<serde_json::Value>> {
        let features = feature_set(prompt_text);
        if features.is_empty() {
            return None;
        }
        let mut cache = self.inner.lock();
        let mut found_key = None;
        for (k, e) in cache.iter() {
            if jaccard(&features, &e.features) >= self.min_similarity {
                found_key = Some(*k);
                break;
            }
        }
        if let Some(k) = found_key {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return cache.get(&k).map(|e| e.response.clone());
        }
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        None
    }

    pub fn put(&self, prompt_text: &str, response: serde_json::Value) {
        let features = feature_set(prompt_text);
        if features.is_empty() {
            return;
        }
        let key = features
            .iter()
            .fold(0xcbf29ce484222325u64, |a, f| a.rotate_left(7) ^ f);
        self.inner.lock().put(
            key,
            Entry {
                features: Arc::new(features),
                response: Arc::new(response),
            },
        );
    }

    pub fn stats(&self) -> (u64, u64, usize) {
        (
            self.hits.load(std::sync::atomic::Ordering::Relaxed),
            self.misses.load(std::sync::atomic::Ordering::Relaxed),
            self.inner.lock().len(),
        )
    }
}

/// Extract the text content of a chat-completions-style request for
/// fingerprinting: every message's content concatenated.
pub fn prompt_text(body: &serde_json::Value) -> String {
    let mut s = String::new();
    if let Some(msgs) = body.get("messages").and_then(|m| m.as_array()) {
        for m in msgs {
            if let Some(c) = m.get("content") {
                match c {
                    serde_json::Value::String(t) => {
                        s.push_str(t);
                        s.push('\n');
                    }
                    serde_json::Value::Array(parts) => {
                        for p in parts {
                            if let Some(t) = p.get("text").and_then(|t| t.as_str()) {
                                s.push_str(t);
                                s.push('\n');
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    s
}

/// Sorted set of hashed features: lowercase word unigrams + word
/// bigrams. Unigrams carry short prompts; bigrams add order signal.
pub fn feature_set(text: &str) -> Vec<u64> {
    let words: Vec<String> = text.split_whitespace().map(|w| w.to_lowercase()).collect();
    let mut feats = Vec::with_capacity(words.len() * 2);
    for w in &words {
        feats.push(fxhash(w.as_bytes()));
    }
    for w in words.windows(2) {
        feats.push(fxhash(w.join(" ").as_bytes()));
    }
    feats.sort_unstable();
    feats.dedup();
    feats
}

/// Jaccard similarity on two sorted feature vectors.
fn jaccard(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let (mut i, mut j, mut inter) = (0, 0, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                inter += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let union = a.len() + b.len() - inter;
    inter as f64 / union as f64
}

fn fxhash(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in bytes {
        h = (h.rotate_left(5) ^ b as u64).wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn similarity_debug() {
        let a = feature_set("what is the capital of france please tell me");
        let b = feature_set("what is the capital of france please say");
        eprintln!("near-dup jaccard = {:.3}", jaccard(&a, &b));
        let c = feature_set("completely unrelated sentence about marine biology");
        let d = feature_set("rust borrow checker rules");
        eprintln!("unrelated jaccard = {:.3}", jaccard(&c, &d));
    }

    #[test]
    fn near_duplicates_hit() {
        let d = Deduper::new(0.6, 16);
        let prompt = "what is the capital of france please tell me";
        d.put(prompt, serde_json::json!({"answer": "paris"}));
        let hit = d.get("what is the capital of france please say");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap()["answer"], "paris");
    }

    #[test]
    fn different_prompts_miss() {
        let d = Deduper::new(0.6, 16);
        d.put(
            "completely unrelated sentence about marine biology",
            serde_json::json!({}),
        );
        assert!(d.get("rust borrow checker rules").is_none());
    }

    #[test]
    fn prompt_text_extracts() {
        let body = serde_json::json!({
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": "hello world"}
            ]
        });
        assert!(prompt_text(&body).contains("hello world"));
    }
}
