use lru::LruCache;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;

/// FxHash-style hasher for u64 keys — SipHash is the bottleneck when
/// tallying thousands of index hits per lookup.
#[derive(Default)]
struct FxHasher(u64);
impl Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(5) ^ b as u64).wrapping_mul(0x100000001b3);
        }
    }
    fn write_u64(&mut self, n: u64) {
        self.0 = (self.0.rotate_left(5) ^ n).wrapping_mul(0x100000001b3);
    }
    fn finish(&self) -> u64 {
        self.0
    }
}
type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

/// Semantic dedup: feature-set Jaccard similarity over normalized
/// prompt text. Two prompts sharing >= min_similarity of their hashed
/// word features are treated as the same request and the cached
/// response is replayed.
///
/// Deterministic — no model, no embeddings. Lookups use an inverted
/// index (feature → entry keys) so only entries sharing at least one
/// feature are scored; unrelated cache entries are never touched.
/// Cost is O(matches) not O(cache size).
struct Entry {
    features: Arc<Vec<u64>>,
    response: Arc<serde_json::Value>,
}

struct Index {
    cache: LruCache<u64, Entry>,
    /// feature hash -> entry keys containing that feature.
    inverted: FxMap<u64, Vec<u64>>,
}

impl Index {
    fn remove_key(&mut self, key: u64) {
        if let Some(e) = self.cache.pop(&key) {
            for f in e.features.iter() {
                if let Some(keys) = self.inverted.get_mut(f) {
                    keys.retain(|k| *k != key);
                    if keys.is_empty() {
                        self.inverted.remove(f);
                    }
                }
            }
        }
    }
}

pub struct Deduper {
    min_similarity: f64,
    inner: Mutex<Index>,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl Deduper {
    pub fn new(min_similarity: f64, cache_size: usize) -> Self {
        Self {
            min_similarity,
            inner: Mutex::new(Index {
                cache: LruCache::new(NonZeroUsize::new(cache_size.max(1)).unwrap()),
                inverted: FxMap::default(),
            }),
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
        let mut idx = self.inner.lock();

        // candidates: entries sharing >= 1 feature, tallied
        let mut counts: FxMap<u64, usize> = FxMap::default();
        for f in &features {
            if let Some(keys) = idx.inverted.get(f) {
                for k in keys {
                    *counts.entry(*k).or_insert(0) += 1;
                }
            }
        }

        // exact Jaccard only on candidates that can possibly meet the
        // threshold: shared >= min_similarity * min(len_a, len_b)
        let mut best: Option<(u64, f64)> = None;
        for (k, shared) in counts {
            let Some(e) = idx.cache.peek(&k) else {
                continue;
            };
            let min_len = features.len().min(e.features.len());
            if (shared as f64) < self.min_similarity * min_len as f64 {
                continue;
            }
            let sim = jaccard(&features, &e.features);
            if sim >= self.min_similarity && best.map(|(_, s)| sim > s).unwrap_or(true) {
                best = Some((k, sim));
            }
        }

        if let Some((k, _)) = best {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return idx.cache.get(&k).map(|e| e.response.clone());
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
        let mut idx = self.inner.lock();
        // evict cleanly: remove the victim's index postings too
        if idx.cache.len() == idx.cache.cap().get() {
            if let Some((victim, _)) = idx.cache.peek_lru() {
                let victim = *victim;
                idx.remove_key(victim);
            }
        }
        for f in &features {
            idx.inverted.entry(*f).or_default().push(key);
        }
        idx.cache.put(
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
            self.inner.lock().cache.len(),
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
    fn eviction_clears_index() {
        let d = Deduper::new(0.9, 2);
        d.put("alpha beta gamma", serde_json::json!({"n": 1}));
        d.put("delta epsilon zeta", serde_json::json!({"n": 2}));
        d.put("eta theta iota", serde_json::json!({"n": 3})); // evicts first
        assert!(d.get("alpha beta gamma").is_none());
        assert!(d.get("eta theta iota").is_some());
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
