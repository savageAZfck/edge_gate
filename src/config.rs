use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub upstreams: HashMap<String, Upstream>,
    #[serde(default)]
    pub dedup: DedupConfig,
    #[serde(default)]
    pub blinding: BlindConfig,
    #[serde(default)]
    pub filter: FilterConfig,
    #[serde(default)]
    pub tarpit: TarpitConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub costs: HashMap<String, ModelCost>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Upstream {
    /// Base URL, e.g. "https://api.openai.com" or "http://127.0.0.1:8080"
    pub url: String,
    /// Optional bearer token injected as Authorization header.
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DedupConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Jaccard similarity >= this counts as a duplicate (0.0-1.0).
    #[serde(default = "default_similarity")]
    pub min_similarity: f64,
    /// Max cached responses.
    #[serde(default = "default_cache")]
    pub cache_size: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BlindConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Literal strings and regexes are not mixed: entries are literal
    /// substrings to blind before the request leaves the machine.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// File with one pattern per line (merged with `patterns`).
    pub patterns_file: Option<PathBuf>,
    /// Replace blinded values back in the upstream response.
    #[serde(default = "default_true")]
    pub unblind_response: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct FilterConfig {
    #[serde(default)]
    pub enabled: bool,
    /// If the upstream response contains any of these substrings, the
    /// response is replaced with a refusal notice.
    #[serde(default)]
    pub blocklist: Vec<String>,
    pub blocklist_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TarpitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Requests per second allowed per client IP before tarpitting.
    #[serde(default = "default_rps")]
    pub requests_per_second: f64,
    /// Burst allowance.
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Extra latency (ms) added per over-limit request.
    #[serde(default = "default_delay")]
    pub delay_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,
    #[serde(default)]
    pub record_bodies: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ModelCost {
    /// USD per 1M input tokens.
    pub input_per_mtok: f64,
    /// USD per 1M output tokens.
    pub output_per_mtok: f64,
}

fn default_listen() -> String {
    "127.0.0.1:8400".into()
}
fn default_true() -> bool {
    true
}
fn default_similarity() -> f64 {
    0.6
}
fn default_cache() -> usize {
    1024
}
fn default_rps() -> f64 {
    5.0
}
fn default_burst() -> u32 {
    10
}
fn default_delay() -> u64 {
    500
}
fn default_audit_path() -> PathBuf {
    PathBuf::from("edge_gate_ledger.jsonl")
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_similarity: default_similarity(),
            cache_size: default_cache(),
        }
    }
}
impl Default for BlindConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            patterns: Vec::new(),
            patterns_file: None,
            unblind_response: true,
        }
    }
}
impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: default_rps(),
            burst: default_burst(),
            delay_ms: default_delay(),
        }
    }
}
impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_audit_path(),
            record_bodies: false,
        }
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path)?;
        let mut cfg: Config = toml::from_str(&text)?;
        if let Some(f) = &cfg.blinding.patterns_file {
            let extra = std::fs::read_to_string(f)?;
            cfg.blinding.patterns.extend(
                extra
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty()),
            );
        }
        if let Some(f) = &cfg.filter.blocklist_file {
            let extra = std::fs::read_to_string(f)?;
            cfg.filter.blocklist.extend(
                extra
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty()),
            );
        }
        Ok(cfg)
    }
}
