use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cost + token accounting. Reads `usage` from upstream responses when
/// present; falls back to a chars/4 estimate otherwise.
pub struct Meter {
    /// model -> (input_per_mtok, output_per_mtok) USD
    costs: HashMap<String, (f64, f64)>,
    totals: Mutex<HashMap<String, ModelTotals>>,
    requests: AtomicU64,
    dedup_saved_usd: Mutex<f64>,
}

#[derive(Default, Clone)]
struct ModelTotals {
    requests: u64,
    input_tokens: u64,
    output_tokens: u64,
    usd: f64,
}

impl Meter {
    pub fn new(costs: &HashMap<String, crate::config::ModelCost>) -> Self {
        let table = costs
            .iter()
            .map(|(k, v)| (k.clone(), (v.input_per_mtok, v.output_per_mtok)))
            .collect();
        Self {
            costs: table,
            totals: Mutex::new(HashMap::new()),
            requests: 0.into(),
            dedup_saved_usd: Mutex::new(0.0),
        }
    }

    /// Record a completed upstream call. `usage` is the upstream JSON
    /// `usage` object if present.
    pub fn record(&self, model: &str, usage: Option<&serde_json::Value>, est_chars: usize) -> f64 {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let (in_tok, out_tok) = match usage {
            Some(u) => (
                u.get("prompt_tokens")
                    .or_else(|| u.get("input_tokens"))
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0),
                u.get("completion_tokens")
                    .or_else(|| u.get("output_tokens"))
                    .and_then(|t| t.as_u64())
                    .unwrap_or(0),
            ),
            None => ((est_chars / 4) as u64, 0),
        };
        let (ci, co) = self.costs.get(model).copied().unwrap_or((0.0, 0.0));
        let usd = in_tok as f64 * ci / 1e6 + out_tok as f64 * co / 1e6;
        let mut t = self.totals.lock();
        let e = t.entry(model.to_string()).or_default();
        e.requests += 1;
        e.input_tokens += in_tok;
        e.output_tokens += out_tok;
        e.usd += usd;
        usd
    }

    /// Estimated spend avoided by serving a dedup hit.
    pub fn record_dedup_save(&self, model: &str) {
        let (ci, co) = self.costs.get(model).copied().unwrap_or((0.0, 0.0));
        // rough estimate: avg request ~1k in / 300 out
        let saved = 1000.0 * ci / 1e6 + 300.0 * co / 1e6;
        *self.dedup_saved_usd.lock() += saved;
    }

    /// Prometheus exposition text.
    pub fn render(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "edge_gate_requests_total {}\n",
            self.requests.load(Ordering::Relaxed)
        ));
        for (model, t) in self.totals.lock().iter() {
            s.push_str(&format!(
                "edge_gate_model_requests{{model=\"{}\"}} {}\n",
                model, t.requests
            ));
            s.push_str(&format!(
                "edge_gate_model_input_tokens{{model=\"{}\"}} {}\n",
                model, t.input_tokens
            ));
            s.push_str(&format!(
                "edge_gate_model_output_tokens{{model=\"{}\"}} {}\n",
                model, t.output_tokens
            ));
            s.push_str(&format!(
                "edge_gate_model_usd{{model=\"{}\"}} {:.6}\n",
                model, t.usd
            ));
        }
        s.push_str(&format!(
            "edge_gate_dedup_saved_usd {:.6}\n",
            *self.dedup_saved_usd.lock()
        ));
        s.push_str(&format!("edge_gate_total_usd {:.6}\n", self.total_usd()));
        s
    }

    pub fn total_usd(&self) -> f64 {
        self.totals.lock().values().map(|t| t.usd).sum()
    }
}
