use aho_corasick::AhoCorasick;

/// Output firewall: scans upstream response text for blocklist hits.
/// Streaming-aware: checks can run incrementally over chunks.
pub struct OutputFilter {
    ac: Option<AhoCorasick>,
}

pub const REFUSAL: &str =
    "[edge_gate output firewall: response contained a blocked pattern and was withheld]";

impl OutputFilter {
    pub fn new(blocklist: &[String]) -> Self {
        let pats: Vec<&String> = blocklist.iter().filter(|p| !p.is_empty()).collect();
        let ac = if pats.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(aho_corasick::MatchKind::LeftmostLongest)
                    .build(pats.iter().map(|s| s.as_str()))
                    .expect("aho-corasick build"),
            )
        };
        Self { ac }
    }

    /// Returns the offending pattern offset if blocked.
    pub fn check(&self, text: &str) -> bool {
        match &self.ac {
            Some(ac) => ac.is_match(text),
            None => false,
        }
    }

    pub fn is_active(&self) -> bool {
        self.ac.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_listed_pattern() {
        let f = OutputFilter::new(&["rm -rf /".to_string()]);
        assert!(f.check("run rm -rf / now"));
        assert!(!f.check("run ls"));
    }
}
