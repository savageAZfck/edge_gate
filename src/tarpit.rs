use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Per-client token bucket. Requests over the limit are not rejected —
/// they are delayed, which throttles floods without giving a clean
/// 429 signal to hammer against.
pub struct Tarpit {
    rps: f64,
    burst: f64,
    delay_ms: u64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    tarpitted: std::sync::atomic::AtomicU64,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Tarpit {
    pub fn new(rps: f64, burst: u32, delay_ms: u64) -> Self {
        Self {
            rps,
            burst: burst as f64,
            delay_ms,
            buckets: Mutex::new(HashMap::new()),
            tarpitted: 0.into(),
        }
    }

    /// Check a client; returns the delay to apply before serving.
    pub fn check(&self, ip: IpAddr) -> Duration {
        let now = Instant::now();
        let mut map = self.buckets.lock();
        let b = map.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        b.tokens = (b.tokens + now.duration_since(b.last).as_secs_f64() * self.rps).min(self.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Duration::ZERO
        } else {
            self.tarpitted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Duration::from_millis(self.delay_ms)
        }
    }

    pub fn tarpitted_count(&self) -> u64 {
        self.tarpitted.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn burst_then_tarpit() {
        let t = Tarpit::new(1.0, 2, 100);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(t.check(ip), Duration::ZERO);
        assert_eq!(t.check(ip), Duration::ZERO);
        assert_eq!(t.check(ip), Duration::from_millis(100));
        assert_eq!(t.tarpitted_count(), 1);
    }
}
