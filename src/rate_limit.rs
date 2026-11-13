use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Default)]
pub struct LoginRateLimiter {
    inner: Mutex<HashMap<String, Vec<Instant>>>,
}

impl LoginRateLimiter {
    pub fn check_and_record(&self, key: &str, limit: u32, window: Duration) -> bool {
        let mut map = self.inner.lock().expect("rate limiter lock");
        let now = Instant::now();
        let entries = map.entry(key.to_string()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() as u32 >= limit {
            return false;
        }
        entries.push(now);
        true
    }
}
