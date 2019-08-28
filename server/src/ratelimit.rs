use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MAX: usize = 8;
const TIMEOUT: Duration = Duration::from_secs(60 * 15);

pub struct RateLimiter {
    limits: DashMap<IpAddr, Vec<Instant>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            limits: DashMap::default(),
        }
    }

    pub fn check(&self, addr: IpAddr) -> bool {
        let mut shard = self.limits.get_raw_mut_from_key(&addr);
        let v = shard.entry(addr).or_default();
        v.push(Instant::now());
        v.retain(|t| t.elapsed() < TIMEOUT);
        v.len() <= MAX
    }
}
