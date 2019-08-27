use dashmap::{DashMap, DashMapRef};
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn expiry_work<K: Hash + Eq + Send + Sync, V: Send + Sync>(cache: &DashMap<K, (Instant, V)>) {
    loop {
        thread::sleep(Duration::from_secs(15));
        cache.retain(|_, v| v.0.elapsed().as_secs() < 60);
    }
}

pub struct ExpiryCache<K: 'static + Hash + Eq + Send + Sync, V: 'static + Send + Sync> {
    kv: Arc<DashMap<K, (Instant, V)>>,
    _expiry_worker: thread::JoinHandle<()>,
}

impl<K: 'static + Hash + Eq + Send + Sync, V: 'static + Send + Sync> ExpiryCache<K, V> {
    pub fn new() -> Self {
        let map = Arc::new(DashMap::default());
        let cache = map.clone();
        let handle = thread::spawn(move || expiry_work(&cache));

        Self {
            kv: map,
            _expiry_worker: handle,
        }
    }

    pub fn set(&self, k: K, v: V) {
        self.kv.insert(k, (Instant::now(), v));
    }

    pub fn get(&self, k: &K) -> Result<DashMapRef<'_, K, (Instant, V)>, CacheError> {
        self.kv.get(k).ok_or(CacheError::InvalidKey)
    }
}

#[derive(Debug)]
pub enum CacheError {
    InvalidKey,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CacheError")
    }
}

impl std::error::Error for CacheError {}
