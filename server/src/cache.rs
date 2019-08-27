use dashmap::{DashMap, DashMapRef};
use std::hash::Hash;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::ops::Deref;

fn expiry_work<K: Hash + Eq + Send + Sync, V: Send + Sync>(cache: &DashMap<K, (Instant, V)>) {
    loop {
        thread::sleep(Duration::from_secs(15));
        cache.retain(|_, v| v.0.elapsed().as_secs() < 60);
    }
}

pub struct ExpiryCache<K: 'static + Hash + Eq + Send + Sync, V: 'static + Send + Sync> {
    kv: Arc<DashMap<K, (Instant, V)>>,
    expiry_worker: thread::JoinHandle<()>,
}

impl<K: 'static + Hash + Eq + Send + Sync, V: 'static + Send + Sync> ExpiryCache<K, V> {
    pub fn new() -> Self {
        let map = Arc::new(DashMap::default());
        let cache = map.clone();
        let handle = thread::spawn(move || expiry_work(&cache));

        Self {
            kv: map,
            expiry_worker: handle,
        }
    }

    pub fn set(&self, k: K, v: V) {
        self.kv.insert(k, (Instant::now(), v));
    }

    pub fn get(&self, k: &K) -> Option<DashMapRef<'_, K, (Instant, V)>> {
        self.kv.get(k)
    }
}
