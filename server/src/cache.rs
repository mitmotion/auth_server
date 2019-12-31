use std::time::{Duration, Instant};
use std::sync::Mutex;
use std::hash::Hash;
use std::collections::HashMap;
use std::thread;
use std::sync::Arc;

pub struct TimedCacheEntry<V> {
    pub timestamp: Instant,
    pub data: V,
}

fn work_clean<K: Eq + Hash + Send, V>(map: Arc<Mutex<HashMap<K, TimedCacheEntry<V>>>>) {
    thread::sleep(Duration::from_secs(60));
    map.lock().unwrap().retain(|_, v| v.timestamp.elapsed() < Duration::from_secs(15));
}

pub struct TimedCache<K, V> {
    inner: Arc<Mutex<HashMap<K, TimedCacheEntry<V>>>>,
}

impl<K: 'static + Eq + Hash + Send, V: 'static + Send + Clone> TimedCache<K, V> {
    pub fn new() -> Self {
        let inner = Arc::new(Mutex::new(HashMap::new()));
        {
            let inner = inner.clone();
            thread::spawn(|| work_clean(inner));
        }
        Self { inner }
    }

    pub fn insert(&self, k: K, v: V) {
        self.inner.lock().unwrap().insert(k, TimedCacheEntry{ timestamp: Instant::now(), data: v });
    }

    pub fn run(&self, k: &K, f: impl FnOnce(Option<&mut TimedCacheEntry<V>>) -> bool) {
        let mut inner = self.inner.lock().unwrap();
        let v = inner.get_mut(k);
        if !f(v) {
            inner.remove(&k);
        }
    }
}
