// ============================================================================
// A small, bounded, in-process rate limiter.
// ============================================================================
// Redis is the primary store for login and registration throttles (shared
// between instances, survives restarts). When Redis is unreachable the old code
// failed OPEN -- unlimited password guesses. This is the fallback: per-process,
// forgotten on restart, and capped in memory, but a lockout that exists.
// ============================================================================
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Entry {
    count: u64,
    window_start: Instant,
    window: Duration,
    locked_until: Option<Instant>,
}

#[derive(Debug)]
pub struct LocalLimiter {
    max_keys: usize,
    inner: Mutex<HashMap<String, Entry>>,
}

impl LocalLimiter {
    pub fn new(max_keys: usize) -> Self {
        LocalLimiter { max_keys: max_keys.max(1), inner: Mutex::new(HashMap::new()) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        // A poisoned lock means another request panicked while holding it; the map is
        // still a valid map. Carrying on is safer than panicking every later request.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop expired entries; if still full, drop the one whose window started earliest.
    fn make_room(map: &mut HashMap<String, Entry>, max_keys: usize, now: Instant) {
        if map.len() < max_keys {
            return;
        }
        map.retain(|_, e| {
            let window_live = now.duration_since(e.window_start) < e.window;
            let locked = e.locked_until.is_some_and(|u| u > now);
            window_live || locked
        });
        // Still full: evict the oldest window among the keys that are NOT locked, so a flood of
        // one-failure keys cannot push a lockout out; only when every key is locked does the oldest
        // lockout go.
        while map.len() >= max_keys {
            let victim = map
                .iter()
                .min_by_key(|(_, e)| (e.locked_until.is_some_and(|u| u > now), e.window_start))
                .map(|(k, _)| k.clone());
            match victim {
                Some(k) => {
                    map.remove(&k);
                }
                None => break,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Seconds left on a lockout for `key`, if there is one.
    pub fn locked_ttl(&self, key: &str) -> Option<i64> {
        self.locked_ttl_at(key, Instant::now())
    }

    pub fn locked_ttl_at(&self, key: &str, now: Instant) -> Option<i64> {
        let map = self.lock();
        let until = map.get(key)?.locked_until?;
        if until > now {
            Some(until.duration_since(now).as_secs().max(1) as i64)
        } else {
            None
        }
    }

    /// Count one failure; once `max` failures fall inside `window`, lock the key for `window`.
    /// Returns true if the key is locked after this failure.
    pub fn fail(&self, key: &str, max: u64, window: Duration) -> bool {
        self.fail_at(key, max, window, Instant::now())
    }

    pub fn fail_at(&self, key: &str, max: u64, window: Duration, now: Instant) -> bool {
        let mut map = self.lock();
        if !map.contains_key(key) {
            Self::make_room(&mut map, self.max_keys, now);
        }
        let e = map.entry(key.to_string()).or_insert(Entry { count: 0, window_start: now, window, locked_until: None });
        if now.duration_since(e.window_start) >= e.window {
            e.count = 0;
            e.window_start = now;
        }
        e.window = window;
        e.count += 1;
        if e.count >= max {
            e.locked_until = Some(now + window);
        }
        e.locked_until.is_some_and(|u| u > now)
    }

    /// Count one use of a budget (registrations): true while the use is within `max` per `window`.
    pub fn allow(&self, key: &str, max: u64, window: Duration) -> bool {
        self.allow_at(key, max, window, Instant::now())
    }

    pub fn allow_at(&self, key: &str, max: u64, window: Duration, now: Instant) -> bool {
        let mut map = self.lock();
        if !map.contains_key(key) {
            Self::make_room(&mut map, self.max_keys, now);
        }
        let e = map.entry(key.to_string()).or_insert(Entry { count: 0, window_start: now, window, locked_until: None });
        if now.duration_since(e.window_start) >= e.window {
            e.count = 0;
            e.window_start = now;
        }
        e.window = window;
        e.count += 1;
        e.count <= max
    }

    /// Forget the failures counted against `key` (a successful login). A lockout in force is not lifted,
    /// the same as the Redis path, which deletes only the counter.
    pub fn clear(&self, key: &str) {
        let mut map = self.lock();
        let locked = map.get(key).and_then(|e| e.locked_until).is_some_and(|u| u > Instant::now());
        if locked {
            if let Some(e) = map.get_mut(key) {
                e.count = 0;
            }
        } else {
            map.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(900);

    #[test]
    fn locks_after_max_failures_and_expires() {
        let l = LocalLimiter::new(100);
        let t0 = Instant::now();
        for i in 0..4 {
            assert!(!l.fail_at("ip:1", 5, W, t0 + Duration::from_secs(i)), "failure {i}");
            assert_eq!(l.locked_ttl_at("ip:1", t0), None);
        }
        assert!(l.fail_at("ip:1", 5, W, t0 + Duration::from_secs(4)));
        assert!(l.locked_ttl_at("ip:1", t0 + Duration::from_secs(5)).unwrap() > 800);
        assert_eq!(l.locked_ttl_at("ip:1", t0 + W + Duration::from_secs(10)), None, "lock expires");
        // a different key is unaffected
        assert_eq!(l.locked_ttl_at("ip:2", t0), None);
    }

    #[test]
    fn window_rolls_over() {
        let l = LocalLimiter::new(100);
        let t0 = Instant::now();
        for i in 0..4 {
            l.fail_at("k", 5, W, t0 + Duration::from_secs(i));
        }
        // the 5th failure comes after the window: the count restarts, no lock
        assert!(!l.fail_at("k", 5, W, t0 + W + Duration::from_secs(1)));
    }

    #[test]
    fn allow_counts_per_window() {
        let l = LocalLimiter::new(100);
        let t0 = Instant::now();
        let hour = Duration::from_secs(3600);
        for i in 0..10 {
            assert!(l.allow_at("reg:1", 10, hour, t0 + Duration::from_secs(i)), "use {i}");
        }
        assert!(!l.allow_at("reg:1", 10, hour, t0 + Duration::from_secs(11)));
        assert!(!l.allow_at("reg:1", 10, hour, t0 + Duration::from_secs(12)));
        assert!(l.allow_at("reg:1", 10, hour, t0 + hour + Duration::from_secs(1)), "new window");
        assert!(l.allow_at("reg:2", 10, hour, t0), "another key");
    }

    #[test]
    fn memory_is_bounded_and_expired_entries_go_first() {
        let l = LocalLimiter::new(50);
        let t0 = Instant::now();
        for i in 0..10_000u64 {
            l.fail_at(&format!("ip:{i}"), 5, W, t0 + Duration::from_millis(i));
            assert!(l.len() <= 50, "grew to {} at {i}", l.len());
        }
        // expired entries are dropped before live ones
        let l = LocalLimiter::new(3);
        l.fail_at("old1", 5, W, t0);
        l.fail_at("old2", 5, W, t0);
        l.fail_at("live", 5, W, t0 + W + Duration::from_secs(5));
        l.fail_at("new", 5, W, t0 + W + Duration::from_secs(6));
        assert!(l.len() <= 3);
        assert!(l.lock().contains_key("live") && l.lock().contains_key("new"));
    }

    #[test]
    fn a_flood_of_new_keys_does_not_push_out_a_lockout() {
        let l = LocalLimiter::new(10);
        let t0 = Instant::now();
        for i in 0..5 {
            l.fail_at("victim", 5, W, t0 + Duration::from_secs(i));
        }
        assert!(l.locked_ttl_at("victim", t0 + Duration::from_secs(6)).is_some());
        for i in 0..5_000u64 {
            l.fail_at(&format!("flood{i}"), 5, W, t0 + Duration::from_secs(10) + Duration::from_millis(i));
        }
        assert!(l.len() <= 10);
        assert!(l.locked_ttl_at("victim", t0 + Duration::from_secs(30)).is_some(), "unlocked keys are evicted first");
    }

    #[test]
    fn only_a_flood_of_locked_keys_evicts_a_lockout() {
        // the honest limit of a bounded table, stated as a test: if every slot holds a lockout,
        // the oldest lockout is the one to go. (Only reached while Redis is down.)
        let l = LocalLimiter::new(4);
        let t0 = Instant::now();
        for k in ["a", "b", "c", "d"] {
            for i in 0..5 {
                l.fail_at(k, 5, W, t0 + Duration::from_secs(i));
            }
        }
        for i in 0..5 {
            l.fail_at("e", 5, W, t0 + Duration::from_secs(10 + i));
        }
        assert!(l.locked_ttl_at("e", t0 + Duration::from_secs(20)).is_some());
        assert!(l.len() <= 4);
    }

    #[test]
    fn clear_forgets_the_count_but_not_a_lockout() {
        let l = LocalLimiter::new(10);
        let t0 = Instant::now();
        for i in 0..3 {
            l.fail_at("k", 5, W, t0 + Duration::from_secs(i));
        }
        l.clear("k");
        assert!(l.is_empty(), "an unlocked key is simply forgotten");
        // after the clear, three more failures do not reach five
        for i in 0..3 {
            assert!(!l.fail_at("k", 5, W, t0 + Duration::from_secs(10 + i)));
        }
        // a key that IS locked stays locked
        let now = Instant::now();
        for _ in 0..5 {
            l.fail_at("locked", 5, W, now);
        }
        l.clear("locked");
        assert!(l.locked_ttl("locked").is_some());
    }
}
