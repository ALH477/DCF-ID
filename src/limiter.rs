// ============================================================================
// A small, bounded, in-process rate limiter.
// ============================================================================
// Redis is the primary store for login and registration throttles (shared
// between instances, survives restarts). When Redis is unreachable the old code
// failed OPEN -- unlimited password guesses. This is the fallback: per-process,
// forgotten on restart, and capped in memory, but a limit that exists.
//
// Both kinds of counter are ATTEMPT counters taken before the work is done:
//
//   take    one attempt slot, admitted while the count is within `max`; an attempt over
//           `max` is turned away and does not count (so a flood of rejected requests
//           cannot inflate the counter and keep a legitimate user locked out afterwards);
//           the window restarts at the `max`-th attempt, so the lockout that follows a
//           run of failures lasts a full window from the last permitted guess
//   refund  give a slot back (a success, or an attempt that was never evaluated)
//   allow   a fixed-window budget with no refund (registrations)
// ============================================================================
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Entry {
    count: u64,
    max: u64,
    window_start: Instant,
    window: Duration,
}

impl Entry {
    fn live(&self, now: Instant) -> bool {
        now.duration_since(self.window_start) < self.window
    }
    /// No slot left in a window that has not ended.
    fn full(&self, now: Instant) -> bool {
        self.live(now) && self.count >= self.max
    }
    fn remaining_secs(&self, now: Instant) -> i64 {
        let left = self.window.saturating_sub(now.duration_since(self.window_start));
        (left.as_secs() as i64).max(1)
    }
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

    /// Drop expired entries; if still full, drop the oldest window among the keys that are NOT
    /// full, so a flood of one-attempt keys cannot push a lockout out; only when every key is
    /// full does the oldest lockout go.
    fn make_room(map: &mut HashMap<String, Entry>, max_keys: usize, now: Instant) {
        if map.len() < max_keys {
            return;
        }
        map.retain(|_, e| e.live(now));
        while map.len() >= max_keys {
            let victim = map.iter().min_by_key(|(_, e)| (e.full(now), e.window_start)).map(|(k, _)| k.clone());
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

    fn entry<'a>(
        map: &'a mut HashMap<String, Entry>,
        max_keys: usize,
        key: &str,
        max: u64,
        window: Duration,
        now: Instant,
    ) -> &'a mut Entry {
        if !map.contains_key(key) {
            Self::make_room(map, max_keys, now);
        }
        let e = map.entry(key.to_string()).or_insert(Entry { count: 0, max, window_start: now, window });
        if !e.live(now) {
            e.count = 0;
            e.window_start = now;
        }
        e.max = max;
        e.window = window;
        e
    }

    /// Take one attempt slot for `key`: `(admitted, seconds until the window ends)`.
    pub fn take(&self, key: &str, max: u64, window: Duration) -> (bool, i64) {
        self.take_at(key, max, window, Instant::now())
    }

    pub fn take_at(&self, key: &str, max: u64, window: Duration, now: Instant) -> (bool, i64) {
        let mut map = self.lock();
        let e = Self::entry(&mut map, self.max_keys, key, max, window, now);
        e.count += 1;
        if e.count == max {
            e.window_start = now; // the lockout runs a full window from the last permitted attempt
        }
        let admitted = e.count <= max;
        if !admitted {
            e.count -= 1; // a turned-away attempt is not counted
        }
        (admitted, e.remaining_secs(now))
    }

    /// Give a slot back. A key with nothing left is forgotten.
    pub fn refund(&self, key: &str) {
        let mut map = self.lock();
        if let Some(e) = map.get_mut(key) {
            e.count = e.count.saturating_sub(1);
            if e.count == 0 {
                map.remove(key);
            }
        }
    }

    /// Forget `key` altogether.
    pub fn clear(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Count one use of a fixed-window budget (registrations): true while the use is within `max` per
    /// `window`. Uses over the budget are counted and never refunded.
    pub fn allow(&self, key: &str, max: u64, window: Duration) -> bool {
        self.allow_at(key, max, window, Instant::now())
    }

    pub fn allow_at(&self, key: &str, max: u64, window: Duration, now: Instant) -> bool {
        let mut map = self.lock();
        let e = Self::entry(&mut map, self.max_keys, key, max, window, now);
        e.count += 1;
        e.count <= max
    }

    /// Slots currently held under `key` (0 if none). For tests.
    pub fn held(&self, key: &str) -> u64 {
        self.lock().get(key).map_or(0, |e| e.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(900);

    #[test]
    fn admits_max_then_turns_away_without_counting() {
        let l = LocalLimiter::new(100);
        let t0 = Instant::now();
        for i in 0..5 {
            let (ok, _) = l.take_at("ip:1", 5, W, t0 + Duration::from_secs(i));
            assert!(ok, "attempt {i}");
        }
        for i in 5..50 {
            let (ok, ttl) = l.take_at("ip:1", 5, W, t0 + Duration::from_secs(i));
            assert!(!ok, "attempt {i} is over the limit");
            assert!(ttl > 800);
        }
        assert_eq!(l.held("ip:1"), 5, "forty-five turned-away attempts counted for nothing");
        assert!(l.take_at("ip:2", 5, W, t0).0, "another key is unaffected");
    }

    #[test]
    fn the_lockout_runs_a_full_window_from_the_last_permitted_attempt() {
        let l = LocalLimiter::new(100);
        let t0 = Instant::now();
        // four early attempts, then the fifth a long time later
        for i in 0..4 {
            assert!(l.take_at("k", 5, W, t0 + Duration::from_secs(i)).0);
        }
        let t5 = t0 + Duration::from_secs(800);
        assert!(l.take_at("k", 5, W, t5).0);
        // 799 s after the fifth, still shut; a full window after it, open again
        assert!(!l.take_at("k", 5, W, t5 + Duration::from_secs(799)).0);
        let (ok, ttl) = l.take_at("k", 5, W, t5 + Duration::from_secs(100));
        assert!(!ok && (799..=800).contains(&ttl), "ttl {ttl}");
        assert!(l.take_at("k", 5, W, t5 + W + Duration::from_secs(1)).0, "window over");
    }

    #[test]
    fn refund_gives_a_slot_back_and_forgets_an_empty_key() {
        let l = LocalLimiter::new(100);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(l.take_at("k", 5, W, t0).0);
        }
        assert!(!l.take_at("k", 5, W, t0).0);
        l.refund("k");
        assert_eq!(l.held("k"), 4);
        assert!(l.take_at("k", 5, W, t0).0, "the refunded slot is usable");
        for _ in 0..5 {
            l.refund("k");
        }
        assert!(l.is_empty(), "nothing left, nothing remembered");
        l.refund("never-seen"); // harmless
    }

    #[test]
    fn concurrent_takes_admit_exactly_max() {
        let l = std::sync::Arc::new(LocalLimiter::new(100));
        let admitted = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let hs: Vec<_> = (0..64)
            .map(|_| {
                let (l, a) = (l.clone(), admitted.clone());
                std::thread::spawn(move || {
                    if l.take("burst", 5, W).0 {
                        a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 5);
        assert_eq!(l.held("burst"), 5);
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
    fn window_rolls_over() {
        let l = LocalLimiter::new(100);
        let t0 = Instant::now();
        for i in 0..4 {
            assert!(l.take_at("k", 5, W, t0 + Duration::from_secs(i)).0);
        }
        // the fifth and sixth come after the window: the count restarted
        assert!(l.take_at("k", 5, W, t0 + W + Duration::from_secs(1)).0);
        assert_eq!(l.held("k"), 1);
    }

    #[test]
    fn memory_is_bounded_and_expired_entries_go_first() {
        let l = LocalLimiter::new(50);
        let t0 = Instant::now();
        for i in 0..10_000u64 {
            l.take_at(&format!("ip:{i}"), 5, W, t0 + Duration::from_millis(i));
            assert!(l.len() <= 50, "grew to {} at {i}", l.len());
        }
        let l = LocalLimiter::new(3);
        l.take_at("old1", 5, W, t0);
        l.take_at("old2", 5, W, t0);
        l.take_at("live", 5, W, t0 + W + Duration::from_secs(5));
        l.take_at("new", 5, W, t0 + W + Duration::from_secs(6));
        assert!(l.len() <= 3);
        assert!(l.held("live") == 1 && l.held("new") == 1);
    }

    #[test]
    fn a_flood_of_new_keys_does_not_push_out_a_lockout() {
        let l = LocalLimiter::new(10);
        let t0 = Instant::now();
        for _ in 0..5 {
            l.take_at("victim", 5, W, t0);
        }
        assert!(!l.take_at("victim", 5, W, t0 + Duration::from_secs(6)).0);
        for i in 0..5_000u64 {
            l.take_at(&format!("flood{i}"), 5, W, t0 + Duration::from_secs(10) + Duration::from_millis(i));
        }
        assert!(l.len() <= 10);
        assert!(!l.take_at("victim", 5, W, t0 + Duration::from_secs(30)).0, "unfull keys are evicted first");
    }

    #[test]
    fn only_a_flood_of_full_keys_evicts_a_lockout() {
        // the honest limit of a bounded table, stated as a test: if every slot holds a lockout,
        // the oldest lockout is the one to go. (Only reached while Redis is down.)
        let l = LocalLimiter::new(4);
        let t0 = Instant::now();
        for k in ["a", "b", "c", "d"] {
            for i in 0..5 {
                l.take_at(k, 5, W, t0 + Duration::from_secs(i));
            }
        }
        for i in 0..5 {
            l.take_at("e", 5, W, t0 + Duration::from_secs(10 + i));
        }
        assert!(!l.take_at("e", 5, W, t0 + Duration::from_secs(20)).0);
        assert!(l.len() <= 4);
    }

    #[test]
    fn clear_forgets() {
        let l = LocalLimiter::new(10);
        for _ in 0..5 {
            l.take("k", 5, W);
        }
        l.clear("k");
        assert!(l.is_empty());
        assert!(l.take("k", 5, W).0);
    }
}
