//! Shared `inspect` results. The collector (every few seconds) and push (every
//! minute) both need each container's health and restart count; this cache lets
//! them share one inspect per container instead of each making its own.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// How long a cached result stays valid while the container state is unchanged.
/// A health change (healthy → unhealthy) does not change the state, so this is
/// the most that health can lag behind.
pub(crate) const INSPECT_TTL: Duration = Duration::from_secs(30);

struct Entry {
    /// Docker state from the listing at inspect time. A different state on a
    /// later lookup (restart, stop, start) makes the entry stale at once.
    state: String,
    health_status: String,
    restart_count: u64,
    fetched_at: Instant,
}

/// Docker id → last inspect result. Pure, so the freshness rules are tested
/// without Docker.
#[derive(Default)]
pub(crate) struct InspectCache {
    entries: HashMap<String, Entry>,
}

impl InspectCache {
    /// The cached `(health_status, restart_count)`, or `None` when the id is
    /// new, its state changed, or the entry is older than [`INSPECT_TTL`].
    pub(crate) fn get(&self, id: &str, state: &str, now: Instant) -> Option<(String, u64)> {
        let e = self.entries.get(id)?;
        (e.state == state && now.saturating_duration_since(e.fetched_at) < INSPECT_TTL)
            .then(|| (e.health_status.clone(), e.restart_count))
    }

    pub(crate) fn insert(&mut self, id: &str, state: &str, value: &(String, u64), now: Instant) {
        self.entries.insert(
            id.to_string(),
            Entry {
                state: state.to_string(),
                health_status: value.0.clone(),
                restart_count: value.1,
                fetched_at: now,
            },
        );
    }

    /// Drops entries for containers Docker no longer lists, so the map does not
    /// grow without bound.
    pub(crate) fn retain_ids(&mut self, live: &HashSet<&str>) {
        self.entries.retain(|id, _| live.contains(id.as_str()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache_with(id: &str, state: &str, at: Instant) -> InspectCache {
        let mut c = InspectCache::default();
        c.insert(id, state, &("healthy".to_string(), 2), at);
        c
    }

    #[test]
    fn fresh_entry_with_same_state_is_a_hit() {
        let t = Instant::now();
        let c = cache_with("a", "running", t);
        assert_eq!(
            c.get("a", "running", t + Duration::from_secs(29)),
            Some(("healthy".to_string(), 2))
        );
    }

    #[test]
    fn unknown_id_is_a_miss() {
        let t = Instant::now();
        assert_eq!(cache_with("a", "running", t).get("b", "running", t), None);
    }

    #[test]
    fn state_change_is_a_miss() {
        let t = Instant::now();
        assert_eq!(cache_with("a", "running", t).get("a", "exited", t), None);
    }

    #[test]
    fn entry_older_than_ttl_is_a_miss() {
        let t = Instant::now();
        assert_eq!(
            cache_with("a", "running", t).get("a", "running", t + INSPECT_TTL),
            None
        );
    }

    #[test]
    fn retain_drops_unlisted_ids() {
        let t = Instant::now();
        let mut c = cache_with("a", "running", t);
        c.insert("b", "running", &("none".to_string(), 0), t);
        c.retain_ids(&HashSet::from(["b"]));
        assert_eq!(c.get("a", "running", t), None);
        assert!(c.get("b", "running", t).is_some());
    }
}
