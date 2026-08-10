use super::CachedMemory;
use store::MemRow;

fn memory(used: u64) -> MemRow {
    MemRow {
        time: 0,
        total: 100,
        available: 100 - used,
        used,
        used_percent: used as f64,
        free: 100 - used,
    }
}

#[test]
fn cached_memory_returns_the_latest_snapshot() {
    let cache = CachedMemory::new(memory(10));
    assert_eq!(cache.get().used, 10);

    cache.set(memory(25));

    assert_eq!(cache.get().used, 25);
}
