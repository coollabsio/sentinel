use store::Store;

#[test]
fn reports_row_counts_and_storage_for_every_table() {
    let s = Store::open_in_memory().unwrap();
    s.insert_cpu(1_000, 1.0).unwrap();
    s.insert_cpu(2_000, 2.0).unwrap();
    s.insert_memory(&store::MemRow {
        time: 1_000,
        total: 1,
        available: 1,
        used: 1,
        used_percent: 1.0,
        free: 1,
    })
    .unwrap();

    let stats = s.db_stats().unwrap();
    assert_eq!(stats.row_count, 3, "total across all tables");
    assert!(stats.storage_bytes > 0);

    let names: Vec<_> = stats.tables.iter().map(|t| t.table_name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "cpu_usage",
            "memory_usage",
            "container_cpu_usage",
            "container_memory_usage",
            "disk_usage",
            "container_disk_usage"
        ]
    );
    let cpu = stats
        .tables
        .iter()
        .find(|t| t.table_name == "cpu_usage")
        .unwrap();
    assert_eq!(cpu.row_count, 2);
}

#[test]
fn reports_zeroes_for_an_empty_database() {
    let s = Store::open_in_memory().unwrap();
    let stats = s.db_stats().unwrap();
    assert_eq!(stats.row_count, 0);
    assert_eq!(stats.tables.len(), 6);
    assert!(stats.tables.iter().all(|t| t.row_count == 0));
}
