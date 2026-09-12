use store::{CommandJournal, CommandStart};

#[test]
fn replays_a_completed_command_after_reopening_the_database() {
    let path = std::env::temp_dir().join(format!(
        "sentinel-command-journal-{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    {
        let journal = CommandJournal::open(&path, 7, 100_000).unwrap();
        assert_eq!(
            journal.start("command-1", b"request-a", 1_000).unwrap(),
            CommandStart::Started
        );
        journal.finish("command-1", b"result-a", 2_000).unwrap();
    }

    let journal = CommandJournal::open(&path, 7, 100_000).unwrap();
    assert_eq!(
        journal.start("command-1", b"request-a", 3_000).unwrap(),
        CommandStart::Completed(b"result-a".to_vec())
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn rejects_conflicts_and_does_not_repeat_an_interrupted_command() {
    let journal = CommandJournal::open_in_memory(7, 100_000).unwrap();
    assert_eq!(
        journal.start("command-1", b"request-a", 1_000).unwrap(),
        CommandStart::Started
    );
    assert_eq!(
        journal.start("command-1", b"request-a", 2_000).unwrap(),
        CommandStart::Interrupted
    );
    assert_eq!(
        journal.start("command-1", b"request-b", 2_000).unwrap(),
        CommandStart::Conflict
    );
}

#[test]
fn cleanup_removes_only_expired_or_excess_completed_commands() {
    let journal = CommandJournal::open_in_memory(7, 2).unwrap();
    let day = 86_400_000;
    journal.start("active", b"active", 0).unwrap();
    for (id, time) in [("expired", 0), ("old", 8 * day), ("new", 9 * day)] {
        journal.start(id, id.as_bytes(), time).unwrap();
        journal.finish(id, id.as_bytes(), time).unwrap();
    }

    assert_eq!(journal.cleanup(10 * day).unwrap(), 1);
    assert_eq!(
        journal.start("expired", b"expired", 10 * day).unwrap(),
        CommandStart::Started
    );
    assert_eq!(
        journal.start("active", b"active", 10 * day).unwrap(),
        CommandStart::Interrupted
    );
    assert!(matches!(
        journal.start("old", b"old", 10 * day).unwrap(),
        CommandStart::Completed(_)
    ));
    assert!(matches!(
        journal.start("new", b"new", 10 * day).unwrap(),
        CommandStart::Completed(_)
    ));
}
