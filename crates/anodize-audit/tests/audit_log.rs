use anodize_audit::{genesis_hash, verify_log, AuditLog};
use tempfile::TempDir;

#[test]
fn create_append_verify() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    let genesis = genesis_hash(b"fake-root-cert-der");
    let mut log = AuditLog::create(&path, &genesis).unwrap();

    for i in 0u64..5 {
        log.append("test.event", serde_json::json!({"i": i}))
            .unwrap();
    }

    let count = verify_log(&path).unwrap();
    assert_eq!(count, 5);
}

#[test]
fn open_resumes_chain() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");

    let genesis = genesis_hash(b"some-cert");
    {
        let mut log = AuditLog::create(&path, &genesis).unwrap();
        log.append("first", serde_json::json!({})).unwrap();
        log.append("second", serde_json::json!({})).unwrap();
    }

    // Re-open and append more.
    let mut log = AuditLog::open(&path).unwrap();
    let r = log.append("third", serde_json::json!({})).unwrap();
    assert_eq!(r.seq, 2);

    assert_eq!(verify_log(&path).unwrap(), 3);
}
