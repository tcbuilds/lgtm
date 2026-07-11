use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

fn fake_ruff(body: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("lgtm-fake-ruff-{}-{sequence}", std::process::id()));
    std::fs::write(&path, format!("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ruff 0.test'; exit 0; fi\n{body}\n"))
        .expect("fake Ruff writable");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("fake Ruff executable");
    path
}

#[test]
fn fake_ruff_normalizes_each_stable_rule() {
    let binary = fake_ruff(
        "printf '%s' '[{\"code\":\"S110\",\"filename\":\"a.py\",\"message\":\"try-except-pass\",\"location\":{\"row\":7}},{\"code\":\"BLE001\",\"filename\":\"b.py\",\"message\":\"broad exception\",\"location\":{\"row\":9}}]'; exit 1",
    );
    let results = scan_with_binary(
        binary.to_str().expect("UTF-8 path"),
        &["a.py".to_string(), "b.py".to_string()],
    );
    std::fs::remove_file(binary).expect("fake Ruff removable");
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|result| result.status == Status::Failed));
    assert_eq!(results[0].locations[0].line, Some(7));
    assert_eq!(results[1].locations[0].line, Some(9));
}

#[test]
fn missing_ruff_is_unverified_for_both_rules() {
    let missing = format!("/missing/lgtm-ruff-{}", std::process::id());
    let results = scan_with_binary(&missing, &["a.py".to_string()]);
    assert_eq!(results.len(), 2);
    assert!(
        results
            .iter()
            .all(|result| result.status == Status::Unverified)
    );
}

#[test]
fn successful_parent_cleans_up_pipe_inheriting_descendant() {
    let binary = fake_ruff("(sleep 5) & printf '[]'; exit 0");
    let started = Instant::now();
    let results = scan_with_binary(binary.to_str().expect("UTF-8 path"), &["a.py".to_string()]);
    std::fs::remove_file(binary).expect("fake Ruff removable");

    assert!(started.elapsed() < DRAIN_TIMEOUT + Duration::from_secs(1));
    assert!(results.iter().all(|result| result.status == Status::Passed));
}
