use super::*;

fn waiver() -> Waiver {
    Waiver {
        rule_id: "no-broad-exception-handling".to_string(),
        reason: "legacy boundary".to_string(),
        owner: "platform".to_string(),
        expires: "2999-12-31".to_string(),
    }
}

fn result(status: Status, remediation: Option<&str>) -> EnforcementResult {
    EnforcementResult {
        rule_id: "no-broad-exception-handling".to_string(),
        status,
        severity: super::super::Severity::Error,
        message: "result".to_string(),
        locations: Vec::new(),
        remediation: remediation.map(str::to_string),
        evidence: crate::checks::ResultEvidence {
            check: "ruff.check".to_string(),
            tool_version: None,
            finding_descriptions: Vec::new(),
        },
    }
}

#[test]
fn active_waiver_marks_failure_and_clears_remediation() {
    let mut results = vec![result(Status::Failed, Some("fix"))];
    apply(&[waiver()], &mut results);
    assert_eq!(results[0].status, Status::Waived);
    assert!(results[0].remediation.is_none());
}

#[test]
fn active_waiver_does_not_hide_passing_check() {
    let mut results = vec![result(Status::Passed, None)];
    apply(&[waiver()], &mut results);
    assert_eq!(results[0].status, Status::Passed);
}

#[test]
fn calendar_validation_rejects_impossible_dates() {
    assert_eq!(parse_date("1970-01-01"), Ok(0));
    assert!(parse_date("2027-02-29").is_err());
    assert!(parse_date("2028-02-29").is_ok());
}

#[test]
fn protected_rule_ids_are_unwaivable_even_if_category_metadata_drifts() {
    let rules = super::super::load_embedded_registry().expect("registry");
    for rule_id in [
        "no-committed-secrets",
        "sql-parameterization",
        "destructive-operation-safeguards",
        "auth-change-security-review",
    ] {
        let mut rule = find_rule(&rules, rule_id)
            .expect("protected rule exists")
            .clone();
        rule.category = Category::Architecture;
        assert!(
            ensure_waivable(&rule).is_err(),
            "{rule_id} must stay protected"
        );
    }
}

#[test]
fn an_overridable_nonsecurity_rule_remains_waivable() {
    let rules = super::super::load_embedded_registry().expect("registry");
    let rule = find_rule(&rules, "function-size").expect("overridable rule");
    assert!(ensure_waivable(rule).is_ok());
}

fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("lgtm-waivers-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join(".lgtm")).expect("create temp root");
    root
}

fn write_store(root: &Path, waivers: &[Waiver]) {
    let store = Store {
        waivers: waivers.to_vec(),
    };
    let bytes = serde_json::to_vec_pretty(&store).expect("serialize store");
    std::fs::write(root.join(".lgtm/waivers.json"), bytes).expect("write store");
}

#[derive(Debug, Deserialize)]
struct SurvivorBaseline {
    schema_version: u32,
    budget_seconds: u64,
    survivors: Vec<SurvivorEntry>,
}

#[derive(Debug, Deserialize)]
struct SurvivorEntry {
    file: String,
    line: u32,
    name: String,
    mutation: String,
    reason: String,
    owner: String,
    date: String,
    classification: String,
}

fn read_survivor_baseline() -> SurvivorBaseline {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("mutation-survivors.json");
    let raw = std::fs::read_to_string(path).expect("survivor baseline is checked in");
    serde_json::from_str(&raw).expect("survivor baseline has valid metadata")
}

fn validate_survivor_baseline(baseline: &SurvivorBaseline) -> BTreeSet<String> {
    assert_eq!(baseline.schema_version, 1);
    assert!(baseline.budget_seconds > 0);
    let mut names = BTreeSet::new();
    for entry in &baseline.survivors {
        assert!(entry.file.starts_with("src/"));
        assert!(entry.line > 0);
        assert!(!entry.reason.trim().is_empty());
        assert!(!entry.owner.trim().is_empty());
        assert!(matches!(
            entry.classification.as_str(),
            "equivalent" | "gap"
        ));
        assert_eq!(entry.date.len(), 10);
        assert!(
            entry
                .date
                .as_bytes()
                .iter()
                .enumerate()
                .all(|(index, byte)| {
                    if matches!(index, 4 | 7) {
                        *byte == b'-'
                    } else {
                        byte.is_ascii_digit()
                    }
                })
        );
        assert!(parse_date(&entry.date).is_ok());
        assert!(
            entry
                .name
                .starts_with(&format!("{}:{}:", entry.file, entry.line))
        );
        assert_eq!(
            entry.name.rsplit_once(": ").map(|(_, value)| value),
            Some(entry.mutation.as_str())
        );
        assert!(
            names.insert(entry.name.clone()),
            "duplicate survivor: {}",
            entry.name
        );
    }
    names
}

fn assert_missed_report_is_reviewed(path: &Path, names: &BTreeSet<String>) {
    let raw = std::fs::read_to_string(path).expect("missed survivor fixture exists");
    for name in raw.lines().filter(|line| !line.is_empty()) {
        assert!(names.contains(name), "unreviewed mutation survivor: {name}");
    }
}

#[test]
fn survivor_baseline_validates_metadata_and_rejects_unlisted_misses() {
    let baseline = read_survivor_baseline();
    let names = validate_survivor_baseline(&baseline);
    let empty_baseline = SurvivorBaseline {
        schema_version: baseline.schema_version,
        budget_seconds: baseline.budget_seconds,
        survivors: Vec::new(),
    };
    assert!(validate_survivor_baseline(&empty_baseline).is_empty());
    let root = temp_root("survivor-report");
    let output = root.join("mutants.out");
    std::fs::create_dir_all(&output).expect("create survivor fixture");
    let missed = output.join("missed.txt");
    if let Some(listed) = baseline.survivors.first().map(|entry| entry.name.as_str()) {
        std::fs::write(&missed, format!("{listed}\n")).expect("write listed survivor fixture");
        assert_missed_report_is_reviewed(&missed, &names);
    } else {
        std::fs::write(&missed, "").expect("write empty survivor fixture");
        assert_missed_report_is_reviewed(&missed, &names);
    }

    std::fs::write(&missed, "unlisted survivor\n").expect("write unlisted survivor fixture");
    let rejection = std::panic::catch_unwind(|| {
        assert_missed_report_is_reviewed(&missed, &names);
    });
    assert!(rejection.is_err(), "unlisted survivor must be rejected");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn elapsed_expiry_does_not_invalidate_the_store() {
    let mut item = waiver();
    item.expires = "2000-01-01".to_string();
    let store = Store {
        waivers: vec![item],
    };
    let rules = super::super::load_embedded_registry().expect("registry");
    validate_store(&store, &rules).expect("an elapsed expiry must not corrupt the store");
}

#[test]
fn load_active_drops_expired_waivers_and_keeps_current_ones() {
    let root = temp_root("mixed");
    let mut expired = waiver();
    expired.expires = "2000-01-01".to_string();
    let mut active = waiver();
    active.rule_id = "function-size".to_string();
    write_store(&root, &[expired, active]);
    let rules = super::super::load_embedded_registry().expect("registry");
    let loaded = load_active(&root, &rules).expect("an expired waiver must not fail the load");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].rule_id, "function-size");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn load_active_uses_the_expiry_boundary_of_an_injected_day() {
    let root = temp_root("boundary");
    let evaluated = parse_date("2026-08-02").expect("fixed evaluated date");
    let mut before = waiver();
    before.rule_id = "function-size".to_string();
    before.expires = "2026-08-01".to_string();
    let mut on = waiver();
    on.rule_id = "file-size".to_string();
    on.expires = "2026-08-02".to_string();
    let mut after = waiver();
    after.rule_id = "function-complexity".to_string();
    after.expires = "2026-08-03".to_string();
    write_store(&root, &[before, on, after]);
    let rules = super::super::load_embedded_registry().expect("registry");
    let loaded = load_active_at(&root, &rules, evaluated).expect("fixed-date load");
    assert_eq!(
        loaded
            .iter()
            .map(|item| item.rule_id.as_str())
            .collect::<Vec<_>>(),
        vec!["function-complexity"]
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn store_still_rejects_malformed_expiry() {
    let mut item = waiver();
    item.expires = "not-a-date".to_string();
    let store = Store {
        waivers: vec![item],
    };
    let rules = super::super::load_embedded_registry().expect("registry");
    assert!(validate_store(&store, &rules).is_err());
}

#[test]
fn creating_a_waiver_still_requires_a_future_expiry() {
    assert!(validate_future_date("2000-01-01").is_err());
    assert!(validate_future_date("2999-12-31").is_ok());
}

#[test]
fn store_rejects_duplicate_rule_entries() {
    let item = waiver();
    let store = Store {
        waivers: vec![item.clone(), item],
    };
    let rules = super::super::load_embedded_registry().expect("registry");
    assert!(validate_store(&store, &rules).is_err());
}
