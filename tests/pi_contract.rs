use std::fs;

use serde_json::Value;

const MATRIX_PATH: &str = "tests/fixtures/pi/0.84.2/capability_matrix.json";
const TOOLS_PATH: &str = "tests/fixtures/pi/0.84.2/tool_provenance.json";
const DISCOVERY_PATH: &str = "tests/fixtures/pi/0.84.2/discovery.json";
const TRUST_PATH: &str = "tests/fixtures/pi/0.84.2/trust.json";
const MALFORMED_PATH: &str = "tests/fixtures/pi/0.84.2/malformed_extension.json";
const MANIFEST_PATH: &str = "tests/fixtures/pi/0.84.2/capture_manifest.json";
const SOURCE_PATH: &str = "tests/fixtures/pi/0.84.2/source_captures.json";
const DOC_PATH: &str = "doc/adapters/pi.md";

fn read_json(path: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("fixture exists"))
        .unwrap_or_else(|error| panic!("{path} must contain valid JSON: {error}"))
}

fn rows() -> Vec<Value> {
    read_json(MATRIX_PATH)["rows"]
        .as_array()
        .expect("capability rows are an array")
        .clone()
}

#[test]
fn capability_rows_carry_provenance_and_fixture_ids() {
    let matrix = read_json(MATRIX_PATH);
    assert_eq!(matrix["schema_version"], 1);
    assert_eq!(matrix["pi_version"], "0.84.2");
    assert_eq!(matrix["package"], "@earendil-works/pi-coding-agent");
    let manifest = read_json(MANIFEST_PATH);
    let captures = manifest["captures"].as_array().expect("capture manifest");
    let source = read_json(SOURCE_PATH);
    let source_captures = source["captures"].as_array().expect("source captures");

    let allowed_statuses = ["verified_source", "verified_live", "unverified"];
    for row in rows() {
        for key in [
            "id",
            "lgtm_hook",
            "pi_event",
            "tool_name",
            "fixture_id",
            "tool_input_path",
            "response_support",
            "discovery_method",
            "verification_status",
            "evidence",
        ] {
            assert!(row.get(key).is_some(), "row is missing {key}: {row:?}");
        }
        let status = row["verification_status"]
            .as_str()
            .expect("verification status is a string");
        assert!(
            allowed_statuses.contains(&status),
            "unknown status: {status}"
        );
        assert!(!row["id"].as_str().unwrap().is_empty());
        let fixture_id = row["fixture_id"].as_str().expect("fixture id");
        assert!(!fixture_id.is_empty());
        let capture = captures
            .iter()
            .find(|capture| capture["fixture_id"] == fixture_id)
            .unwrap_or_else(|| panic!("manifest is missing {fixture_id}"));
        assert!(
            capture["kind"]
                .as_str()
                .is_some_and(|kind| !kind.is_empty())
        );
        let capture_path = capture["path"].as_str().expect("capture path");
        assert!(!capture_path.is_empty());
        if capture["kind"] == "source" {
            let source_capture = source_captures
                .iter()
                .find(|item| item["fixture_id"] == fixture_id)
                .unwrap_or_else(|| panic!("source capture is missing {fixture_id}"));
            assert!(
                source["capture_method"]
                    .as_str()
                    .is_some_and(|method| !method.is_empty())
            );
            assert!(
                source_capture["excerpt"]
                    .as_str()
                    .is_some_and(|excerpt| !excerpt.is_empty())
            );
        } else {
            assert!(
                std::path::Path::new("tests/fixtures/pi/0.84.2")
                    .join(capture_path)
                    .is_file()
            );
        }
        assert!(!row["discovery_method"].as_str().unwrap().is_empty());
        assert!(!row["response_support"].as_str().unwrap().is_empty());
        assert!(
            row["evidence"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        );
        if status == "unverified" {
            assert!(
                row["notes"]
                    .as_str()
                    .is_some_and(|notes| notes.contains("unverified"))
            );
        }
    }
}

#[test]
fn every_manifest_capture_and_matrix_citation_resolves_to_checked_in_evidence() {
    let manifest = read_json(MANIFEST_PATH);
    let source = read_json(SOURCE_PATH);
    let base = std::path::Path::new("tests/fixtures/pi/0.84.2");
    let source_captures = source["captures"].as_array().expect("source captures");
    for capture in source_captures {
        let path = capture["source_path"].as_str().expect("source path");
        let file = base.join(path);
        let lines = fs::read_to_string(&file).expect("checked-in source capture");
        let range = capture["line_range"].as_str().expect("line range");
        let mut bounds = range
            .split('-')
            .map(|value| value.parse::<usize>().unwrap());
        let start = bounds.next().unwrap();
        let end = bounds.next().unwrap();
        let excerpt = capture["excerpt"].as_str().expect("source excerpt");
        let actual = lines
            .lines()
            .skip(start - 1)
            .take(end - start + 1)
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(actual, excerpt, "citation drifted for {path}:{range}");
    }
    let source_ids: std::collections::BTreeSet<_> = source_captures
        .iter()
        .map(|capture| capture["fixture_id"].as_str().unwrap())
        .collect();
    for row in rows() {
        assert!(
            source_ids.contains(row["fixture_id"].as_str().unwrap())
                || manifest["captures"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|capture| capture["fixture_id"] == row["fixture_id"])
        );
        assert!(row["notes"].as_str().is_some_and(|notes| !notes.is_empty()));
        for citation in row["evidence"].as_array().unwrap() {
            let citation = citation.as_str().unwrap();
            if citation.starts_with("dist/") || citation.starts_with("docs/") {
                let (path, range) = citation.rsplit_once(':').expect("citation path and range");
                let file = base
                    .join("captures")
                    .join(std::path::Path::new(path).file_name().unwrap());
                assert!(file.is_file(), "citation path is not captured: {citation}");
                assert!(range.contains('-'), "citation range is missing: {citation}");
            }
        }
    }
    for capture in manifest["captures"].as_array().unwrap() {
        if capture["kind"] == "live" {
            let path = base.join(capture["path"].as_str().unwrap());
            let value = read_json(path.to_str().unwrap());
            assert!(
                contains_value(&value, capture["fixture_id"].as_str().unwrap()),
                "live fixture id missing from target"
            );
        }
    }
}

fn contains_value(value: &Value, expected: &str) -> bool {
    value.as_str() == Some(expected)
        || value
            .as_array()
            .is_some_and(|items| items.iter().any(|item| contains_value(item, expected)))
        || value
            .as_object()
            .is_some_and(|items| items.values().any(|item| contains_value(item, expected)))
}

#[test]
fn documentation_names_every_matrix_capability_without_overclaiming() {
    let doc = fs::read_to_string(DOC_PATH).expect("Pi contract document exists");
    let lower = doc.to_ascii_lowercase();
    assert!(
        !lower.contains("all tools"),
        "documentation must not claim all tools"
    );
    assert!(
        !lower.contains("universal interception"),
        "documentation must not claim universal interception"
    );
    for row in rows() {
        let id = row["id"].as_str().expect("row id is a string");
        assert!(doc.contains(id), "documentation is missing matrix row {id}");
    }
    assert!(
        doc.contains("unverified"),
        "deferred capabilities must be explicit"
    );
}

#[test]
fn tool_provenance_fixture_requires_builtin_source_and_schema() {
    let fixture = read_json(TOOLS_PATH);
    assert_eq!(fixture["pi_version"], "0.84.2");
    let captures = fixture["captures"]
        .as_array()
        .expect("captures are an array");
    let builtins = captures
        .iter()
        .find(|capture| capture["fixture_id"] == "live-sdk-builtins-001")
        .expect("built-in capture exists");
    let tools = builtins["tools"]
        .as_array()
        .expect("built-in tools are an array");
    for (name, required, source_path) in [
        ("read", &["path"][..], "<builtin:read>"),
        ("bash", &["command"][..], "<builtin:bash>"),
        ("edit", &["path", "edits"][..], "<builtin:edit>"),
        ("write", &["path", "content"][..], "<builtin:write>"),
    ] {
        let tool = tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("missing built-in tool {name}"));
        assert_eq!(tool["source_info"]["source"], "builtin");
        assert_eq!(tool["source_info"]["path"], source_path);
        for required_key in required {
            assert!(
                tool["parameters"]["required"]
                    .as_array()
                    .is_some_and(|keys| keys.iter().any(|key| key == required_key)),
                "{name} is missing required parameter {required_key}"
            );
        }
        assert_eq!(
            tool["enforcement_eligibility"],
            "verified_builtin_provenance_and_schema"
        );
    }
}

#[test]
fn same_name_override_remains_unverified_for_builtin_enforcement() {
    let fixture = read_json(TOOLS_PATH);
    let override_capture = fixture["captures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|capture| capture["fixture_id"] == "live-sdk-override-001")
        .expect("override capture exists");
    let tool = &override_capture["tools"][0];
    assert_eq!(tool["name"], "read");
    assert_ne!(tool["source_info"]["source"], "builtin");
    assert_eq!(tool["source_info"]["scope"], "project");
    assert_eq!(
        tool["enforcement_eligibility"],
        "unverified_same_name_override"
    );
}

#[test]
fn discovery_fixture_pins_project_global_and_nested_cwd_behavior() {
    let fixture = read_json(DISCOVERY_PATH);
    assert_eq!(
        fixture["project_root"]["loaded_extensions"][0],
        "<project>/.pi/extensions/project.ts"
    );
    assert_eq!(
        fixture["project_root"]["loaded_extensions"][1],
        "<agent>/extensions/global.ts"
    );
    assert_eq!(
        fixture["nested_cwd"]["loaded_extensions"][0],
        "<agent>/extensions/global.ts"
    );
    assert_eq!(
        fixture["interpretation"]["project_extension_ancestor_walk"],
        false
    );
    assert_eq!(
        fixture["interpretation"]["global_extension_applies_to_nested_cwd"],
        true
    );
    assert_eq!(
        fixture["interpretation"]["project_before_global_order"],
        true
    );
}

#[test]
fn trust_and_malformed_extension_fixtures_preserve_runtime_decisions() {
    let trust = read_json(TRUST_PATH);
    assert_eq!(trust["decisions"]["yes"]["trusted"], "yes");
    assert_eq!(trust["decisions"]["no"]["trusted"], "no");
    assert_eq!(trust["decisions"]["yes"]["remember"], false);
    assert_eq!(trust["decisions"]["no"]["remember"], false);

    let malformed = read_json(MALFORMED_PATH);
    assert_eq!(
        malformed["loaded_extensions"][0],
        "<agent>/extensions/good.ts"
    );
    assert_eq!(
        malformed["errors"][0]["path"],
        "<project>/.pi/extensions/bad.ts"
    );
    assert!(
        malformed["errors"][0]["error"]
            .as_str()
            .is_some_and(|error| error.contains("valid factory function"))
    );
}
