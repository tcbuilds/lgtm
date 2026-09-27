use std::path::PathBuf;

use super::*;

#[test]
fn configured_generic_rule_is_not_heuristic_eligible() {
    let finding = CommitFinding {
        rule_id: GENERIC_RULE_ID.to_string(),
        file: "a.txt".to_string(),
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 2,
        fingerprint: "a".to_string(),
        blob_identity: "b".to_string(),
    };
    for contents in [
        b"[[rules]]\nid = \"generic-api-key\"\n".to_vec(),
        b"[[rules]]\nid = \"custom-rule\"\n".to_vec(),
    ] {
        let config = BoundFile {
            path: PathBuf::from(".gitleaks.toml"),
            contents,
            digest: String::new(),
            metadata_identity: String::new(),
            present: true,
        };
        assert!(!is_heuristic_eligible(&finding, &config));
    }
}

#[test]
fn identity_is_full_sha256_not_a_truncated_hash() {
    let state = RepositoryState {
        root: "/repo".to_string(),
        git_dir: "/repo/.git".to_string(),
        head: "commit:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        tree: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        index_identity: "index".to_string(),
        head_identity: "head".to_string(),
        git_binary_identity: "git-binary".to_string(),
    };
    let file = BoundFile {
        path: PathBuf::from("config"),
        contents: Vec::new(),
        digest: "config".to_string(),
        metadata_identity: "metadata".to_string(),
        present: false,
    };
    let commit_argv = ["git".to_string(), "commit".to_string()];
    let identity = build_identity(
        &state,
        IdentityContext {
            config: &file,
            ignore: &file,
            policy_config: &file,
            waivers: &file,
            execution_policy: &file,
            scanner_version: "gitleaks 8.30.1",
            scanner_binary_identity: "gitleaks-binary",
            commit_argv: &commit_argv,
            session_id: Some("session"),
            harness: "claude",
            findings: &[],
        },
    );
    assert_eq!(identity.digest.len(), 64);
}
