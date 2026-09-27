use std::path::PathBuf;

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitIdentity {
    pub(crate) digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CommitAssessment {
    Pass {
        identity: CommitIdentity,
    },
    Deny {
        identity: Option<CommitIdentity>,
        reason: String,
    },
    PendingHeuristicApproval {
        identity: CommitIdentity,
        findings: Vec<CommitFinding>,
    },
}

impl CommitAssessment {
    pub(crate) fn blocking_reason(&self) -> String {
        match self {
            Self::Pass { .. } => String::new(),
            Self::Deny { reason, .. } => reason.clone(),
            Self::PendingHeuristicApproval { findings, .. } => format!(
                "staged commit secret assessment requires heuristic approval for {} potential finding(s), but this adapter has no approval path; {}",
                findings.len(),
                super::COMMIT_REMEDIATION
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommitFinding {
    pub(crate) rule_id: String,
    pub(crate) file: String,
    pub(crate) start_line: u64,
    pub(crate) start_column: u64,
    pub(crate) end_line: u64,
    pub(crate) end_column: u64,
    pub(crate) fingerprint: String,
    pub(crate) blob_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BoundFile {
    pub(super) path: PathBuf,
    pub(super) contents: Vec<u8>,
    pub(super) digest: String,
    pub(super) metadata_identity: String,
    pub(super) present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RepositoryState {
    pub(super) root: String,
    pub(super) git_dir: String,
    pub(super) head: String,
    pub(super) tree: String,
    pub(super) index_identity: String,
    pub(super) head_identity: String,
    pub(super) git_binary_identity: String,
}

pub(super) struct GitCapture {
    pub(super) code: Option<i32>,
    pub(super) stdout: Vec<u8>,
}

pub(super) struct IdentityContext<'a> {
    pub(super) config: &'a BoundFile,
    pub(super) ignore: &'a BoundFile,
    pub(super) policy_config: &'a BoundFile,
    pub(super) waivers: &'a BoundFile,
    pub(super) scanner_version: &'a str,
    pub(super) scanner_binary_identity: &'a str,
    pub(super) commit_argv: &'a [String],
    pub(super) session_id: Option<&'a str>,
    pub(super) harness: &'a str,
    pub(super) findings: &'a [CommitFinding],
}

pub(super) fn build_identity(
    state: &RepositoryState,
    context: IdentityContext<'_>,
) -> CommitIdentity {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, "lgtm.commit-index-assessment.v1");
    hash_field(&mut hasher, &state.root);
    hash_field(&mut hasher, &state.git_dir);
    hash_field(&mut hasher, &state.head);
    hash_field(&mut hasher, &state.tree);
    hash_field(&mut hasher, &state.index_identity);
    hash_field(&mut hasher, &state.head_identity);
    hash_field(&mut hasher, &state.git_binary_identity);
    hash_field(&mut hasher, context.session_id.unwrap_or("<none>"));
    hash_field(&mut hasher, context.harness);
    hash_field(&mut hasher, super::COMMIT_SCANNER_MODE);
    hash_field(&mut hasher, context.scanner_version);
    hash_field(&mut hasher, context.scanner_binary_identity);
    hash_field(&mut hasher, &context.config.digest);
    hash_field(&mut hasher, &context.config.metadata_identity);
    hash_field(&mut hasher, &context.ignore.digest);
    hash_field(&mut hasher, &context.ignore.metadata_identity);
    hash_field(&mut hasher, &context.policy_config.digest);
    hash_field(&mut hasher, &context.policy_config.metadata_identity);
    hash_field(&mut hasher, &context.waivers.digest);
    hash_field(&mut hasher, &context.waivers.metadata_identity);
    hash_field(&mut hasher, crate::policy::POLICY_BUNDLE_VERSION);
    hash_field(&mut hasher, &crate::policy::bundle_digest());
    for argument in context.commit_argv {
        hash_field(&mut hasher, argument);
    }
    for finding in context.findings {
        hash_field(&mut hasher, &finding.rule_id);
        hash_field(&mut hasher, &finding.file);
        hash_field(&mut hasher, &finding.start_line.to_string());
        hash_field(&mut hasher, &finding.start_column.to_string());
        hash_field(&mut hasher, &finding.end_line.to_string());
        hash_field(&mut hasher, &finding.end_column.to_string());
        hash_field(&mut hasher, &finding.fingerprint);
        hash_field(&mut hasher, &finding.blob_identity);
    }
    CommitIdentity {
        digest: format!("{:x}", hasher.finalize()),
    }
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}
