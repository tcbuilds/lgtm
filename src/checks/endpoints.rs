//! Deterministic public-endpoint signals for common Python/TypeScript frameworks.

use std::path::Path;

use super::{EnforcementResult, Location, ResultEvidence, Status};
use crate::policy::Severity;

pub fn scan(files: &[String]) -> Vec<EnforcementResult> {
    let mut locations = Vec::new();
    for file in files {
        let lower_path = file.to_ascii_lowercase();
        let Ok(source) = std::fs::read_to_string(Path::new(file)) else {
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            let fastapi = lower.contains("@app.get")
                || lower.contains("@app.post")
                || lower.contains("@router.");
            let express = lower.contains("app.get(")
                || lower.contains("app.post(")
                || lower.contains("router.get(");
            let next = lower_path.contains("/api/")
                || lower.contains("export async function get(")
                || lower.contains("export async function post(");
            if fastapi || express || next {
                locations.push(Location {
                    file: file.clone(),
                    line: Some((index + 1) as u64),
                });
            }
        }
    }
    let status = if files.is_empty() {
        Status::NotApplicable
    } else if locations.is_empty() {
        Status::Passed
    } else {
        Status::Warning
    };
    vec![EnforcementResult {
        rule_id: "public-endpoint-review".to_string(),
        status,
        severity: Severity::Warning,
        message: if locations.is_empty() { "No supported public endpoint signal was found.".to_string() } else { format!("Review {} public endpoint signal(s) for validation, auth, rate limits, and secure defaults.", locations.len()) },
        locations,
        remediation: (status == Status::Warning).then(|| "Add boundary validation, server-side authorization, rate limiting, and secure cookie/CORS/CSRF/debug settings; document evidence.".to_string()),
        evidence: ResultEvidence { check: "native.public-endpoints".to_string(), tool_version: None, finding_descriptions: Vec::new() },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_fastapi_and_next_route_signals() {
        let root = std::env::temp_dir().join(format!("lgtm-endpoints-{}", std::process::id()));
        std::fs::create_dir_all(root.join("api")).expect("root");
        let py = root.join("routes.py");
        let ts = root.join("api/route.ts");
        std::fs::write(&py, "@app.get('/items')\ndef items(): pass\n").expect("fastapi");
        std::fs::write(
            &ts,
            "export async function GET() { return Response.json({}); }\n",
        )
        .expect("next");
        let results = scan(&[
            py.to_string_lossy().into_owned(),
            ts.to_string_lossy().into_owned(),
        ]);
        assert_eq!(results[0].status, Status::Warning);
        assert_eq!(results[0].locations.len(), 2);
        std::fs::remove_dir_all(root).ok();
    }
}
