use std::collections::BTreeSet;

pub(super) fn add_path_observations(
    path: &str,
    languages: &mut BTreeSet<String>,
    domains: &mut BTreeSet<String>,
    risks: &mut BTreeSet<String>,
) {
    let lower = path.to_ascii_lowercase();
    add_language(&lower, languages);
    for (needle, domain) in DOMAIN_PATHS {
        if lower.contains(needle) {
            domains.insert((*domain).to_string());
        }
    }
    if SECURITY_PATHS.iter().any(|needle| lower.contains(needle)) {
        risks.insert("authentication".to_string());
    }
    if DEPENDENCY_FILES.iter().any(|name| lower.ends_with(name)) {
        risks.insert("dependency-change".to_string());
    }
}

pub(super) fn add_content_observations(
    content: &str,
    domains: &mut BTreeSet<String>,
    risks: &mut BTreeSet<String>,
) {
    let lower = content.to_ascii_lowercase();
    add_matches(&lower, IMPORT_SIGNALS, domains);
    add_matches(&lower, RISK_CONTENT, risks);
    if lower.contains("update ") && lower.contains(" set ") {
        risks.insert("database-write".to_string());
    }
}

fn add_language(path: &str, languages: &mut BTreeSet<String>) {
    let language = match path.rsplit_once('.').map(|(_, extension)| extension) {
        Some("py") => Some("python"),
        Some("rs") => Some("rust"),
        Some("ts" | "tsx") => Some("typescript"),
        Some("js" | "jsx") => Some("javascript"),
        Some("tf") => Some("terraform"),
        Some("css" | "scss") => Some("css"),
        _ => None,
    };
    if let Some(language) = language {
        languages.insert(language.to_string());
    }
}

fn add_matches(text: &str, mappings: &[(&str, &str)], output: &mut BTreeSet<String>) {
    for (needle, value) in mappings {
        if text.contains(needle) {
            output.insert((*value).to_string());
        }
    }
}

const DOMAIN_PATHS: &[(&str, &str)] = &[
    ("/routes/", "api"),
    ("/api/", "api"),
    ("/models/", "database"),
    ("/migrations/", "database"),
    ("/workers/", "worker"),
    ("terraform", "infrastructure"),
    (".github/workflows", "infrastructure"),
    ("/components/", "frontend"),
];

const SECURITY_PATHS: &[&str] = &["/auth", "/security", "permissions", "oauth"];
const DEPENDENCY_FILES: &[&str] = &[
    "pyproject.toml",
    "requirements.txt",
    "cargo.toml",
    "package.json",
];
const IMPORT_SIGNALS: &[(&str, &str)] = &[
    ("fastapi", "api"),
    ("flask", "api"),
    ("sqlalchemy", "database"),
    ("psycopg", "database"),
    ("postgres", "database"),
    ("celery", "worker"),
    ("import react", "frontend"),
];
const RISK_CONTENT: &[(&str, &str)] = &[
    ("@app.", "public-api"),
    ("@router.", "public-api"),
    ("insert into", "database-write"),
    ("delete from", "database-write"),
    (".commit(", "database-write"),
    ("requests.", "http-client"),
    ("httpx.", "http-client"),
    ("subprocess.", "subprocess"),
    ("jwt", "authentication"),
    ("oauth", "authentication"),
    (".auth import", "authentication"),
];
