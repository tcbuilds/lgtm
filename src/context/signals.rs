use std::collections::BTreeSet;

pub(super) fn add_path_observations(
    path: &str,
    languages: &mut BTreeSet<String>,
    domains: &mut BTreeSet<String>,
    risks: &mut BTreeSet<String>,
) {
    let lower = path.to_ascii_lowercase();
    add_language(&lower, languages);
    for (name, domain) in DOMAIN_DIRECTORY_PATHS {
        if has_directory_component(&lower, name) {
            domains.insert((*domain).to_string());
        }
    }
    for (name, domain) in DOMAIN_COMPONENT_PATHS {
        if has_component_or_filename_stem(&lower, name) {
            domains.insert((*domain).to_string());
        }
    }
    for (first, second, domain) in DOMAIN_DIRECTORY_SEQUENCES {
        if has_directory_sequence(&lower, first, second) {
            domains.insert((*domain).to_string());
        }
    }
    if SECURITY_PATHS
        .iter()
        .any(|name| has_component_or_filename_stem(&lower, name))
    {
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
        Some("go") => Some("go"),
        Some("ts" | "tsx") => Some("typescript"),
        Some("js" | "jsx") => Some("javascript"),
        Some("sh" | "bash") => Some("shell"),
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

fn has_directory_component(path: &str, name: &str) -> bool {
    let mut components = path_components(path).peekable();
    while let Some(component) = components.next() {
        if component == name && components.peek().is_some() {
            return true;
        }
    }
    false
}

fn has_directory_sequence(path: &str, first: &str, second: &str) -> bool {
    let mut components = path_components(path).peekable();
    while let Some(component) = components.next() {
        if component == first && components.peek().copied() == Some(second) {
            components.next();
            if components.peek().is_some() {
                return true;
            }
        }
    }
    false
}

fn has_component_or_filename_stem(path: &str, name: &str) -> bool {
    let mut components = path_components(path).peekable();
    while let Some(component) = components.next() {
        if component == name {
            return true;
        }
        if components.peek().is_none()
            && component
                .rsplit_once('.')
                .is_some_and(|(stem, _)| stem == name)
        {
            return true;
        }
    }
    false
}

fn path_components(path: &str) -> impl Iterator<Item = &str> {
    path.split('/')
        .filter(|component| !component.is_empty() && *component != ".")
}

const DOMAIN_DIRECTORY_PATHS: &[(&str, &str)] = &[
    ("routes", "api"),
    ("api", "api"),
    ("models", "database"),
    ("migrations", "database"),
    ("workers", "worker"),
    ("components", "frontend"),
];
const DOMAIN_COMPONENT_PATHS: &[(&str, &str)] = &[("terraform", "infrastructure")];
const DOMAIN_DIRECTORY_SEQUENCES: &[(&str, &str, &str)] =
    &[(".github", "workflows", "infrastructure")];
const SECURITY_PATHS: &[&str] = &["auth", "security", "permissions", "oauth"];
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
    ("sqlalchemy", "database-client"),
    ("psycopg", "database-client"),
    ("postgres", "database-client"),
    ("subprocess.", "subprocess"),
    ("request.get_json", "public-input"),
    ("cursor.execute", "database-client"),
    ("while true", "loop"),
    ("retry", "retry"),
    ("shutil.rmtree", "destructive-operation"),
    ("try:", "try-except"),
    ("except ", "exception-handler"),
    ("except:", "bare-except"),
    ("jwt", "authentication"),
    ("oauth", "authentication"),
    (".auth import", "authentication"),
];
