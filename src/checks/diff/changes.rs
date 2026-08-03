use std::collections::BTreeSet;

pub(super) fn parse_paths(
    bytes: &[u8],
    files: &mut BTreeSet<String>,
    test_evidence_excluded: &mut BTreeSet<String>,
) -> Result<(), String> {
    for field in bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
    {
        let path = std::str::from_utf8(field).map_err(|_| "git path was not UTF-8")?;
        validate_path(path)?;
        files.insert(path.to_string());
        test_evidence_excluded.remove(path);
    }
    Ok(())
}

pub(super) fn parse_name_status(
    bytes: &[u8],
    files: &mut BTreeSet<String>,
    test_evidence_excluded: &mut BTreeSet<String>,
) -> Result<(), String> {
    let fields: Vec<_> = bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect();
    let mut index = 0;
    while index < fields.len() {
        let status = std::str::from_utf8(fields[index]).map_err(|_| "git status was not UTF-8")?;
        index += 1;
        let paths = usize::from(status.starts_with('R') || status.starts_with('C')) + 1;
        if index + paths > fields.len() {
            return Err("malformed git name-status output".to_string());
        }
        let is_deleted = status.starts_with('D');
        let is_rename_or_copy = status.starts_with('R') || status.starts_with('C');
        for (path_index, field) in fields[index..index + paths].iter().enumerate() {
            let path = std::str::from_utf8(field).map_err(|_| "git path was not UTF-8")?;
            validate_path(path)?;
            files.insert(path.to_string());
            if is_deleted && path_index == 0 {
                test_evidence_excluded.insert(path.to_string());
            } else if !is_rename_or_copy || path_index > 0 {
                test_evidence_excluded.remove(path);
            }
        }
        index += paths;
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), String> {
    if path.starts_with('/') || path.split('/').any(|part| part == "..") {
        Err("unsafe git path".to_string())
    } else {
        Ok(())
    }
}
