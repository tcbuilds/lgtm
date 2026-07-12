//! Bounded lexical structural metrics for AST-dependent policy slices.

use std::path::Path;

use thiserror::Error;

const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_LINES: usize = 20_000;
const MAX_TOKENS: usize = 200_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub language: String,
    pub file_lines: usize,
    pub token_count: usize,
    pub functions: Vec<FunctionMetric>,
    pub types: Vec<TypeMetric>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionMetric {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub lines: usize,
    pub parameters: usize,
    pub complexity: usize,
    pub max_nesting: usize,
    pub exempt: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeMetric {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub lines: usize,
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("unsupported structural language `{0}`")]
    UnsupportedLanguage(String),
    #[error("source exceeds structural byte limit")]
    Oversized,
    #[error("source exceeds structural line limit")]
    TooManyLines,
    #[error("source exceeds structural token limit")]
    TooManyTokens,
    #[error("source has invalid UTF-8")]
    InvalidUtf8,
    #[error("source has unbalanced braces")]
    UnbalancedBraces,
}

pub fn analyze_file(path: &Path, language: &str) -> Result<Analysis, AnalysisError> {
    if is_excluded_path(path) {
        return Err(AnalysisError::UnsupportedLanguage(
            "excluded path".to_string(),
        ));
    }
    let metadata = std::fs::metadata(path).map_err(|_| AnalysisError::InvalidUtf8)?;
    if metadata.len() > MAX_SOURCE_BYTES {
        return Err(AnalysisError::Oversized);
    }
    let bytes = std::fs::read(path).map_err(|_| AnalysisError::InvalidUtf8)?;
    let source = std::str::from_utf8(&bytes).map_err(|_| AnalysisError::InvalidUtf8)?;
    analyze_source(language, source)
}

pub fn analyze_source(language: &str, source: &str) -> Result<Analysis, AnalysisError> {
    if !matches!(
        language,
        "python" | "rust" | "typescript" | "javascript" | "go"
    ) {
        return Err(AnalysisError::UnsupportedLanguage(language.to_string()));
    }
    if source.len() as u64 > MAX_SOURCE_BYTES {
        return Err(AnalysisError::Oversized);
    }
    let lines: Vec<_> = source.lines().collect();
    if lines.len() > MAX_LINES {
        return Err(AnalysisError::TooManyLines);
    }
    let token_count = source.split_whitespace().count();
    if token_count > MAX_TOKENS {
        return Err(AnalysisError::TooManyTokens);
    }
    let brace_language = !matches!(language, "python");
    let mut brace_depth = 0_usize;
    let mut functions = Vec::new();
    let mut active: Option<(String, usize, usize, usize, bool)> = None;
    for (index, raw_line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let line = strip_comment(raw_line, language);
        if brace_language {
            brace_depth = update_brace_depth(&line, brace_depth)?;
        }
        if let Some((name, start, start_depth, start_indent, exempt)) = active.as_ref() {
            let ended = if brace_language {
                brace_depth < *start_depth && line.contains('}')
            } else {
                !line.trim().is_empty()
                    && indentation(&line) <= *start_indent
                    && !matches!(line.trim_start().chars().next(), Some(')' | ']' | '}'))
                    && line_number > *start
            };
            if ended {
                functions.push(metric(
                    name,
                    *start,
                    line_number,
                    &lines[*start - 1..=index],
                    language,
                    *exempt,
                ));
                active = None;
            }
        }
        if active.is_none()
            && let Some((name, indent)) = function_header(&line, language)
        {
            let exempt = line_number > 1 && has_exemption_marker(lines[line_number - 2]);
            active = Some((name, line_number, brace_depth, indent, exempt));
        }
    }
    if let Some((name, start, _, _, exempt)) = active {
        functions.push(metric(
            &name,
            start,
            lines.len(),
            &lines[start - 1..],
            language,
            exempt,
        ));
    }
    if brace_language && brace_depth != 0 {
        return Err(AnalysisError::UnbalancedBraces);
    }
    Ok(Analysis {
        language: language.to_string(),
        file_lines: lines.len(),
        token_count,
        functions,
        types: type_metrics(language, &lines),
    })
}

fn type_metrics(language: &str, lines: &[&str]) -> Vec<TypeMetric> {
    let mut metrics = Vec::new();
    let brace_language = !matches!(language, "python");
    let mut depth = 0_usize;
    let mut active: Option<(String, usize, usize, usize)> = None;
    for (index, raw_line) in lines.iter().enumerate() {
        let line_number = index + 1;
        let line = strip_comment(raw_line, language);
        if brace_language {
            depth = update_brace_depth(&line, depth).unwrap_or(depth);
        }
        if let Some((name, start, start_depth, indent)) = active.as_ref() {
            let ended = if brace_language {
                depth < *start_depth && line.contains('}')
            } else {
                !line.trim().is_empty() && indentation(&line) <= *indent && line_number > *start
            };
            if ended {
                metrics.push(TypeMetric {
                    name: name.clone(),
                    start_line: *start,
                    end_line: line_number,
                    lines: line_number - *start + 1,
                });
                active = None;
            }
        }
        if active.is_none()
            && let Some((name, indent)) = type_header(&line, language)
        {
            active = Some((name, line_number, depth, indent));
        }
    }
    if let Some((name, start, _, _)) = active {
        metrics.push(TypeMetric {
            name,
            start_line: start,
            end_line: lines.len(),
            lines: lines.len() - start + 1,
        });
    }
    metrics
}

fn type_header(line: &str, language: &str) -> Option<(String, usize)> {
    let trimmed = line.trim_start();
    let indent = indentation(line);
    if language == "python" {
        let name = trimmed
            .strip_prefix("class ")?
            .split(['(', ':'])
            .next()?
            .trim();
        return (!name.is_empty()).then(|| (name.to_string(), indent));
    }
    if !trimmed.contains('{') {
        return None;
    }
    let marker = match language {
        "rust" => ["struct ", "enum ", "trait ", "impl "].as_slice(),
        "typescript" | "javascript" => ["class ", "interface ", "type "].as_slice(),
        "go" => ["type "].as_slice(),
        _ => return None,
    };
    marker.iter().find_map(|prefix| {
        let start = trimmed.find(prefix)? + prefix.len();
        let name = trimmed[start..]
            .split(['{', '=', '<', ' ', ';'])
            .next()?
            .trim();
        (!name.is_empty()).then(|| (name.to_string(), indent))
    })
}

fn function_header(line: &str, language: &str) -> Option<(String, usize)> {
    let trimmed = line.trim_start();
    let indent = indentation(line);
    if language == "python" {
        let name = trimmed
            .strip_prefix("async def ")
            .or_else(|| trimmed.strip_prefix("def "))?
            .split('(')
            .next()?
            .trim();
        return (!name.is_empty()).then(|| (name.to_string(), indent));
    }
    let marker = match language {
        "rust" => "fn ",
        "go" => "func ",
        _ => "function ",
    };
    let start = trimmed.find(marker)? + marker.len();
    let name = trimmed[start..].split(['(', '<', ' ']).next()?.trim();
    (!name.is_empty()).then(|| (name.to_string(), indent))
}

fn metric(
    name: &str,
    start: usize,
    end: usize,
    lines: &[&str],
    _language: &str,
    exempt: bool,
) -> FunctionMetric {
    let text = lines.join("\n");
    let parameters = text
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')').map(|(params, _)| params))
        .map(|params| {
            params
                .split(',')
                .filter(|param| !param.trim().is_empty())
                .count()
        })
        .unwrap_or(0);
    let complexity = ["if ", "for ", "while ", "match ", "&&", "||", "? "]
        .iter()
        .map(|needle| text.matches(needle).count())
        .sum::<usize>()
        + 1;
    let max_nesting = lines
        .iter()
        .map(|line| indentation(line) / 4)
        .max()
        .unwrap_or(0);
    FunctionMetric {
        name: name.to_string(),
        start_line: start,
        end_line: end.max(start),
        lines: end.max(start) - start + 1,
        parameters,
        complexity,
        max_nesting,
        exempt,
    }
}

fn has_exemption_marker(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("lgtm: exempt")
        && lower.contains("reason=")
        && lower.contains("owner=")
        && lower.contains("expires=")
        && lower.contains("delete=")
}

fn update_brace_depth(line: &str, depth: usize) -> Result<usize, AnalysisError> {
    let mut depth = depth;
    for character in line.chars() {
        match character {
            '{' => depth += 1,
            '}' if depth == 0 => return Err(AnalysisError::UnbalancedBraces),
            '}' => depth -= 1,
            _ => {}
        }
    }
    Ok(depth)
}

fn strip_comment(line: &str, language: &str) -> String {
    if language == "python" {
        line.split('#').next().unwrap_or_default().to_string()
    } else {
        line.split("//").next().unwrap_or_default().to_string()
    }
}

fn indentation(line: &str) -> usize {
    line.chars()
        .take_while(|character| character.is_whitespace())
        .count()
}

pub fn is_excluded_path(path: &Path) -> bool {
    path.components().any(|component| {
        component.as_os_str().to_str().is_some_and(|name| {
            matches!(
                name,
                "target" | "node_modules" | "vendor" | "dist" | "build"
            ) || name.ends_with(".generated")
        })
    }) || path.extension().and_then(|extension| extension.to_str()) == Some("min.js")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_rust_metrics_include_span_parameters_and_complexity() {
        let analysis = analyze_source(
            "rust",
            "fn answer(value: u32) {\n    if value > 0 {\n        println!(\"ok\");\n    }\n}\n",
        )
        .expect("analysis");
        assert_eq!(analysis.functions[0].name, "answer");
        assert_eq!(analysis.functions[0].parameters, 1);
        assert_eq!(analysis.functions[0].lines, 5);
        assert!(analysis.functions[0].complexity >= 2);
    }

    #[test]
    fn malformed_and_oversized_sources_are_not_passed() {
        assert!(matches!(
            analyze_source("rust", "fn broken() {"),
            Err(AnalysisError::UnbalancedBraces)
        ));
        assert!(matches!(
            analyze_source("rust", "fn broken() {}\n}"),
            Err(AnalysisError::UnbalancedBraces)
        ));
        assert!(matches!(
            analyze_source("python", &"x\n".repeat(MAX_LINES + 1)),
            Err(AnalysisError::TooManyLines)
        ));
    }

    #[test]
    fn bounded_typescript_and_go_functions_are_supported() {
        let typescript = analyze_source(
            "typescript",
            "function render(value: unknown) {\n  return value;\n}\n",
        )
        .expect("TypeScript analysis");
        assert_eq!(typescript.functions[0].name, "render");
        let go = analyze_source("go", "func Run(value string) {\n}\n").expect("Go analysis");
        assert_eq!(go.functions[0].name, "Run");
        let rust = analyze_source("rust", "struct Record {\n    value: u32,\n}\n")
            .expect("Rust type analysis");
        assert_eq!(rust.types[0].name, "Record");
        let javascript = analyze_source(
            "javascript",
            "function render(value) {\n  return value;\n}\n",
        )
        .expect("JavaScript analysis");
        assert_eq!(javascript.functions[0].name, "render");
        assert!(matches!(
            analyze_source("typescript", "function broken() {"),
            Err(AnalysisError::UnbalancedBraces)
        ));
        assert!(matches!(
            analyze_source("go", "func broken() {"),
            Err(AnalysisError::UnbalancedBraces)
        ));
        assert!(is_excluded_path(Path::new("target/generated.rs")));
    }

    #[test]
    fn every_supported_language_obeys_the_same_resource_bounds() {
        for language in ["python", "typescript", "javascript", "rust", "go"] {
            assert!(matches!(
                analyze_source(language, &"t ".repeat(MAX_TOKENS + 1)),
                Err(AnalysisError::TooManyTokens)
            ));
        }
    }
}
