use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[cfg(test)]
use std::cell::Cell;

#[derive(Clone, Copy)]
enum Quote {
    String { escaped: bool },
    RawString { hashes: usize },
}

#[derive(Default)]
struct LexState {
    block_comment_depth: usize,
    quote: Option<Quote>,
}

struct Token {
    kind: TokenKind,
    line: usize,
    column: usize,
}

enum TokenKind {
    Word(String),
    Punctuation(u8),
}

pub(super) struct PatchIndex {
    added_lines: BTreeMap<String, BTreeSet<usize>>,
    referenced_files: BTreeSet<String>,
    contains_cfg_test: bool,
}

#[cfg(test)]
thread_local! {
    static PATCH_PARSE_COUNT: Cell<usize> = const { Cell::new(0) };
}

impl PatchIndex {
    pub(super) fn from_patch(patch: &str) -> Self {
        #[cfg(test)]
        PATCH_PARSE_COUNT.with(|count| count.set(count.get() + 1));

        let mut index = Self {
            added_lines: BTreeMap::new(),
            referenced_files: BTreeSet::new(),
            contains_cfg_test: false,
        };
        let mut current_file = None;
        let mut hunk_start = None;
        let mut new_line = 0;
        for line in patch.lines() {
            index.contains_cfg_test |= line.contains("#[cfg(test)]");
            if line.starts_with("diff --git ") {
                current_file = None;
                hunk_start = None;
                if let Some((old_path, new_path)) = parse_diff_header(line) {
                    index.referenced_files.insert(old_path);
                    index.referenced_files.insert(new_path.clone());
                    current_file = Some(new_path);
                }
                continue;
            }
            let Some(file) = current_file.as_ref() else {
                continue;
            };
            if line.starts_with("@@ ") {
                hunk_start = parse_new_hunk_start(line);
                new_line = hunk_start.unwrap_or_default();
                continue;
            }
            let Some(_) = hunk_start else {
                continue;
            };
            if line.starts_with('+') && !line.starts_with("+++") {
                index
                    .added_lines
                    .entry(file.clone())
                    .or_default()
                    .insert(new_line);
                new_line += 1;
            } else if line.starts_with(' ') {
                new_line += 1;
            }
        }
        index
    }

    #[cfg(test)]
    pub(super) fn reset_parse_count() {
        PATCH_PARSE_COUNT.with(|count| count.set(0));
    }

    #[cfg(test)]
    pub(super) fn parse_count() -> usize {
        PATCH_PARSE_COUNT.with(Cell::get)
    }
}

pub(super) fn inline_test_hunk_touched(root: &Path, file: &str, patch: &PatchIndex) -> bool {
    let Some(source) = std::fs::read_to_string(root.join(file)).ok() else {
        return patch.contains_cfg_test;
    };
    let inline_lines = inline_test_lines(&source);
    if inline_lines.is_empty() {
        return false;
    }
    patch
        .added_lines
        .get(file)
        .is_some_and(|lines| lines.iter().any(|line| inline_lines.contains(line)))
        || !patch.referenced_files.contains(file)
}

fn parse_new_hunk_start(line: &str) -> Option<usize> {
    let range = line
        .split_whitespace()
        .find_map(|part| part.strip_prefix('+'))?;
    range
        .split_once(',')
        .map_or_else(|| range.parse().ok(), |(start, _)| start.parse().ok())
}

fn inline_test_lines(source: &str) -> BTreeSet<usize> {
    let code_lines = source
        .lines()
        .scan(LexState::default(), |state, line| {
            Some(sanitize_line(line, state))
        })
        .collect::<Vec<_>>();
    let tokens = tokenize(&code_lines);
    let mut inline_lines = BTreeSet::new();
    for (marker, line) in code_lines.iter().enumerate() {
        let Some(attribute_end) = cfg_test_attribute_end(line) else {
            continue;
        };
        let Some(first) = tokens.iter().position(|token| {
            token.line > marker || (token.line == marker && token.column >= attribute_end)
        }) else {
            continue;
        };
        let Some((open_line, open_column)) = parse_module_body(&tokens, first) else {
            continue;
        };
        let Some(end) = matching_brace(&code_lines, open_line, open_column) else {
            continue;
        };
        inline_lines.extend(marker + 1..=end + 1);
    }
    inline_lines
}

fn cfg_test_attribute_end(line: &[u8]) -> Option<usize> {
    const ATTRIBUTE: &[u8] = b"#[cfg(test)]";
    let start = line
        .windows(ATTRIBUTE.len())
        .position(|window| window == ATTRIBUTE)?;
    if line[..start].iter().any(|byte| !byte.is_ascii_whitespace()) {
        return None;
    }
    Some(start + ATTRIBUTE.len())
}

fn parse_module_body(tokens: &[Token], first: usize) -> Option<(usize, usize)> {
    let mut index = first;
    if is_word(&tokens[index], "pub") {
        index += 1;
        if tokens
            .get(index)
            .is_some_and(|token| matches!(token.kind, TokenKind::Punctuation(b'(')))
        {
            index += 1;
            while !is_punctuation(tokens.get(index)?, b')') {
                index += 1;
            }
            index += 1;
        }
    }
    if !is_word(tokens.get(index)?, "mod") {
        return None;
    }
    index += 1;
    if !matches!(tokens.get(index)?.kind, TokenKind::Word(_)) {
        return None;
    }
    index += 1;
    let token = tokens.get(index)?;
    if is_punctuation(token, b';') {
        return None;
    }
    is_punctuation(token, b'{').then_some((token.line, token.column))
}

fn matching_brace(lines: &[Vec<u8>], open_line: usize, open_column: usize) -> Option<usize> {
    let mut depth = 0_usize;
    for (line_index, line) in lines.iter().enumerate().skip(open_line) {
        let start = if line_index == open_line {
            open_column
        } else {
            0
        };
        for byte in line.iter().skip(start) {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        return Some(line_index);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

fn tokenize(lines: &[Vec<u8>]) -> Vec<Token> {
    let mut tokens = Vec::new();
    for (line, bytes) in lines.iter().enumerate() {
        let mut column = 0;
        while column < bytes.len() {
            if bytes[column].is_ascii_whitespace() {
                column += 1;
                continue;
            }
            if is_word_byte(bytes[column]) {
                let start = column;
                column += 1;
                while column < bytes.len() && is_word_byte(bytes[column]) {
                    column += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Word(String::from_utf8_lossy(&bytes[start..column]).into()),
                    line,
                    column: start,
                });
            } else {
                tokens.push(Token {
                    kind: TokenKind::Punctuation(bytes[column]),
                    line,
                    column,
                });
                column += 1;
            }
        }
    }
    tokens
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 128
}

fn is_word(token: &Token, expected: &str) -> bool {
    matches!(&token.kind, TokenKind::Word(word) if word == expected)
}

fn is_punctuation(token: &Token, expected: u8) -> bool {
    matches!(token.kind, TokenKind::Punctuation(punctuation) if punctuation == expected)
}

fn sanitize_line(line: &str, state: &mut LexState) -> Vec<u8> {
    let mut code = line.as_bytes().to_vec();
    let mut index = 0;
    while index < code.len() {
        if state.block_comment_depth > 0 {
            if code.get(index..index + 2) == Some(b"/*") {
                state.block_comment_depth += 1;
                blank(&mut code, index, 2);
                index += 2;
            } else if code.get(index..index + 2) == Some(b"*/") {
                state.block_comment_depth -= 1;
                blank(&mut code, index, 2);
                index += 2;
            } else {
                blank(&mut code, index, 1);
                index += 1;
            }
            continue;
        }
        if let Some(quote) = state.quote {
            match quote {
                Quote::String { escaped } => {
                    let byte = code[index];
                    blank(&mut code, index, 1);
                    if escaped {
                        state.quote = Some(Quote::String { escaped: false });
                    } else if byte == b'\\' {
                        state.quote = Some(Quote::String { escaped: true });
                    } else if byte == b'"' {
                        state.quote = None;
                    }
                    index += 1;
                }
                Quote::RawString { hashes } => {
                    if raw_string_end(&code, index, hashes) {
                        blank(&mut code, index, hashes + 1);
                        state.quote = None;
                        index += hashes + 1;
                    } else {
                        blank(&mut code, index, 1);
                        index += 1;
                    }
                }
            }
            continue;
        }
        if code.get(index..index + 2) == Some(b"//") {
            let remaining = code.len() - index;
            blank(&mut code, index, remaining);
            break;
        }
        if code.get(index..index + 2) == Some(b"/*") {
            state.block_comment_depth = 1;
            blank(&mut code, index, 2);
            index += 2;
            continue;
        }
        if let Some((length, hashes)) = raw_string_start(&code, index) {
            blank(&mut code, index, length);
            state.quote = Some(Quote::RawString { hashes });
            index += length;
            continue;
        }
        if code[index] == b'"' {
            state.quote = Some(Quote::String { escaped: false });
            blank(&mut code, index, 1);
            index += 1;
            continue;
        }
        if let Some(length) = char_literal_length(&code, index) {
            blank(&mut code, index, length);
            index += length;
            continue;
        }
        index += 1;
    }
    code
}

fn blank(code: &mut [u8], start: usize, length: usize) {
    let end = start.saturating_add(length).min(code.len());
    code[start..end].fill(b' ');
}

fn raw_string_start(code: &[u8], index: usize) -> Option<(usize, usize)> {
    if index > 0 && is_word_byte(code[index - 1]) {
        return None;
    }
    let prefix = if code.get(index) == Some(&b'r') {
        1
    } else if code.get(index..index + 2) == Some(b"br") {
        2
    } else {
        return None;
    };
    let mut cursor = index + prefix;
    let mut hashes = 0;
    while code.get(cursor) == Some(&b'#') {
        hashes += 1;
        cursor += 1;
    }
    (code.get(cursor) == Some(&b'"')).then_some((cursor + 1 - index, hashes))
}

fn raw_string_end(code: &[u8], index: usize, hashes: usize) -> bool {
    if code.get(index) != Some(&b'"') {
        return false;
    }
    code.get(index + 1..index + 1 + hashes)
        .is_some_and(|suffix| suffix.iter().all(|byte| *byte == b'#'))
}

fn char_literal_length(code: &[u8], index: usize) -> Option<usize> {
    if code.get(index) != Some(&b'\'') {
        return None;
    }
    let mut cursor = index + 1;
    if code.get(cursor) == Some(&b'\\') {
        cursor += 2;
    } else {
        cursor += 1;
    }
    (code.get(cursor) == Some(&b'\'')).then_some(cursor + 1 - index)
}

fn parse_diff_header(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("diff --git ")?;
    let (old_path, rest) = parse_header_path(rest)?;
    let (new_path, rest) = parse_header_path(rest.trim_start())?;
    if !rest.trim().is_empty() {
        return None;
    }
    Some((
        old_path.strip_prefix("a/")?.to_string(),
        new_path.strip_prefix("b/")?.to_string(),
    ))
}

fn parse_header_path(input: &str) -> Option<(String, &str)> {
    if input.starts_with('"') {
        let (path, consumed) = parse_quoted_path(input)?;
        Some((path, &input[consumed..]))
    } else {
        let end = input.find(char::is_whitespace).unwrap_or(input.len());
        (!input[..end].is_empty()).then_some((input[..end].to_string(), &input[end..]))
    }
}

fn parse_quoted_path(input: &str) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    let mut index = 1;
    let mut decoded = Vec::new();
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Some((String::from_utf8(decoded).ok()?, index + 1)),
            b'\\' => {
                index += 1;
                let byte = match bytes.get(index)? {
                    b'a' => 7,
                    b'b' => 8,
                    b'f' => 12,
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'v' => 11,
                    b'\\' | b'"' => bytes[index],
                    b'0'..=b'7' => {
                        let mut value = 0;
                        let mut count = 0;
                        while count < 3 {
                            let Some(digit) = bytes.get(index + count) else {
                                break;
                            };
                            if !(b'0'..=b'7').contains(digit) {
                                break;
                            }
                            value = value * 8 + usize::from(*digit - b'0');
                            count += 1;
                        }
                        index += count - 1;
                        u8::try_from(value).ok()?
                    }
                    _ => return None,
                };
                decoded.push(byte);
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    None
}
