//! `generate-api-doc` — the extraction layer behind `docs/api/api-doc.json`
//! and `docs/api/openapi.json`.
//!
//! Design contract (no invented facts — every field is read from code or is
//! explicitly `null`):
//!
//! * Routes come from the SAME `.route("path", get(handler))` registrations
//!   (and the same production source inventory) as `generate-endpoints-doc`, extended
//!   to keep the handler ident per method. The route count is asserted equal
//!   to `generate_endpoints_doc`'s count so the two documents cannot drift.
//! * Permission tiers and auth exemption are NOT re-derived here: the real
//!   `ryuki-api` binary is invoked as `target/debug/ryuki-api
//!   --dump-route-meta` (build it first with `cargo build -p ryuki-api`).
//!   That hidden flag reads `[{"path","method"}]` from stdin and answers with
//!   `{"meta":[{"path","method","tier","auth_exempt"}],"openapi":{...}}` by
//!   calling the same functions the auth middleware uses. The `openapi` half
//!   of the envelope is the curated `openapi_document()` and is written
//!   verbatim to `docs/api/openapi.json`.
//! * Handler descriptions are the handler's own `///` doc comment. Summaries
//!   use its first sentence, with a deterministic method/path/handler fallback
//!   so every operation remains navigable even when source docs are absent.
//! * `query_params` / `request_body` come from the `Query<T>` / `Json<T>`
//!   extractors in the handler signature; `T`'s field list is parsed from its
//!   `struct` definition (name honours `#[serde(rename)]` / `rename_all`,
//!   `optional` = `Option<...>` or `#[serde(default)]`). Unfindable or
//!   non-struct types degrade to `null` fields, never guesses.
//! * `response_notes` uses only unambiguous body/signature evidence:
//!   `total_count_headers(` (bare array + required X-Total-Count),
//!   `request_list_headers(` (conditional count/cursor headers),
//!   `add_page_meta(` or inline `"total"/"limit"/"offset"` keys (paginated object), and a
//!   `ProblemDetails`/`Json<ApiError>` error arm (the platform ApiError shape:
//!   error, message, and optional detail).
//! * Area keys reuse `endpoints_doc_section` verbatim; per-area descriptions
//!   are a curated, evidence-based table (route inventory, handler docs,
//!   `docs/*.md` guides). Areas without evidence get the plain
//!   "Routes for <Title>." placeholder.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use serde::Serialize;
use syn::visit::Visit as _;

pub(crate) const API_DOC_JSON_PATH: &str = "docs/api/api-doc.json";
pub(crate) const OPENAPI_JSON_PATH: &str = "docs/api/openapi.json";
const RYUKI_API_DUMP_BIN: &str = "target/debug/ryuki-api";

// ───────────────────────── route extraction ─────────────────────────

/// One `.route("path", ...)` registration: the path plus each detected
/// method and (when it is a plain fn ident) its handler.
pub(crate) struct RouteRegistration {
    pub(crate) path: String,
    pub(crate) methods: Vec<MethodHandler>,
}

pub(crate) struct MethodHandler {
    pub(crate) method: String,
    pub(crate) handler: Option<String>,
}

/// Extracts (path, method, handler) triples from active
/// `.route("path", get(handler))` registrations, including chained
/// registrations like `get(a).post(b)`. This is the single route parser:
/// `extract_route_methods` (used by `generate-endpoints-doc`) delegates here
/// and drops the handler idents, so both documents see the same route set.
pub(crate) fn extract_route_registrations(source: &str) -> Vec<RouteRegistration> {
    let source = crate::strip_source_comments(source);
    let mut results = Vec::new();
    for candidate in source.split(".route(").skip(1) {
        let rest = candidate.trim_start();
        let Some(route) = rest.strip_prefix('"') else {
            continue;
        };
        let Some(end) = route.find('"') else {
            continue;
        };
        let path = route[..end].to_string();
        let arguments = crate::route_call_arguments(&route[end + 1..]);
        let methods = route_method_handlers(&arguments);
        results.push(RouteRegistration { path, methods });
    }
    results
}

fn route_method_handlers(arguments: &str) -> Vec<MethodHandler> {
    let mut methods: Vec<MethodHandler> = Vec::new();
    for (token, method) in crate::ROUTE_METHOD_TOKENS {
        for (index, _) in arguments.match_indices(token) {
            let boundary_ok = arguments[..index]
                .chars()
                .next_back()
                .is_none_or(|ch| !ch.is_ascii_alphanumeric() && ch != '_');
            if boundary_ok && !methods.iter().any(|entry| entry.method == *method) {
                let handler = handler_ident(&arguments[index + token.len()..]);
                methods.push(MethodHandler {
                    method: (*method).to_string(),
                    handler,
                });
            }
        }
    }
    if methods.is_empty() {
        methods.push(MethodHandler {
            method: "ANY".to_string(),
            handler: None,
        });
    }
    methods
}

/// The expression inside `get(...)`, kept only when it is a plain (possibly
/// module-qualified) fn ident. Closures or wrapped expressions yield `None`
/// rather than a fabricated name.
fn handler_ident(after_token: &str) -> Option<String> {
    let inner = crate::route_call_arguments(after_token);
    let trimmed = inner.trim();
    let plain = !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == ':');
    if plain {
        Some(trimmed.to_string())
    } else {
        None
    }
}

// ───────────────────────── source scanning ─────────────────────────

#[derive(Clone, Default)]
pub(crate) struct HandlerInfo {
    file: String,
    doc: Option<String>,
    /// Raw parameter-list text (`None` when the fn is generic or bodyless).
    params: Option<String>,
    /// Raw return-type text between `)` and the body `{`.
    returns: String,
    /// Comment-stripped handler body. Kept for conservative response facts.
    body: Option<String>,
    body_flags: BodyFlags,
}

#[derive(Clone, Copy, Default)]
struct BodyFlags {
    total_count_headers: bool,
    request_list_headers: bool,
    paginated_object: bool,
}

pub(crate) struct StructInfo {
    file: String,
    /// `None` for tuple/unit structs (field shapes we do not document).
    fields: Option<Vec<ApiField>>,
}

/// Everything the doc assembler needs from the Rust sources: fn name ->
/// definitions and struct name -> definitions (multiple files may define the
/// same name; resolution prefers the closest file).
#[derive(Default)]
pub(crate) struct SourceScan {
    handlers: BTreeMap<String, Vec<HandlerInfo>>,
    structs: BTreeMap<String, Vec<StructInfo>>,
}

/// Byte offsets of every line start, so line-oriented decl detection can hand
/// absolute positions to the delimiter-matching walker.
fn line_offsets(source: &str) -> Vec<usize> {
    let mut offsets = vec![0usize];
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            offsets.push(index + 1);
        }
    }
    offsets
}

/// Walks `source` from `start` skipping comments (line, nested block), string
/// literals (normal and raw), and char literals, returning the index of the
/// first occurrence of any char in `targets` at code level.
fn find_code_char(source: &[char], start: usize, targets: &[char]) -> Option<usize> {
    let mut i = start;
    while i < source.len() {
        match skip_noise(source, i) {
            Some(next) if next > i => {
                i = next;
                continue;
            }
            _ => {}
        }
        if targets.contains(&source[i]) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Finds a function signature terminator at delimiter depth zero. Unlike
/// `find_code_char`, this deliberately ignores semicolons inside array types
/// such as `[(HeaderName, &'static str); 1]`.
fn find_signature_terminator(source: &[char], start: usize) -> Option<usize> {
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut i = start;
    while i < source.len() {
        match skip_noise(source, i) {
            Some(next) if next > i => {
                i = next;
                continue;
            }
            _ => {}
        }
        let at_top = paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 && brace_depth == 0;
        if at_top && matches!(source[i], '{' | ';') {
            return Some(i);
        }
        match source[i] {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '<' => angle_depth += 1,
            '>' if angle_depth > 0 => angle_depth -= 1,
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    None
}

/// Finds the matching `close` for the `open` delimiter at `open_idx`
/// (`source[open_idx]` must be `open`), honouring comments and literals.
fn matching_delimiter(source: &[char], open_idx: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = open_idx;
    while i < source.len() {
        match skip_noise(source, i) {
            Some(next) if next > i => {
                i = next;
                continue;
            }
            _ => {}
        }
        if source[i] == open {
            depth += 1;
        } else if source[i] == close {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// If `i` sits at the start of a comment, string/raw-string, or char literal,
/// returns the index just past it; otherwise `None`. Keeps the structural
/// walkers honest inside bodies that embed JSON strings and `r#"..."#`.
fn skip_noise(source: &[char], i: usize) -> Option<usize> {
    let c = *source.get(i)?;
    // line + nested block comments
    if c == '/' {
        match source.get(i + 1) {
            Some('/') => {
                let mut j = i + 2;
                while j < source.len() && source[j] != '\n' {
                    j += 1;
                }
                return Some(j);
            }
            Some('*') => {
                let mut depth = 1usize;
                let mut j = i + 2;
                while j < source.len() && depth > 0 {
                    if source[j] == '/' && source.get(j + 1) == Some(&'*') {
                        depth += 1;
                        j += 2;
                    } else if source[j] == '*' && source.get(j + 1) == Some(&'/') {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                return Some(j);
            }
            _ => return None,
        }
    }
    // raw strings: r"..."  r#"..."#  (optionally b-prefixed), only when the
    // `r` is not the tail of an identifier.
    if (c == 'r' || c == 'b') && (i == 0 || !is_ident_char(source[i - 1])) {
        let mut j = i;
        if source[j] == 'b' {
            j += 1;
        }
        if source.get(j) == Some(&'r') {
            j += 1;
            let mut hashes = 0usize;
            while source.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if source.get(j) == Some(&'"') {
                j += 1;
                loop {
                    match source.get(j) {
                        None => return Some(j),
                        Some('"') => {
                            let mut k = j + 1;
                            let mut seen = 0usize;
                            while seen < hashes && source.get(k) == Some(&'#') {
                                seen += 1;
                                k += 1;
                            }
                            if seen == hashes {
                                return Some(k);
                            }
                            j += 1;
                        }
                        Some(_) => j += 1,
                    }
                }
            }
        }
        return None;
    }
    // normal strings
    if c == '"' {
        let mut j = i + 1;
        while j < source.len() {
            match source[j] {
                '\\' => j += 2,
                '"' => return Some(j + 1),
                _ => j += 1,
            }
        }
        return Some(j);
    }
    // char literal vs lifetime: 'x' or '\n' is a literal, 'static is not.
    if c == '\'' {
        return match (source.get(i + 1), source.get(i + 2)) {
            (Some('\\'), _) => {
                // skip the escaped char (which may itself be a quote), then
                // scan to the closing quote
                let mut j = i + 3;
                while j < source.len() && source[j] != '\'' {
                    j += 1;
                }
                Some(j + 1)
            }
            (Some(_), Some('\'')) => Some(i + 3),
            _ => None, // lifetime
        };
    }
    None
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

const DECL_PREFIX_TOKENS: &[&str] = &["pub", "async", "const", "unsafe", "extern"];

fn prefix_tokens_allowed(prefix: &str) -> bool {
    prefix.split_whitespace().all(|token| {
        DECL_PREFIX_TOKENS.contains(&token)
            || token.starts_with("pub(")
            || (token.starts_with('"') && token.ends_with('"'))
    })
}

/// `(name, byte offset just past the name within `line`)` when `line` is a
/// fn/struct declaration for `keyword` ("fn" or "struct").
fn decl_name(line: &str, keyword: &str) -> Option<(String, usize)> {
    let needle = format!("{keyword} ");
    let pos = line.find(&needle)?;
    if !prefix_tokens_allowed(&line[..pos]) {
        return None;
    }
    let after = &line[pos + needle.len()..];
    let rel = after.find(|c: char| !c.is_whitespace())?;
    let name: String = after[rel..]
        .chars()
        .take_while(|c| is_ident_char(*c))
        .collect();
    if name.is_empty() || name.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((name.clone(), pos + needle.len() + rel + name.len()))
}

fn doc_line(trimmed: &str) -> Option<String> {
    let rest = trimmed.strip_prefix("///")?;
    Some(rest.strip_prefix(' ').unwrap_or(rest).to_string())
}

/// Scans one source file, appending fn and struct definitions to the index.
pub(crate) fn scan_file(source: &str, rel_path: &str, scan: &mut SourceScan) {
    let chars: Vec<char> = source.chars().collect();
    // char-index offsets: build from the char stream so multi-byte text in
    // doc comments cannot desync byte- vs char-based positions.
    let mut offsets = vec![0usize];
    for (index, ch) in chars.iter().enumerate() {
        if *ch == '\n' {
            offsets.push(index + 1);
        }
    }
    let lines: Vec<&str> = source.lines().collect();

    let mut docs: Vec<String> = Vec::new();
    let mut attrs: Vec<String> = Vec::new();
    let mut k = 0usize;
    while k < lines.len() {
        let trimmed = lines[k].trim_start();
        if let Some(doc) = doc_line(trimmed) {
            docs.push(doc);
            k += 1;
            continue;
        }
        if trimmed.starts_with("//") || trimmed.is_empty() {
            k += 1;
            continue;
        }
        if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
            // accumulate a (possibly multi-line) attribute until brackets balance
            let mut attr = String::new();
            let mut balance = 0isize;
            while k < lines.len() {
                let line = lines[k];
                balance += line.chars().filter(|c| *c == '[').count() as isize;
                balance -= line.chars().filter(|c| *c == ']').count() as isize;
                attr.push_str(line.trim());
                attr.push(' ');
                k += 1;
                if balance <= 0 {
                    break;
                }
            }
            attrs.push(attr);
            continue;
        }
        if let Some((name, name_end)) = decl_name(lines[k], "fn") {
            let doc = join_docs(&docs);
            docs.clear();
            attrs.clear();
            let after_name = offsets[k] + char_len(&lines[k][..name_end]);
            let end = record_fn(&chars, after_name, rel_path, name, doc, scan);
            k = advance_to_line_after(&offsets, k, end);
            continue;
        }
        if let Some((name, name_end)) = decl_name(lines[k], "struct") {
            let rename_all = attrs.iter().find_map(|attr| attr_value(attr, "rename_all"));
            docs.clear();
            attrs.clear();
            let after_name = offsets[k] + char_len(&lines[k][..name_end]);
            let end = record_struct(&chars, after_name, rel_path, name, rename_all, scan);
            k = advance_to_line_after(&offsets, k, end);
            continue;
        }
        docs.clear();
        attrs.clear();
        k += 1;
    }
}

fn char_len(text: &str) -> usize {
    text.chars().count()
}

fn advance_to_line_after(offsets: &[usize], mut k: usize, end: usize) -> usize {
    while k + 1 < offsets.len() && offsets[k + 1] <= end {
        k += 1;
    }
    k + 1
}

fn join_docs(docs: &[String]) -> Option<String> {
    if docs.is_empty() {
        return None;
    }
    let joined = docs.join("\n").trim().to_string();
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// Records one fn starting just past its name; returns the char index where
/// scanning may resume (end of body, or of the signature for bodyless fns).
fn record_fn(
    chars: &[char],
    after_name: usize,
    rel_path: &str,
    name: String,
    doc: Option<String>,
    scan: &mut SourceScan,
) -> usize {
    let mut info = HandlerInfo {
        file: rel_path.to_string(),
        doc,
        ..HandlerInfo::default()
    };
    // Generic fns are never axum handlers: skip straight to the body without
    // attempting to parse `<...>` bounds (which may contain `->`/parens).
    let generic = find_code_char(chars, after_name, &['<', '(', '{', ';'])
        .is_some_and(|idx| chars[idx] == '<');
    let mut cursor = after_name;
    if !generic {
        if let Some(open) = find_code_char(chars, after_name, &['(', '{', ';']) {
            if chars[open] == '(' {
                if let Some(close) = matching_delimiter(chars, open, '(', ')') {
                    info.params = Some(chars[open + 1..close].iter().collect());
                    cursor = close + 1;
                }
            }
        }
    }
    let end = match find_signature_terminator(chars, cursor) {
        Some(idx) if chars[idx] == '{' => {
            if !generic {
                info.returns = chars[cursor..idx].iter().collect();
            }
            let close = matching_delimiter(chars, idx, '{', '}').unwrap_or(chars.len() - 1);
            let body: String = chars[idx + 1..close].iter().collect();
            let body = crate::strip_source_comments(&body);
            info.body_flags = BodyFlags {
                total_count_headers: body.contains("total_count_headers("),
                request_list_headers: body.contains("request_list_headers("),
                paginated_object: body.contains("add_page_meta(")
                    || (body.contains("\"total\":")
                        && body.contains("\"limit\":")
                        && body.contains("\"offset\":")),
            };
            info.body = Some(body);
            close
        }
        Some(idx) => idx,
        None => chars.len() - 1,
    };
    scan.handlers.entry(name).or_default().push(info);
    end
}

/// Records one struct; returns the char index where scanning may resume.
fn record_struct(
    chars: &[char],
    after_name: usize,
    rel_path: &str,
    name: String,
    rename_all: Option<String>,
    scan: &mut SourceScan,
) -> usize {
    let Some(open) = find_code_char(chars, after_name, &['{', '(', ';']) else {
        return chars.len() - 1;
    };
    let (fields, end) = if chars[open] == '{' {
        let close = matching_delimiter(chars, open, '{', '}').unwrap_or(chars.len() - 1);
        let body: String = chars[open + 1..close].iter().collect();
        (
            Some(parse_struct_fields(&body, rename_all.as_deref())),
            close,
        )
    } else if chars[open] == '(' {
        // tuple struct: field shapes are not documented
        let close = matching_delimiter(chars, open, '(', ')').unwrap_or(chars.len() - 1);
        (None, close)
    } else {
        (None, open) // unit struct
    };
    scan.structs.entry(name).or_default().push(StructInfo {
        file: rel_path.to_string(),
        fields,
    });
    end
}

/// Extracts `key = "value"` out of an attribute line (used for
/// `#[serde(rename = "...")]` and `#[serde(rename_all = "...")]`).
fn attr_value(attr: &str, key: &str) -> Option<String> {
    if !attr.contains("serde") {
        return None;
    }
    let pos = attr.find(key)?;
    let rest = &attr[pos + key.len()..];
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn serde_word(attr: &str, word: &str) -> bool {
    if !attr.contains("serde") {
        return false;
    }
    attr.match_indices(word).any(|(idx, _)| {
        let before_ok = attr[..idx]
            .chars()
            .next_back()
            .is_none_or(|c| !is_ident_char(c));
        let after_ok = attr[idx + word.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_ident_char(c));
        before_ok && after_ok
    })
}

/// Splits a struct body into top-level comma-separated field chunks and
/// parses each into the documented field shape.
fn parse_struct_fields(body: &str, rename_all: Option<&str>) -> Vec<ApiField> {
    let mut fields = Vec::new();
    for chunk in split_top_level(body) {
        let mut docs: Vec<String> = Vec::new();
        let mut attrs: Vec<String> = Vec::new();
        let mut decl = String::new();
        for line in chunk.lines() {
            let trimmed = line.trim();
            if let Some(doc) = doc_line(trimmed) {
                docs.push(doc);
            } else if trimmed.starts_with("#[") {
                attrs.push(trimmed.to_string());
            } else {
                // strip trailing line comments; field decls never contain "//"
                let code = trimmed.split("//").next().unwrap_or("").trim();
                if !code.is_empty() {
                    decl.push_str(code);
                    decl.push(' ');
                }
            }
        }
        let decl = decl.trim();
        let Some(colon) = field_colon(decl) else {
            continue;
        };
        if attrs
            .iter()
            .any(|attr| serde_word(attr, "skip") || serde_word(attr, "skip_deserializing"))
        {
            continue;
        }
        let raw_name = decl[..colon]
            .split_whitespace()
            .last()
            .unwrap_or("")
            .trim_start_matches("r#")
            .to_string();
        if raw_name.is_empty() {
            continue;
        }
        let ty = normalize_type(&decl[colon + 1..]);
        let rename = attrs.iter().find_map(|attr| attr_value(attr, "rename"));
        let has_default = attrs.iter().any(|attr| serde_word(attr, "default"));
        let (ty, is_option) = strip_option(&ty);
        let name = rename.unwrap_or_else(|| match rename_all {
            Some(rule) => apply_rename_all(rule, &raw_name),
            None => raw_name,
        });
        fields.push(ApiField {
            name,
            type_: ty,
            optional: is_option || has_default,
            doc: join_docs(&docs),
        });
    }
    fields
}

/// The `name: Type` separator — the first `:` that is not part of `::`.
fn field_colon(decl: &str) -> Option<usize> {
    let bytes = decl.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b':' {
            if bytes.get(i + 1) == Some(&b':') {
                i += 2;
                continue;
            }
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Splits struct-body text at top-level commas, honouring `<>`/`()`/`[]`
/// nesting and string literals (inside attribute values). Comment text —
/// `//` remarks and `///` field docs — is copied verbatim but its characters
/// are never counted as delimiters (prose like "keys -> values" or an
/// unbalanced parenthesis would otherwise desync the depth).
fn split_top_level(body: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut depth = 0isize;
    let mut in_string = false;
    let mut escaped = false;
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_string {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            current.push(ch);
            for comment_char in chars.by_ref() {
                current.push(comment_char);
                if comment_char == '\n' {
                    break;
                }
            }
            continue;
        }
        match ch {
            '"' => {
                in_string = true;
                current.push(ch);
            }
            '<' | '(' | '[' => {
                depth += 1;
                current.push(ch);
            }
            '>' | ')' | ']' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                chunks.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        chunks.push(current);
    }
    chunks
}

fn normalize_type(raw: &str) -> String {
    raw.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("< ", "<")
        .replace(" >", ">")
        .replace(" ,", ",")
}

/// Strips ONE outer `Option<...>` layer; the boolean reports whether it was
/// present (Option-ness is emitted separately as `optional`).
fn strip_option(ty: &str) -> (String, bool) {
    match ty
        .strip_prefix("Option<")
        .and_then(|rest| rest.strip_suffix('>'))
    {
        Some(inner) => (inner.trim().to_string(), true),
        None => (ty.to_string(), false),
    }
}

fn apply_rename_all(rule: &str, name: &str) -> String {
    match rule {
        "camelCase" => snake_to_camel(name, false),
        "PascalCase" => snake_to_camel(name, true),
        "kebab-case" => name.replace('_', "-"),
        "SCREAMING_SNAKE_CASE" => name.to_uppercase(),
        "SCREAMING-KEBAB-CASE" => name.replace('_', "-").to_uppercase(),
        "lowercase" => name.to_lowercase(),
        "UPPERCASE" => name.to_uppercase(),
        _ => name.to_string(), // snake_case and unknown rules: keep as written
    }
}

fn snake_to_camel(name: &str, capitalize_first: bool) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper_next = capitalize_first;
    for ch in name.chars() {
        if ch == '_' {
            upper_next = true;
        } else if upper_next {
            out.extend(ch.to_uppercase());
            upper_next = false;
        } else {
            out.push(ch);
        }
    }
    out
}

// ───────────────────────── doc-comment helpers ─────────────────────────

/// First sentence of a doc comment: up to the first `.` that ends a word,
/// where the next non-space char does not start a lowercase continuation
/// (so "e.g. lowered" or "vs. the" do not split early). Falls back to the
/// whole (flattened) text when no sentence boundary exists.
pub(crate) fn first_sentence(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = flat.chars().collect();
    for (index, ch) in chars.iter().enumerate() {
        if *ch != '.' {
            continue;
        }
        match chars.get(index + 1) {
            None => return flat,
            Some(next) if next.is_whitespace() => {
                let continues_lowercase = chars
                    .iter()
                    .skip(index + 2)
                    .find(|c| !c.is_whitespace())
                    .is_some_and(|c| c.is_lowercase());
                if !continues_lowercase {
                    return chars[..=index].iter().collect();
                }
            }
            Some(_) => {}
        }
    }
    flat
}

// ───────────────────────── extractor detection ─────────────────────────

/// The generic argument of the first boundary-clean `Wrapper<...>` occurrence
/// in a parameter list (e.g. `Query<AdminListPage>` -> `AdminListPage`).
fn extractor_type(params: &str, wrapper: &str) -> Option<String> {
    let token = format!("{wrapper}<");
    for (index, _) in params.match_indices(&token) {
        // reject `RawQuery<` (ident tail) but accept `extract::Query<`
        let boundary_ok = params[..index]
            .chars()
            .next_back()
            .is_none_or(|c| !is_ident_char(c));
        if !boundary_ok {
            continue;
        }
        let rest = &params[index + token.len()..];
        let mut depth = 1isize;
        let mut inner = String::new();
        for ch in rest.chars() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(normalize_type(&inner));
                    }
                }
                _ => {}
            }
            inner.push(ch);
        }
    }
    None
}

/// A type token that can name a findable struct: a plain ident, optionally
/// module-qualified. Returns the final segment for index lookup.
fn plain_struct_name(ty: &str) -> Option<&str> {
    let plain = !ty.is_empty() && ty.chars().all(|ch| is_ident_char(ch) || ch == ':');
    if plain {
        ty.rsplit("::").next()
    } else {
        None
    }
}

// ───────────────────────── output document shape ─────────────────────────
// Field order below is the committed contract for docs/api/api-doc.json.

#[derive(Serialize)]
struct ApiDocument {
    generated_by: &'static str,
    route_count: usize,
    areas: Vec<ApiArea>,
}

#[derive(Serialize)]
struct ApiArea {
    key: String,
    title: String,
    description: String,
    routes: Vec<ApiRoute>,
}

#[derive(Serialize)]
struct ApiRoute {
    method: String,
    path: String,
    tier: Option<String>,
    auth_exempt: bool,
    handler: Option<String>,
    summary: String,
    description: Option<String>,
    path_params: Vec<ApiField>,
    query_params_state: QueryParamsState,
    query_params: Option<Vec<ApiField>>,
    request_headers: Vec<ApiHeader>,
    request_body_state: RequestBodyState,
    request_body: Option<ApiRequestBody>,
    success_responses: Vec<ApiResponse>,
    response_notes: Option<String>,
}

#[derive(Clone, Serialize)]
pub(crate) struct ApiField {
    name: String,
    #[serde(rename = "type")]
    type_: String,
    optional: bool,
    doc: Option<String>,
}

#[derive(Serialize)]
struct ApiRequestBody {
    #[serde(rename = "struct")]
    struct_name: String,
    fields: Option<Vec<ApiField>>,
}

#[derive(Clone, Serialize)]
struct ApiHeader {
    name: String,
    #[serde(rename = "type")]
    type_: String,
    required: bool,
    description: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum RequestBodyState {
    Json,
    None,
    Unknown,
    Raw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum QueryParamsState {
    Known,
    None,
    Unknown,
}

#[derive(Serialize)]
struct ApiResponse {
    status: u16,
    description: String,
    body_state: ResponseBodyState,
    body: Option<ApiResponseBody>,
    headers: Vec<ApiHeader>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum ResponseBodyState {
    Json,
    None,
    Unknown,
    Raw,
}

#[derive(Clone, Serialize)]
struct ApiResponseBody {
    #[serde(rename = "type")]
    type_: String,
    fields: Option<Vec<ApiField>>,
}

// ───────────────────────── area metadata ─────────────────────────

/// Acronyms that stay uppercase when a key is humanized into a title.
const TITLE_ACRONYMS: &[&str] = &["cmdb", "vm", "api", "dns", "ipam", "oob", "ad"];

pub(crate) fn area_title(key: &str) -> String {
    key.split(['-', '_'])
        .filter(|word| !word.is_empty())
        .map(|word| {
            if TITLE_ACRONYMS.contains(&word) {
                word.to_uppercase()
            } else {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                    None => String::new(),
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Curated, evidence-based area descriptions. Sources: the area's route
/// inventory in docs/api/endpoints.md, the owning handlers' doc comments,
/// and the docs/*.md guides (rbac-and-scoping, notifications, orchestration,
/// site-management). Keys absent here fall back to "Routes for <Title>.".
const AREA_DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "activity",
        "The global activity audit feed: who-did-what-when records across the platform. \
         Reads require the audit tier.",
    ),
    (
        "admin",
        "Platform administration: API token and session management, approval groups, \
         delegation boundaries, feature-flag governance, and notification dispatch-outbox \
         introspection. Both reads and mutations under /api/admin require the admin tier.",
    ),
    (
        "analytics",
        "AIOps suggestion lifecycle (generate, review, accept, implement, reject) and \
         cost/capacity analytics readouts.",
    ),
    (
        "approvals",
        "Cross-domain approval worklist: the pending-approvals queue and the approval \
         decision-readiness contract.",
    ),
    (
        "audit",
        "Compliance controls and findings with assessment actions, plus audit-log \
         hash-chain verification.",
    ),
    (
        "auth",
        "Session authentication for the portal and API: local and Entra ID/OIDC sign-in \
         and sign-out flows, plus pre-login status, session, and role reads. The sign-in \
         endpoints and pre-login reads are deliberately auth-exempt.",
    ),
    (
        "boundary",
        "Reports the platform's execution-boundary status: whether HTTP requests, provider \
         calls, live execution, raw payloads, secret values, and customer identifiers are \
         allowed in the current execution mode.",
    ),
    (
        "build",
        "Application-environment build lifecycle: plan, approve, deploy, list, and retire \
         application environments, plus the related build contracts.",
    ),
    (
        "catalog",
        "The service-catalog read surface: offering categories and definitions, approval \
         routes, the access-control model, and evidence manifests.",
    ),
    (
        "cmdb",
        "Configuration-management database surface: CI reads and export, impact analysis, \
         reconciliation, relationship graph, file exchange, and ServiceNow integration.",
    ),
    (
        "dashboard",
        "Contract endpoints for the portal's global-overview and risk-heatmap dashboards.",
    ),
    (
        "datacenter",
        "Datacenter readiness and capacity checks (power, cooling, rack space, switch \
         ports), plus firmware, hardware, out-of-band, storage, network, and image-factory \
         surfaces with per-site readiness reporting.",
    ),
    (
        "events",
        "The platform domain-event feed and alert surface: list events and alerts, and \
         acknowledge alerts singly or in batch.",
    ),
    (
        "evidence",
        "Evidence-pack operations: collect, export, redact, and verify compliance evidence.",
    ),
    (
        "identity",
        "Identity governance: access-review campaigns, reviewer verdicts and \
         recertification, AD computer lifecycle, gMSA lifecycle, file-share/NTFS \
         recertification, and RBAC approval-model contracts.",
    ),
    ("images", "Contract endpoint for the golden-image factory."),
    (
        "integrations",
        "External-provider integration management: connection CRUD, health history, \
         credential expiry, circuit breakers, vendor capabilities, adapter readiness and \
         contract tests, plus signed inbound webhooks.",
    ),
    (
        "inventory",
        "Inventory coverage and hygiene: coverage summaries, OS baseline compliance, \
         ownership-risk reads, and reconciliation.",
    ),
    (
        "maintain",
        "Maintenance operations: OS baseline checks and remediation, patch approval and \
         waves, certificate lifecycle, and approved-software deployment.",
    ),
    (
        "me",
        "Self-service endpoints for the signed-in user's own scope preferences; writes are \
         keyed on the verified session identity.",
    ),
    (
        "metering",
        "Usage metering and chargeback: usage reads, chargeback reports, and chargeback \
         rate management.",
    ),
    (
        "metrics",
        "Metrics budgets (create, update, delete, status) and commitment/consumption \
         readouts.",
    ),
    (
        "monitoring",
        "Monitoring configuration: alert-route management, alert reads, noise review, and \
         Zabbix drift contracts.",
    ),
    (
        "network",
        "Network services: DNS record management, IPAM, firewall rule sets, and \
         load-balancer surfaces.",
    ),
    (
        "notifications",
        "In-app notifications for the signed-in user: list, unread count, and read \
         receipts (single and read-all). Notifications are emitted only by server-side \
         domain logic; recipients mark their own items read.",
    ),
    (
        "observe",
        "Observability operations: log-forwarding coverage and gaps, noise suppression, \
         synthetic health dashboards, and the monitoring review queue.",
    ),
    (
        "operations",
        "Operational review contracts and readiness reviews across domains, plus the \
         outage-communications notice lifecycle (create, send, acknowledge, cancel, \
         complete).",
    ),
    (
        "ops",
        "Operational execution: incident and emergency-change lifecycle, runbook approvals \
         and execution, and the operator shift queue with handover. Emergency routes are \
         admin-tier; the shift queue is operator working data.",
    ),
    (
        "patching",
        "Contract endpoints for patching: maintenance calendar, policy import, and reboot \
         orchestration.",
    ),
    (
        "platform",
        "Platform status and bootstrap surface: the liveness/readiness/metrics probes \
         registered outside /api, plus platform summary, uptime, degradation drills, and \
         database-readiness reads. The summary read is auth-exempt so the login view can \
         bootstrap before a session exists.",
    ),
    (
        "protect",
        "Data protection: backup coverage and gap analysis, DR assignment and plans, \
         restore approvals, and secrets management including rotation.",
    ),
    (
        "requests",
        "The governed request lifecycle: create and track requests, validate, plan, \
         approve or reject, execute, verify, cancel, and batch equivalents, with \
         per-request audit trails, approval ledgers, and evidence packs.",
    ),
    (
        "retire",
        "Decommissioning lifecycle: plan, approve, and execute decommissions, with \
         quarantine management.",
    ),
    (
        "software",
        "Contract endpoint for approved-software deployment.",
    ),
    (
        "validation",
        "Runs a named validation slice (via the `slice` query parameter) and returns the \
         validation result; the static dry-run performs no live validation.",
    ),
    (
        "vm",
        "VM day-2 change operations: validate, plan, execute, and verify.",
    ),
    (
        "workflows",
        "Workflow contract reads: per-workflow deployment/dry-run contracts and preflight \
         decision surfaces.",
    ),
];

fn area_description(key: &str) -> String {
    AREA_DESCRIPTIONS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, text)| (*text).to_string())
        .unwrap_or_else(|| format!("Routes for {}.", area_title(key)))
}

// ───────────────────────── dump-binary bridge ─────────────────────────

#[derive(serde::Deserialize)]
struct DumpEnvelope {
    meta: Vec<DumpMetaEntry>,
    openapi: serde_json::Value,
}

#[derive(serde::Deserialize)]
struct DumpMetaEntry {
    path: String,
    method: String,
    tier: Option<String>,
    auth_exempt: bool,
}

/// Invokes `target/debug/ryuki-api --dump-route-meta` with the extracted
/// route keys on stdin. The binary must be built beforehand — permission
/// tiers come from the REAL runtime functions, never a re-implementation.
fn run_route_meta_dump(root: &Path, routes_json: &str) -> Result<DumpEnvelope, String> {
    let binary = root.join(RYUKI_API_DUMP_BIN);
    if !binary.is_file() {
        return Err(format!(
            "{} not found — run `cargo build -p ryuki-api` first; generate-api-doc \
             asks the real binary (--dump-route-meta) for per-route permission \
             tiers so the generated doc cannot drift from enforcement",
            binary.display()
        ));
    }
    let mut child = Command::new(&binary)
        .arg("--dump-route-meta")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to spawn {}: {error}", binary.display()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(routes_json.as_bytes())
            .map_err(|error| format!("failed to write route keys to --dump-route-meta: {error}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("failed to wait for --dump-route-meta: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "--dump-route-meta failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("--dump-route-meta returned invalid JSON: {error}"))
}

// ───────────────────────── assembly ─────────────────────────

struct RouteSeed {
    handler: Option<String>,
    source_file: &'static str,
}

/// Builds api-doc.json + openapi.json under `root` and returns the summary
/// printed by the subcommand.
pub(crate) fn generate_api_doc(root: &Path) -> Result<serde_json::Value, String> {
    // 1. Routes (same sources, same parser core as generate-endpoints-doc).
    let mut routes: BTreeMap<String, BTreeMap<String, RouteSeed>> = BTreeMap::new();
    for source_path in crate::RUST_API_ROUTE_SOURCES {
        let source = crate::read(root, source_path)?;
        for registration in extract_route_registrations(&source) {
            let by_method = routes.entry(registration.path).or_default();
            for entry in registration.methods {
                by_method.entry(entry.method).or_insert(RouteSeed {
                    handler: entry.handler,
                    source_file: source_path,
                });
            }
        }
    }
    let route_count: usize = routes.values().map(BTreeMap::len).sum();

    // 2. Smoke gate: the two generated documents must agree on the surface.
    let (_, endpoints_count) = crate::generate_endpoints_doc(root)?;
    if route_count != endpoints_count {
        return Err(format!(
            "generate-api-doc extracted {route_count} routes but \
             generate-endpoints-doc reports {endpoints_count}; the parsers diverged"
        ));
    }

    // 3. Runtime truth: tiers + auth exemption + the curated OpenAPI document.
    let route_keys: Vec<serde_json::Value> = routes
        .iter()
        .flat_map(|(path, methods)| {
            methods
                .keys()
                .map(move |method| serde_json::json!({"path": path, "method": method}))
        })
        .collect();
    let routes_json = serde_json::to_string(&route_keys)
        .map_err(|error| format!("failed to serialize route keys: {error}"))?;
    let envelope = run_route_meta_dump(root, &routes_json)?;
    let mut meta: BTreeMap<(String, String), (Option<String>, bool)> = BTreeMap::new();
    for entry in envelope.meta {
        meta.insert((entry.path, entry.method), (entry.tier, entry.auth_exempt));
    }

    // 4. Handler + struct indexes from the API sources.
    let scan = scan_repository(root)?;

    // 5. Assemble areas.
    let mut sections: BTreeMap<String, Vec<ApiRoute>> = BTreeMap::new();
    for (path, methods) in &routes {
        for (method, seed) in methods {
            let (tier, auth_exempt) = meta
                .get(&(path.clone(), method.clone()))
                .cloned()
                .ok_or_else(|| {
                    format!("--dump-route-meta returned no entry for {method} {path}")
                })?;
            let route = build_route(path, method, seed, tier, auth_exempt, &scan);
            sections
                .entry(crate::endpoints_doc_section(path))
                .or_default()
                .push(route);
        }
    }
    let areas: Vec<ApiArea> = sections
        .into_iter()
        .map(|(key, routes)| ApiArea {
            title: area_title(&key),
            description: area_description(&key),
            key,
            routes,
        })
        .collect();

    let document = ApiDocument {
        generated_by: "ryuki-validator generate-api-doc",
        route_count,
        areas,
    };

    // 6. Write both documents.
    let api_doc_json = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("failed to serialize api-doc: {error}"))?;
    let openapi_json = serde_json::to_string_pretty(&envelope.openapi)
        .map_err(|error| format!("failed to serialize openapi: {error}"))?;
    write_doc(root, API_DOC_JSON_PATH, &api_doc_json)?;
    write_doc(root, OPENAPI_JSON_PATH, &openapi_json)?;

    Ok(serde_json::json!({
        "routes": route_count,
        "written": [API_DOC_JSON_PATH, OPENAPI_JSON_PATH],
    }))
}

fn write_doc(root: &Path, rel_path: &str, contents: &str) -> Result<(), String> {
    let output_path = root.join(rel_path);
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    fs::write(&output_path, format!("{contents}\n"))
        .map_err(|error| format!("failed to write {}: {error}", output_path.display()))
}

/// Scans every .rs file in the API crate for handlers, and the API + shared
/// crates for struct definitions (request/query types may live in
/// ryuki-core/ryuki-engine/ryuki-protocol).
fn scan_repository(root: &Path) -> Result<SourceScan, String> {
    let mut scan = SourceScan::default();
    for crate_root in [
        "sources/ryuki-api/src",
        "sources/ryuki-core/src",
        "sources/ryuki-engine/src",
        "sources/ryuki-protocol/src",
    ] {
        let mut files = Vec::new();
        collect_rs_files(root, crate_root, &mut files)?;
        for rel_path in files {
            let source = crate::read(root, &rel_path)?;
            scan_file(&source, &rel_path, &mut scan);
        }
    }
    Ok(scan)
}

fn collect_rs_files(root: &Path, rel_dir: &str, out: &mut Vec<String>) -> Result<(), String> {
    let dir = root.join(rel_dir);
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .map_err(|error| format!("failed to read {}: {error}", dir.display()))?
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel_path = format!("{rel_dir}/{name}");
        let file_type = entry
            .file_type()
            .map_err(|error| format!("failed to stat {rel_path}: {error}"))?;
        if file_type.is_dir() {
            collect_rs_files(root, &rel_path, out)?;
        } else if name.ends_with(".rs") {
            out.push(rel_path);
        }
    }
    Ok(())
}

fn build_route(
    path: &str,
    method: &str,
    seed: &RouteSeed,
    tier: Option<String>,
    auth_exempt: bool,
    scan: &SourceScan,
) -> ApiRoute {
    let handler_info = seed
        .handler
        .as_deref()
        .and_then(|token| resolve_handler(scan, token, seed.source_file));
    let doc = handler_info.and_then(|info| info.doc.clone());
    let query_params =
        handler_info.and_then(|info| query_params_for(seed.handler.as_deref(), info, scan));
    let query_params_state = query_params_state_for(handler_info, query_params.as_deref());
    let request_body = handler_info.and_then(|info| request_body_for(info, scan));
    let request_body_state = request_body_state_for(handler_info);
    let path_params = path_params_for(path, handler_info, scan);
    let request_headers = request_headers_for(
        method,
        path,
        tier.as_deref(),
        auth_exempt,
        handler_info,
        request_body_state,
    );
    let mut success_responses = handler_info
        .map(|info| success_responses_for(info, scan))
        .unwrap_or_default();
    if success_responses.is_empty() {
        success_responses = success_response_override(seed.handler.as_deref());
    }
    let response_notes = handler_info.and_then(response_notes_for);
    let summary = doc
        .as_deref()
        .map(first_sentence)
        .unwrap_or_else(|| fallback_summary(method, path, seed.handler.as_deref()));
    ApiRoute {
        method: method.to_string(),
        path: path.to_string(),
        tier,
        auth_exempt,
        handler: seed.handler.clone(),
        summary,
        description: doc,
        path_params,
        query_params_state,
        query_params,
        request_headers,
        request_body_state,
        request_body,
        success_responses,
        response_notes,
    }
}

fn resolve_handler<'a>(
    scan: &'a SourceScan,
    token: &str,
    route_file: &str,
) -> Option<&'a HandlerInfo> {
    let mut segments: Vec<&str> = token.split("::").collect();
    let name = segments.pop()?;
    let candidates = scan.handlers.get(name)?;
    let module = segments
        .iter()
        .rev()
        .find(|segment| **segment != "crate" && !segment.is_empty());
    if let Some(module) = module {
        let file_name = format!("/{module}.rs");
        if let Some(found) = candidates
            .iter()
            .find(|info| info.file.ends_with(&file_name))
        {
            return Some(found);
        }
    }
    candidates
        .iter()
        .find(|info| info.file == route_file)
        .or_else(|| candidates.first())
}

fn resolve_struct<'a>(
    scan: &'a SourceScan,
    ty: &str,
    handler_file: &str,
) -> Option<&'a StructInfo> {
    let name = plain_struct_name(ty)?;
    let candidates = scan.structs.get(name)?;
    candidates
        .iter()
        .find(|info| info.file == handler_file)
        .or_else(|| {
            candidates
                .iter()
                .find(|info| info.file == crate::RUST_API_CONTRACTS_PATH)
        })
        .or_else(|| {
            candidates
                .iter()
                .find(|info| info.file.starts_with("sources/ryuki-api/"))
        })
        .or_else(|| candidates.first())
}

fn path_parameter_names(path: &str) -> Vec<String> {
    path.split('/')
        .filter_map(|segment| {
            segment
                .strip_prefix('{')
                .and_then(|value| value.strip_suffix('}'))
                .map(|value| value.trim_start_matches('*').to_string())
        })
        .collect()
}

fn unknown_path_params(names: &[String]) -> Vec<ApiField> {
    names
        .iter()
        .map(|name| ApiField {
            name: name.clone(),
            type_: "unknown".to_string(),
            optional: false,
            doc: None,
        })
        .collect()
}

fn tuple_type_items(ty: &str) -> Option<Vec<String>> {
    let inner = ty.strip_prefix('(')?.strip_suffix(')')?;
    let items: Vec<String> = split_top_level(inner)
        .into_iter()
        .map(|item| normalize_type(item.trim()))
        .filter(|item| !item.is_empty())
        .collect();
    Some(items)
}

/// Resolves route-template placeholders against the handler's `Path<T>`
/// extractor. Tuple items are positional; struct fields are matched by their
/// serialized names. Unknown types stay explicitly `unknown` rather than being
/// guessed from a placeholder name.
fn path_params_for(path: &str, info: Option<&HandlerInfo>, scan: &SourceScan) -> Vec<ApiField> {
    let names = path_parameter_names(path);
    if names.is_empty() {
        return Vec::new();
    }
    let Some(params) = info.and_then(|info| info.params.as_deref()) else {
        return unknown_path_params(&names);
    };
    let Some(ty) = extractor_type(params, "Path") else {
        return unknown_path_params(&names);
    };

    if let Some(items) = tuple_type_items(&ty) {
        if items.len() != names.len() {
            return unknown_path_params(&names);
        }
        return names
            .into_iter()
            .zip(items)
            .map(|(name, ty)| {
                let (type_, _) = strip_option(&ty);
                ApiField {
                    name,
                    type_,
                    optional: false,
                    doc: None,
                }
            })
            .collect();
    }

    if let Some(found) = info.and_then(|handler| resolve_struct(scan, &ty, &handler.file)) {
        if let Some(fields) = &found.fields {
            let by_name: BTreeMap<&str, &ApiField> = fields
                .iter()
                .map(|field| (field.name.as_str(), field))
                .collect();
            if names.iter().all(|name| by_name.contains_key(name.as_str())) {
                return names
                    .into_iter()
                    .map(|name| {
                        let mut field = by_name[&name.as_str()].clone();
                        field.name = name;
                        // A route-template segment is present on every match,
                        // even if a reusable struct field happened to be Option.
                        field.optional = false;
                        field
                    })
                    .collect();
            }
            if names.len() == 1 && fields.len() == 1 {
                let mut field = fields[0].clone();
                field.name = names[0].clone();
                field.optional = false;
                return vec![field];
            }
            return unknown_path_params(&names);
        }
    }

    if names.len() == 1 {
        let (type_, _) = strip_option(&ty);
        return vec![ApiField {
            name: names[0].clone(),
            type_,
            optional: false,
            doc: None,
        }];
    }
    unknown_path_params(&names)
}

fn direct_param_type_matches(params: &str, expected: &str) -> bool {
    split_top_level(params).into_iter().any(|parameter| {
        let Some(colon) = field_colon(&parameter) else {
            return false;
        };
        let ty = normalize_type(&parameter[colon + 1..]);
        ty == expected || ty.rsplit("::").next() == Some(expected)
    })
}

fn request_body_state_for(info: Option<&HandlerInfo>) -> RequestBodyState {
    let Some(params) = info.and_then(|info| info.params.as_deref()) else {
        return RequestBodyState::Unknown;
    };
    if extractor_type(params, "Json").is_some() {
        return RequestBodyState::Json;
    }
    if direct_param_type_matches(params, "Bytes") {
        return RequestBodyState::Raw;
    }
    if extractor_type(params, "Form").is_some()
        || direct_param_type_matches(params, "Multipart")
        || direct_param_type_matches(params, "Body")
        || direct_param_type_matches(params, "String")
    {
        return RequestBodyState::Unknown;
    }
    RequestBodyState::None
}

fn is_mutation_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

fn api_header(name: &str, type_: &str, required: bool, description: &str) -> ApiHeader {
    ApiHeader {
        name: name.to_string(),
        type_: type_.to_string(),
        required,
        description: description.to_string(),
    }
}

fn request_headers_for(
    method: &str,
    path: &str,
    tier: Option<&str>,
    auth_exempt: bool,
    info: Option<&HandlerInfo>,
    body_state: RequestBodyState,
) -> Vec<ApiHeader> {
    let mut headers = Vec::new();
    let interactive_token_mint = method == "POST" && path == "/api/admin/tokens";
    match tier {
        Some("agent") => headers.push(api_header(
            "Authorization",
            "string",
            true,
            "Required agent credential: `Bearer rya_...`; this route bypasses human-session authentication and validates the agent token in the handler.",
        )),
        Some("webhook") => headers.extend([
            api_header(
                "X-Hub-Signature-256",
                "string",
                true,
                "Required HMAC-SHA256 signature (64 hexadecimal characters, optionally prefixed with `sha256=`) over the Ryuki v1 canonical message: fixed POST path, connection id, timestamp, delivery id, and exact-body SHA-256 digest; no human or agent credential is accepted.",
            ),
            api_header(
                "X-Ryuki-Webhook-Timestamp",
                "integer",
                true,
                "Canonical Unix timestamp in seconds. It is covered by the v1 signature and must be within the receiver's five-minute clock-skew window.",
            ),
            api_header(
                "X-Ryuki-Webhook-Delivery-Id",
                "string",
                true,
                "Unique 1-128 byte `[A-Za-z0-9._-]` delivery identifier covered by the v1 signature and atomically deduplicated per connection.",
            ),
        ]),
        Some("public") => {}
        _ if !auth_exempt => {
            headers.push(api_header(
                "Authorization",
                "string",
                false,
                if interactive_token_mint {
                    "Interactive administrator credential alternative. Service API tokens (`ryk_...`, whose provider mode is `api-token`) are explicitly rejected for token minting; use an interactive `rys_...` session token or `X-Ryuki-Session-Id`."
                } else {
                    "Human credential alternative: supply one `Bearer rys_...` session token, `ryk_...` API token, or validated identity-provider JWT here. Do not combine it with `X-Ryuki-Session-Id` or the session cookie; conflicting carriers fail closed."
                },
            ));
            headers.push(api_header(
                "X-Ryuki-Session-Id",
                "string",
                false,
                if interactive_token_mint {
                    "Interactive administrator session token. Despite this compatibility header name, the value is an opaque `rys_...` bearer, never the administrative session UUID. Service API tokens cannot call this operation."
                } else {
                    "Opaque `rys_...` session-token carrier used by the portal for mutations. Administrative session UUIDs cannot authenticate. Supply exactly one credential carrier per request."
                },
            ));
        }
        _ => {}
    }

    if matches!(body_state, RequestBodyState::Json) {
        headers.push(api_header(
            "Content-Type",
            "string",
            true,
            "Required by the resolved Axum `Json<T>` request extractor; send `application/json`.",
        ));
    }
    let callback_cookie = match path {
        "/api/auth/oidc/callback" => Some(("__Host-oidc_login_csrf", "oidc_login_csrf")),
        "/api/auth/entra/callback" => Some(("__Host-entra_login_csrf", "entra_login_csrf")),
        _ => None,
    };
    if let Some((cookie, loopback_cookie)) = callback_cookie {
        headers.push(api_header(
            "Cookie",
            "string",
            false,
            &format!(
                "Required on the successful `code` + `state` callback path: the browser must return the HttpOnly `{cookie}` binding cookie set by login initiation. The provider-error redirect path does not require it. Explicit loopback HTTP uses the compatibility name `{loopback_cookie}`."
            ),
        ));
    }
    if info
        .and_then(|handler| handler.params.as_deref())
        .is_some_and(|params| direct_param_type_matches(params, "ProtocolVersion"))
    {
        headers.push(api_header(
            "x-ryuki-protocol-version",
            "integer",
            true,
            "Required CP↔agent wire-schema version. The extractor rejects absent, duplicate, malformed, or unsupported values.",
        ));
    }

    let human_mutation =
        is_mutation_method(method) && !auth_exempt && !matches!(tier, Some("agent" | "webhook"));
    let idempotency_required = method == "POST" && path == "/api/ops/emergency/initiate";
    if human_mutation && (idempotency_required || !info.is_some_and(handler_marks_no_store)) {
        let required = idempotency_required;
        let description = if required {
            "Required for emergency initiation; retries with the same key receive the stored at-most-once outcome, while reuse with a different request is rejected."
        } else {
            "Optional at-most-once retry key for human mutations. When omitted, the idempotency middleware passes the request through without deduplication."
        };
        headers.push(api_header(
            "Idempotency-Key",
            "string",
            required,
            description,
        ));
    }
    headers
}

fn fallback_summary(method: &str, path: &str, handler: Option<&str>) -> String {
    match handler.and_then(|token| token.rsplit("::").next()) {
        Some(name) => {
            const TRAILING_VERBS: &[&str] = &[
                "acknowledge",
                "approve",
                "cancel",
                "close",
                "complete",
                "create",
                "delete",
                "disable",
                "enable",
                "execute",
                "export",
                "fail",
                "get",
                "implement",
                "initiate",
                "list",
                "lock",
                "plan",
                "publish",
                "read",
                "reject",
                "reset",
                "retire",
                "revoke",
                "run",
                "send",
                "set",
                "start",
                "stop",
                "test",
                "update",
                "validate",
                "verify",
            ];
            let mut words: Vec<&str> = name.split('_').filter(|word| !word.is_empty()).collect();
            if words.len() > 1
                && words
                    .last()
                    .is_some_and(|word| TRAILING_VERBS.contains(word))
            {
                let verb = words.pop().expect("non-empty words");
                words.insert(0, verb);
            }
            let mut phrase = words.join(" ");
            if let Some(first) = phrase.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            format!("{phrase}.")
        }
        None => format!("{method} {path}."),
    }
}

fn body_visibly_returns_json(body: &str) -> bool {
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0usize;
    while i + 3 < chars.len() {
        match skip_noise(&chars, i) {
            Some(next) if next > i => {
                i = next;
                continue;
            }
            _ => {}
        }
        if chars[i..i + 4] == ['J', 's', 'o', 'n'] {
            let before_ok = i == 0 || !is_ident_char(chars[i - 1]);
            let mut after = i + 4;
            while chars.get(after).is_some_and(|ch| ch.is_whitespace()) {
                after += 1;
            }
            if before_ok && chars.get(after) == Some(&'(') {
                return true;
            }
            i += 4;
        } else {
            i += 1;
        }
    }
    false
}

fn declared_return_type(info: &HandlerInfo) -> Option<String> {
    let raw = info.returns.trim().strip_prefix("->")?.trim();
    if raw.is_empty() {
        return None;
    }
    let normalized = normalize_type(raw);
    Some(
        normalized
            .split_once(" where ")
            .map_or(normalized.as_str(), |(return_type, _)| return_type)
            .trim()
            .to_string(),
    )
}

fn outer_generic_arguments(ty: &str) -> Option<(&str, Vec<String>)> {
    let open = ty.find('<')?;
    if !ty.ends_with('>') {
        return None;
    }
    let outer = ty[..open].trim();
    let args = split_top_level(&ty[open + 1..ty.len() - 1])
        .into_iter()
        .map(|arg| normalize_type(arg.trim()))
        .filter(|arg| !arg.is_empty())
        .collect();
    Some((outer, args))
}

/// Returns only the declared SUCCESS side of a result-shaped return type.
/// Looking for `Json<T>` in the full signature is unsafe because the error arm
/// commonly contains `Json<ApiError>` even when success is a redirect or empty.
fn declared_success_type(info: &HandlerInfo) -> Option<String> {
    let return_type = declared_return_type(info)?;
    let Some((outer, args)) = outer_generic_arguments(&return_type) else {
        return Some(return_type);
    };
    let outer_name = outer.rsplit("::").next().unwrap_or(outer);
    if matches!(outer_name, "Result" | "ApiResult" | "WebhookResult") {
        return args.into_iter().next();
    }
    Some(return_type)
}

fn type_contains_token(ty: &str, token: &str) -> bool {
    ty.match_indices(token).any(|(index, _)| {
        let before_ok = ty[..index]
            .chars()
            .next_back()
            .is_none_or(|ch| !is_ident_char(ch));
        let after_ok = ty[index + token.len()..]
            .chars()
            .next()
            .is_none_or(|ch| !is_ident_char(ch));
        before_ok && after_ok
    })
}

fn ok_expression_contains_json(body: &str) -> bool {
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0usize;
    while i + 1 < chars.len() {
        match skip_noise(&chars, i) {
            Some(next) if next > i => {
                i = next;
                continue;
            }
            _ => {}
        }
        if chars[i] != 'O' || chars[i + 1] != 'k' {
            i += 1;
            continue;
        }
        let before_ok = i == 0 || !is_ident_char(chars[i - 1]);
        let after_ident_ok = chars.get(i + 2).is_none_or(|ch| !is_ident_char(*ch));
        if !before_ok || !after_ident_ok {
            i += 2;
            continue;
        }
        let mut open = i + 2;
        while chars.get(open).is_some_and(|ch| ch.is_whitespace()) {
            open += 1;
        }
        if chars.get(open) != Some(&'(') {
            i += 2;
            continue;
        }
        if let Some(close) = matching_delimiter(&chars, open, '(', ')') {
            let inner: String = chars[open + 1..close].iter().collect();
            if body_visibly_returns_json(&inner) {
                return true;
            }
            i = close + 1;
        } else {
            break;
        }
    }
    false
}

/// The trailing top-level expression, if one is readily identifiable. Closing
/// a top-level block starts a new candidate; an expression whose whole shape is
/// a `match`/`if` block therefore degrades to unknown instead of being guessed.
fn trailing_top_level_expression(body: &str) -> String {
    let chars: Vec<char> = body.chars().collect();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        match skip_noise(&chars, i) {
            Some(next) if next > i => {
                i = next;
                continue;
            }
            _ => {}
        }
        match chars[i] {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => {
                brace_depth = brace_depth.saturating_sub(1);
                if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                    start = i + 1;
                }
            }
            ';' if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    chars[start..].iter().collect::<String>().trim().to_string()
}

fn body_visibly_returns_success_json(body: &str) -> bool {
    if ok_expression_contains_json(body) {
        return true;
    }
    let trailing = trailing_top_level_expression(body);
    trailing.trim_start().starts_with("Json") && body_visibly_returns_json(&trailing)
}

fn expr_constructs_json(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Call(call) => {
            syn_expr_path(&call.func).is_some_and(|path| syn_path_last_is(path, "Json"))
        }
        syn::Expr::Paren(paren) => expr_constructs_json(&paren.expr),
        syn::Expr::Group(group) => expr_constructs_json(&group.expr),
        syn::Expr::Block(block) => block.block.stmts.last().is_some_and(
            |stmt| matches!(stmt, syn::Stmt::Expr(expr, None) if expr_constructs_json(expr)),
        ),
        _ => false,
    }
}

fn expr_maps_success_to_json(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(method) if method.method == "map" => {
            method.args.first().is_some_and(|mapper| match mapper {
                syn::Expr::Path(path) => syn_path_last_is(&path.path, "Json"),
                syn::Expr::Closure(closure) => expr_constructs_json(&closure.body),
                _ => false,
            })
        }
        syn::Expr::MethodCall(method) => expr_maps_success_to_json(&method.receiver),
        syn::Expr::Await(await_expr) => expr_maps_success_to_json(&await_expr.base),
        syn::Expr::Paren(paren) => expr_maps_success_to_json(&paren.expr),
        syn::Expr::Group(group) => expr_maps_success_to_json(&group.expr),
        _ => false,
    }
}

fn handler_tail_maps_success_to_json(info: &HandlerInfo) -> bool {
    let Some(body) = info.body.as_deref() else {
        return false;
    };
    let Ok(block) = syn::parse_str::<syn::Block>(&format!("{{{body}}}")) else {
        return false;
    };
    block.stmts.last().is_some_and(
        |stmt| matches!(stmt, syn::Stmt::Expr(expr, None) if expr_maps_success_to_json(expr)),
    )
}

enum JsonMacroShape {
    Object(Vec<ApiField>),
    NonObject,
    Unsupported,
}

enum ResponseExitShape {
    Error,
    NoBody { safe_alongside_json: bool },
    NonObject,
    Object(Vec<ApiField>),
    Unknown,
}

fn syn_path_last_is(path: &syn::Path, expected: &str) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| segment.ident == expected)
}

fn syn_expr_path(expr: &syn::Expr) -> Option<&syn::Path> {
    match expr {
        syn::Expr::Path(path) => Some(&path.path),
        _ => None,
    }
}

fn split_json_entries(tokens: TokenStream) -> Vec<Vec<TokenTree>> {
    let tokens: Vec<TokenTree> = tokens.into_iter().collect();
    let mut entries = Vec::new();
    let mut current = Vec::new();
    let mut angle_depth = 0usize;
    for (index, token) in tokens.iter().cloned().enumerate() {
        match &token {
            TokenTree::Punct(punct)
                if punct.as_char() == '<'
                    && (angle_depth > 0
                        || (index >= 2
                            && matches!(&tokens[index - 1], TokenTree::Punct(p) if p.as_char() == ':')
                            && matches!(&tokens[index - 2], TokenTree::Punct(p) if p.as_char() == ':'))) =>
            {
                angle_depth += 1;
                current.push(token);
            }
            TokenTree::Punct(punct) if punct.as_char() == '>' && angle_depth > 0 => {
                angle_depth -= 1;
                current.push(token);
            }
            TokenTree::Punct(punct) if punct.as_char() == ',' && angle_depth == 0 => {
                if !current.is_empty() {
                    entries.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(token),
        }
    }
    if !current.is_empty() {
        entries.push(current);
    }
    entries
}

fn has_unpaired_colon(tokens: &[TokenTree]) -> bool {
    tokens.iter().enumerate().any(|(index, token)| {
        if !matches!(token, TokenTree::Punct(punct) if punct.as_char() == ':') {
            return false;
        }
        let before = index.checked_sub(1).and_then(|i| tokens.get(i));
        let after = tokens.get(index + 1);
        !matches!(before, Some(TokenTree::Punct(punct)) if punct.as_char() == ':')
            && !matches!(after, Some(TokenTree::Punct(punct)) if punct.as_char() == ':')
    })
}

fn json_key(tokens: &[TokenTree]) -> Option<String> {
    if tokens.len() != 1 {
        return None;
    }
    match &tokens[0] {
        TokenTree::Ident(ident) => Some(ident.to_string()),
        TokenTree::Literal(literal) => syn::parse_str::<syn::LitStr>(&literal.to_string())
            .ok()
            .map(|value| value.value()),
        _ => None,
    }
}

fn json_value_type(tokens: &[TokenTree]) -> String {
    if tokens.len() == 1 {
        match &tokens[0] {
            TokenTree::Group(group) if group.delimiter() == Delimiter::Brace => {
                return "Value".to_string();
            }
            TokenTree::Group(group) if group.delimiter() == Delimiter::Bracket => {
                return "Vec<Value>".to_string();
            }
            TokenTree::Ident(ident) if ident == "true" || ident == "false" => {
                return "bool".to_string();
            }
            TokenTree::Ident(ident) if ident == "null" => return "null".to_string(),
            TokenTree::Literal(literal) => {
                if let Ok(value) = syn::parse_str::<syn::Lit>(&literal.to_string()) {
                    return match value {
                        syn::Lit::Str(_) | syn::Lit::Char(_) => "String",
                        syn::Lit::Bool(_) => "bool",
                        syn::Lit::Int(_) => "i64",
                        syn::Lit::Float(_) => "f64",
                        _ => "Value",
                    }
                    .to_string();
                }
            }
            _ => {}
        }
    }
    if tokens.len() >= 3 {
        let bang = tokens.get(tokens.len() - 2);
        let group = tokens.last();
        if matches!(bang, Some(TokenTree::Punct(punct)) if punct.as_char() == '!') {
            if let Some(TokenTree::Group(group)) = group {
                return match group.delimiter() {
                    Delimiter::Brace => "Value",
                    Delimiter::Bracket => "Vec<Value>",
                    _ => "Value",
                }
                .to_string();
            }
        }
    }
    "Value".to_string()
}

fn parse_json_object(tokens: TokenStream) -> Option<Vec<ApiField>> {
    let mut fields = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for entry in split_json_entries(tokens) {
        let colon = entry
            .iter()
            .position(|token| matches!(token, TokenTree::Punct(punct) if punct.as_char() == ':'))?;
        let name = json_key(&entry[..colon])?;
        let value = &entry[colon + 1..];
        if !seen.insert(name.clone()) || value.is_empty() || has_unpaired_colon(value) {
            return None;
        }
        fields.push(ApiField {
            name,
            type_: json_value_type(value),
            optional: false,
            doc: None,
        });
    }
    Some(fields)
}

fn json_macro_shape(mac: &syn::Macro) -> JsonMacroShape {
    if !syn_path_last_is(&mac.path, "json") {
        return JsonMacroShape::Unsupported;
    }
    let tokens: Vec<TokenTree> = mac.tokens.clone().into_iter().collect();
    let object_tokens = match &mac.delimiter {
        syn::MacroDelimiter::Brace(_) => Some(mac.tokens.clone()),
        _ if tokens.len() == 1 => match &tokens[0] {
            TokenTree::Group(group) if group.delimiter() == Delimiter::Brace => {
                Some(group.stream())
            }
            TokenTree::Group(_) => return JsonMacroShape::NonObject,
            _ => return JsonMacroShape::NonObject,
        },
        _ => return JsonMacroShape::NonObject,
    };
    match object_tokens.and_then(parse_json_object) {
        Some(fields) => JsonMacroShape::Object(fields),
        None => JsonMacroShape::Unsupported,
    }
}

fn status_code_name(expr: &syn::Expr) -> Option<String> {
    if let syn::Expr::Paren(paren) = expr {
        return status_code_name(&paren.expr);
    }
    if let syn::Expr::Group(group) = expr {
        return status_code_name(&group.expr);
    }
    let path = syn_expr_path(expr)?;
    let mut segments = path.segments.iter().rev();
    let name = segments.next()?.ident.to_string();
    if segments.any(|segment| segment.ident == "StatusCode") {
        Some(name)
    } else {
        None
    }
}

fn is_error_status_name(name: &str) -> bool {
    matches!(
        name,
        "BAD_REQUEST"
            | "UNAUTHORIZED"
            | "PAYMENT_REQUIRED"
            | "FORBIDDEN"
            | "NOT_FOUND"
            | "METHOD_NOT_ALLOWED"
            | "NOT_ACCEPTABLE"
            | "PROXY_AUTHENTICATION_REQUIRED"
            | "REQUEST_TIMEOUT"
            | "CONFLICT"
            | "GONE"
            | "LENGTH_REQUIRED"
            | "PRECONDITION_FAILED"
            | "PAYLOAD_TOO_LARGE"
            | "URI_TOO_LONG"
            | "UNSUPPORTED_MEDIA_TYPE"
            | "RANGE_NOT_SATISFIABLE"
            | "EXPECTATION_FAILED"
            | "IM_A_TEAPOT"
            | "MISDIRECTED_REQUEST"
            | "UNPROCESSABLE_ENTITY"
            | "LOCKED"
            | "FAILED_DEPENDENCY"
            | "TOO_EARLY"
            | "UPGRADE_REQUIRED"
            | "PRECONDITION_REQUIRED"
            | "TOO_MANY_REQUESTS"
            | "REQUEST_HEADER_FIELDS_TOO_LARGE"
            | "UNAVAILABLE_FOR_LEGAL_REASONS"
            | "INTERNAL_SERVER_ERROR"
            | "NOT_IMPLEMENTED"
            | "BAD_GATEWAY"
            | "SERVICE_UNAVAILABLE"
            | "GATEWAY_TIMEOUT"
            | "HTTP_VERSION_NOT_SUPPORTED"
            | "VARIANT_ALSO_NEGOTIATES"
            | "INSUFFICIENT_STORAGE"
            | "LOOP_DETECTED"
            | "NOT_EXTENDED"
            | "NETWORK_AUTHENTICATION_REQUIRED"
    )
}

fn classify_json_call(call: &syn::ExprCall) -> ResponseExitShape {
    let Some(path) = syn_expr_path(&call.func) else {
        return ResponseExitShape::Unknown;
    };
    if !syn_path_last_is(path, "Json") || call.args.len() != 1 {
        return ResponseExitShape::Unknown;
    }
    match call.args.first() {
        Some(syn::Expr::Macro(expr_macro)) => match json_macro_shape(&expr_macro.mac) {
            JsonMacroShape::Object(fields) => ResponseExitShape::Object(fields),
            JsonMacroShape::NonObject => ResponseExitShape::NonObject,
            JsonMacroShape::Unsupported => ResponseExitShape::Unknown,
        },
        _ => ResponseExitShape::Unknown,
    }
}

fn json_call_from_expr(expr: &syn::Expr) -> Option<&syn::ExprCall> {
    match expr {
        syn::Expr::Call(call) => syn_expr_path(&call.func)
            .is_some_and(|path| syn_path_last_is(path, "Json"))
            .then_some(call),
        syn::Expr::Paren(paren) => json_call_from_expr(&paren.expr),
        syn::Expr::Group(group) => json_call_from_expr(&group.expr),
        _ => None,
    }
}

fn classify_success_payload(expr: &syn::Expr) -> ResponseExitShape {
    match expr {
        syn::Expr::Paren(paren) => classify_success_payload(&paren.expr),
        syn::Expr::Group(group) => classify_success_payload(&group.expr),
        syn::Expr::MethodCall(method) if method.method == "into_response" => {
            classify_success_payload(&method.receiver)
        }
        syn::Expr::Call(call) => {
            let Some(path) = syn_expr_path(&call.func) else {
                return ResponseExitShape::Unknown;
            };
            if syn_path_last_is(path, "Json") {
                return classify_json_call(call);
            }
            ResponseExitShape::Unknown
        }
        syn::Expr::Tuple(tuple) if tuple.elems.is_empty() => ResponseExitShape::NoBody {
            safe_alongside_json: false,
        },
        syn::Expr::Tuple(tuple) => {
            let status_name = tuple.elems.iter().find_map(status_code_name);
            if let Some(name) = status_name.as_deref() {
                if is_error_status_name(name) {
                    return ResponseExitShape::Error;
                }
            }
            let mut json = Vec::new();
            let mut unrecognized_metadata = false;
            for element in &tuple.elems {
                if let Some(call) = json_call_from_expr(element) {
                    json.push(classify_json_call(call));
                    continue;
                }
                if status_code_name(element).is_some() || matches!(element, syn::Expr::Array(_)) {
                    continue;
                }
                unrecognized_metadata = true;
            }
            let Some(first) = json.pop() else {
                return status_name.as_deref().and_then(success_status_fact).map_or(
                    ResponseExitShape::Unknown,
                    |(status, _)| ResponseExitShape::NoBody {
                        safe_alongside_json: matches!(status, 204 | 205 | 300..=399),
                    },
                );
            };
            if !json.is_empty() || (status_name.is_none() && unrecognized_metadata) {
                ResponseExitShape::Unknown
            } else {
                first
            }
        }
        syn::Expr::Path(_) => match status_code_name(expr) {
            Some(name) if is_error_status_name(&name) => ResponseExitShape::Error,
            Some(name) => {
                success_status_fact(&name).map_or(ResponseExitShape::Unknown, |(status, _)| {
                    ResponseExitShape::NoBody {
                        safe_alongside_json: matches!(status, 204 | 205 | 300..=399),
                    }
                })
            }
            _ => ResponseExitShape::Unknown,
        },
        _ => ResponseExitShape::Unknown,
    }
}

fn classify_response_exit(expr: &syn::Expr) -> ResponseExitShape {
    match expr {
        syn::Expr::Paren(paren) => classify_response_exit(&paren.expr),
        syn::Expr::Group(group) => classify_response_exit(&group.expr),
        syn::Expr::Call(call) => {
            let Some(path) = syn_expr_path(&call.func) else {
                return classify_success_payload(expr);
            };
            if syn_path_last_is(path, "Err") {
                return ResponseExitShape::Error;
            }
            if syn_path_last_is(path, "Ok") {
                return call
                    .args
                    .first()
                    .map_or(ResponseExitShape::Unknown, classify_success_payload);
            }
            classify_success_payload(expr)
        }
        syn::Expr::Return(return_expr) => return_expr.expr.as_deref().map_or(
            ResponseExitShape::NoBody {
                safe_alongside_json: false,
            },
            classify_response_exit,
        ),
        _ => classify_success_payload(expr),
    }
}

struct HandlerReturnCollector<'ast> {
    expressions: Vec<&'ast syn::Expr>,
}

impl<'ast> syn::visit::Visit<'ast> for HandlerReturnCollector<'ast> {
    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if let Some(expr) = node.expr.as_deref() {
            self.expressions.push(expr);
        }
    }

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {}

    fn visit_item(&mut self, _node: &'ast syn::Item) {}
}

fn collect_tail_exit_shapes(expr: &syn::Expr, outcomes: &mut Vec<ResponseExitShape>) {
    match expr {
        // Explicit returns were already collected by HandlerReturnCollector.
        syn::Expr::Return(_) => {}
        syn::Expr::Paren(paren) => collect_tail_exit_shapes(&paren.expr, outcomes),
        syn::Expr::Group(group) => collect_tail_exit_shapes(&group.expr, outcomes),
        syn::Expr::Block(block) => collect_block_tail_exit_shapes(&block.block, outcomes),
        syn::Expr::TryBlock(block) => collect_block_tail_exit_shapes(&block.block, outcomes),
        syn::Expr::If(if_expr) => {
            collect_block_tail_exit_shapes(&if_expr.then_branch, outcomes);
            if let Some((_, else_expr)) = &if_expr.else_branch {
                collect_tail_exit_shapes(else_expr, outcomes);
            } else {
                outcomes.push(ResponseExitShape::Unknown);
            }
        }
        syn::Expr::Match(match_expr) => {
            for arm in &match_expr.arms {
                collect_tail_exit_shapes(&arm.body, outcomes);
            }
        }
        _ => outcomes.push(classify_response_exit(expr)),
    }
}

fn collect_block_tail_exit_shapes(block: &syn::Block, outcomes: &mut Vec<ResponseExitShape>) {
    if let Some(syn::Stmt::Expr(expr, None)) = block.stmts.last() {
        collect_tail_exit_shapes(expr, outcomes);
    }
}

fn merge_json_shapes(shapes: &[Vec<ApiField>]) -> Option<Vec<ApiField>> {
    if shapes.is_empty() {
        return None;
    }
    let mut order = Vec::new();
    let mut merged: BTreeMap<String, (String, usize)> = BTreeMap::new();
    for shape in shapes {
        for field in shape {
            if !merged.contains_key(&field.name) {
                order.push(field.name.clone());
            }
            let entry = merged
                .entry(field.name.clone())
                .or_insert_with(|| (field.type_.clone(), 0));
            if entry.0 != field.type_ {
                entry.0 = "Value".to_string();
            }
            entry.1 += 1;
        }
    }
    let total = shapes.len();
    let fields: Vec<ApiField> = order
        .into_iter()
        .filter_map(|name| {
            let (type_, count) = merged.remove(&name)?;
            Some(ApiField {
                name,
                type_,
                optional: count < total,
                doc: None,
            })
        })
        .collect();
    (!fields.is_empty()).then_some(fields)
}

/// Extracts a complete top-level object schema only when every directly
/// observable success exit is an inline `Json(json!({...}))` object (or a
/// known bodyless success). Any delegated, variable, or otherwise ambiguous
/// success exit keeps `fields` null rather than presenting a partial schema.
fn literal_success_response_fields(info: &HandlerInfo) -> Option<Vec<ApiField>> {
    let body = info.body.as_deref()?;
    let block = syn::parse_str::<syn::Block>(&format!("{{{body}}}")).ok()?;
    let mut collector = HandlerReturnCollector {
        expressions: Vec::new(),
    };
    collector.visit_block(&block);
    let mut outcomes: Vec<ResponseExitShape> = collector
        .expressions
        .into_iter()
        .map(classify_response_exit)
        .collect();
    collect_block_tail_exit_shapes(&block, &mut outcomes);

    let mut shapes = Vec::new();
    let mut saw_non_object = false;
    let mut saw_incompatible_bodyless = false;
    for outcome in outcomes {
        match outcome {
            ResponseExitShape::Error => {}
            ResponseExitShape::NoBody {
                safe_alongside_json,
            } => saw_incompatible_bodyless |= !safe_alongside_json,
            ResponseExitShape::NonObject => saw_non_object = true,
            ResponseExitShape::Object(fields) => shapes.push(fields),
            ResponseExitShape::Unknown => return None,
        }
    }
    if (saw_non_object || saw_incompatible_bodyless) && !shapes.is_empty() {
        return None;
    }
    let success_type = declared_success_type(info);
    if success_type
        .as_deref()
        .is_some_and(|ty| type_contains_token(ty, "StatusCode"))
        && explicit_response_statuses(info)
            .keys()
            .filter(|status| !matches!(status, 204 | 205 | 300..=399))
            .count()
            != 1
    {
        return None;
    }
    merge_json_shapes(&shapes)
}

fn response_body_for(info: &HandlerInfo, scan: &SourceScan) -> Option<ApiResponseBody> {
    let literal_fields = literal_success_response_fields(info);
    let ty = declared_success_type(info)
        .as_deref()
        .and_then(|success| extractor_type(success, "Json"))
        .or_else(|| {
            info.body
                .as_deref()
                .filter(|body| {
                    body_visibly_returns_success_json(body)
                        || handler_tail_maps_success_to_json(info)
                })
                .map(|_| "Value".to_string())
        })
        .or_else(|| literal_fields.as_ref().map(|_| "Value".to_string()))?;
    let fields = resolve_struct(scan, &ty, &info.file)
        .and_then(|found| found.fields.clone())
        .or(literal_fields);
    Some(ApiResponseBody { type_: ty, fields })
}

fn success_status_fact(name: &str) -> Option<(u16, &'static str)> {
    match name {
        "OK" => Some((200, "OK")),
        "CREATED" => Some((201, "Created")),
        "ACCEPTED" => Some((202, "Accepted")),
        "NON_AUTHORITATIVE_INFORMATION" => Some((203, "Non-Authoritative Information")),
        "NO_CONTENT" => Some((204, "No Content")),
        "RESET_CONTENT" => Some((205, "Reset Content")),
        "PARTIAL_CONTENT" => Some((206, "Partial Content")),
        "MULTI_STATUS" => Some((207, "Multi-Status")),
        "ALREADY_REPORTED" => Some((208, "Already Reported")),
        "IM_USED" => Some((226, "IM Used")),
        "MULTIPLE_CHOICES" => Some((300, "Multiple Choices")),
        "MOVED_PERMANENTLY" => Some((301, "Moved Permanently")),
        "FOUND" => Some((302, "Found")),
        "SEE_OTHER" => Some((303, "See Other")),
        "NOT_MODIFIED" => Some((304, "Not Modified")),
        "TEMPORARY_REDIRECT" => Some((307, "Temporary Redirect")),
        "PERMANENT_REDIRECT" => Some((308, "Permanent Redirect")),
        _ => None,
    }
}

fn explicit_response_statuses(info: &HandlerInfo) -> BTreeMap<u16, &'static str> {
    let mut statuses = BTreeMap::new();
    let Some(body) = info.body.as_deref() else {
        return statuses;
    };
    for (index, _) in body.match_indices("StatusCode::") {
        let rest = &body[index + "StatusCode::".len()..];
        let name: String = rest
            .chars()
            .take_while(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || *ch == '_')
            .collect();
        if let Some((status, description)) = success_status_fact(&name) {
            statuses.insert(status, description);
        }
    }
    // Axum's constructors directly fix these status codes (verified against
    // the pinned axum 0.8 implementation); unlike a bare `Redirect` return
    // type, the constructor call is concrete response evidence.
    if body.contains("Redirect::to(") {
        statuses.insert(303, "See Other");
    }
    if body.contains("Redirect::temporary(") {
        statuses.insert(307, "Temporary Redirect");
    }
    if body.contains("Redirect::permanent(") {
        statuses.insert(308, "Permanent Redirect");
    }
    statuses
}

fn handler_marks_no_store(info: &HandlerInfo) -> bool {
    info.body.as_deref().is_some_and(|body| {
        let lower = body.to_ascii_lowercase();
        let names_cache_control = body.contains("::CACHE_CONTROL")
            || lower.contains("\"cache-control\"")
            || lower.contains("from_static(\"cache-control\")");
        names_cache_control && lower.contains("\"no-store\"")
    })
}

fn success_response_headers(info: &HandlerInfo) -> Vec<ApiHeader> {
    let mut headers = Vec::new();
    let body = info.body.as_deref().unwrap_or_default();
    // The request-list helper is the more specific contract. If a future
    // handler happens to call both helpers, do not emit contradictory required
    // and optional definitions for the same X-Total-Count header.
    if info.body_flags.total_count_headers && !info.body_flags.request_list_headers {
        headers.push(api_header(
            "X-Total-Count",
            "integer",
            true,
            "Filtered total before limit/offset pagination, returned alongside the successful bare JSON array.",
        ));
    }
    if info.body_flags.request_list_headers {
        headers.extend([
            api_header(
                "X-Total-Count",
                "integer",
                false,
                "Filtered, capped total; present only when include_total=true and the aggregate finishes within its statement budget.",
            ),
            api_header(
                "X-Total-Count-Capped",
                "boolean",
                false,
                "True when X-Total-Count reached the supported request-list navigation ceiling.",
            ),
            api_header(
                "X-Total-Count-Unavailable",
                "boolean",
                false,
                "True when include_total=true but the optional aggregate exceeded its statement budget; the bounded page is still returned.",
            ),
            api_header(
                "X-Next-Cursor",
                "string",
                false,
                "Opaque continuation emitted only when another deterministic request-list page exists.",
            ),
        ]);
    }
    if handler_marks_no_store(info) {
        headers.push(api_header(
            "Cache-Control",
            "string",
            true,
            "The handler directly marks this response `no-store`, preventing persistence or idempotency replay of the returned value.",
        ));
    }
    if body.contains("LOCATION")
        && explicit_response_statuses(info)
            .keys()
            .any(|status| matches!(status, 300..=399))
    {
        headers.push(api_header(
            "Location",
            "string",
            true,
            "Redirect target selected by the authentication flow.",
        ));
    }
    if body.contains("SET_COOKIE") {
        headers.push(api_header(
            "Set-Cookie",
            "string",
            false,
            "Authentication/session cookie emitted on the successful branch that establishes or clears browser state.",
        ));
    }
    headers
}

fn response_body_state_for(
    info: &HandlerInfo,
    status: u16,
    body: Option<&ApiResponseBody>,
) -> ResponseBodyState {
    if matches!(status, 204 | 205 | 300..=399) {
        return ResponseBodyState::None;
    }
    if body.is_some() {
        return ResponseBodyState::Json;
    }
    let source = info
        .body
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if source.contains("text/plain") || source.contains("application/octet-stream") {
        ResponseBodyState::Raw
    } else {
        ResponseBodyState::Unknown
    }
}

fn success_responses_for(info: &HandlerInfo, scan: &SourceScan) -> Vec<ApiResponse> {
    let body = response_body_for(info, scan);
    let headers = success_response_headers(info);
    let mut statuses = explicit_response_statuses(info);
    let success_has_dynamic_status = declared_success_type(info)
        .as_deref()
        .is_some_and(|success| type_contains_token(success, "StatusCode"));
    let has_raw_body = matches!(
        response_body_state_for(info, 200, None),
        ResponseBodyState::Raw
    );
    if (body.is_some() || has_raw_body)
        && !success_has_dynamic_status
        && (statuses.is_empty() || statuses.keys().all(|status| matches!(status, 204 | 205)))
    {
        statuses.insert(200, "OK");
    }
    statuses
        .into_iter()
        .map(|(status, description)| {
            let status_body = if matches!(status, 204 | 205 | 300..=399) {
                None
            } else {
                body.clone()
            };
            ApiResponse {
                status,
                description: description.to_string(),
                body_state: response_body_state_for(info, status, status_body.as_ref()),
                body: status_body,
                headers: headers.clone(),
            }
        })
        .collect()
}

fn success_response_override(handler: Option<&str>) -> Vec<ApiResponse> {
    match handler.and_then(|name| name.rsplit("::").next()) {
        Some("webhook_receive") => vec![ApiResponse {
            status: 202,
            description:
                "Accepted after freshness/signature verification and atomic receipt/event recording."
                    .to_string(),
            body_state: ResponseBodyState::Json,
            body: Some(ApiResponseBody {
                type_: "Value".to_string(),
                fields: Some(vec![
                    ApiField {
                        name: "status".to_string(),
                        type_: "String".to_string(),
                        optional: false,
                        doc: Some("Always `accepted` for a successful delivery.".to_string()),
                    },
                    ApiField {
                        name: "event_id".to_string(),
                        type_: "i64".to_string(),
                        optional: false,
                        doc: Some("Identifier of the recorded domain event.".to_string()),
                    },
                ]),
            }),
            headers: Vec::new(),
        }],
        Some("requests_approve_live_apply") => vec![ApiResponse {
            status: 200,
            description: "Mints and queues the request-scoped LiveApply job.".to_string(),
            body_state: ResponseBodyState::Json,
            body: Some(ApiResponseBody {
                type_: "Value".to_string(),
                fields: Some(vec![
                    ApiField {
                        name: "job_id".to_string(),
                        type_: "Uuid".to_string(),
                        optional: false,
                        doc: Some("Identifier of the queued LiveApply agent job.".to_string()),
                    },
                    ApiField {
                        name: "approver".to_string(),
                        type_: "String".to_string(),
                        optional: false,
                        doc: Some(
                            "Verified interactive principal that approved the live apply."
                                .to_string(),
                        ),
                    },
                    ApiField {
                        name: "status".to_string(),
                        type_: "String".to_string(),
                        optional: false,
                        doc: Some("Initial job status; `Pending` on success.".to_string()),
                    },
                    ApiField {
                        name: "mode".to_string(),
                        type_: "String".to_string(),
                        optional: false,
                        doc: Some("Execution mode; `LiveApply` on success.".to_string()),
                    },
                ]),
            }),
            headers: Vec::new(),
        }],
        _ => Vec::new(),
    }
}

fn map_query_fields(handler: Option<&str>) -> Option<Vec<ApiField>> {
    let handler = handler?.rsplit("::").next()?;
    let field = match handler {
        "health" | "ready" => ApiField {
            name: "simulate".to_string(),
            type_: "String".to_string(),
            optional: true,
            doc: Some("Set to `error` to exercise the documented 503 probe response.".to_string()),
        },
        "validation_run" => ApiField {
            name: "slice".to_string(),
            type_: "String".to_string(),
            optional: false,
            doc: Some("Name of the validation slice to execute.".to_string()),
        },
        _ => return None,
    };
    Some(vec![field])
}

fn query_params_for(
    handler: Option<&str>,
    info: &HandlerInfo,
    scan: &SourceScan,
) -> Option<Vec<ApiField>> {
    let params = info.params.as_deref()?;
    let ty = extractor_type(params, "Query")?;
    resolve_struct(scan, &ty, &info.file)
        .and_then(|found| found.fields.clone())
        .or_else(|| map_query_fields(handler))
}

fn query_params_state_for(
    info: Option<&HandlerInfo>,
    query_params: Option<&[ApiField]>,
) -> QueryParamsState {
    if query_params.is_some() {
        return QueryParamsState::Known;
    }
    let Some(info) = info else {
        return QueryParamsState::Unknown;
    };
    let has_query_extractor = info
        .params
        .as_deref()
        .and_then(|params| extractor_type(params, "Query"))
        .is_some();
    if has_query_extractor {
        QueryParamsState::Unknown
    } else {
        QueryParamsState::None
    }
}

fn request_body_for(info: &HandlerInfo, scan: &SourceScan) -> Option<ApiRequestBody> {
    let params = info.params.as_deref()?;
    let ty = extractor_type(params, "Json")?;
    let fields = resolve_struct(scan, &ty, &info.file).and_then(|found| found.fields.clone());
    Some(ApiRequestBody {
        struct_name: ty,
        fields,
    })
}

fn response_notes_for(info: &HandlerInfo) -> Option<String> {
    let mut notes: Vec<&str> = Vec::new();
    if info.body_flags.total_count_headers && !info.body_flags.request_list_headers {
        notes.push(
            "Returns a bare JSON array; the filtered total is exposed via the \
             X-Total-Count response header.",
        );
    }
    if info.body_flags.request_list_headers {
        notes.push(
            "Returns a bare JSON array; include_total defaults to false, so total-count \
             headers are conditional, and X-Next-Cursor is emitted only when another \
             deterministic page exists.",
        );
    }
    if info.body_flags.paginated_object {
        notes.push("Returns a paginated JSON object with total/limit/offset keys.");
    }
    if info.returns.contains("ProblemDetails") || info.returns.contains("Json<ApiError>") {
        notes.push(
            "Error responses use the platform ApiError body (error, message, optional detail).",
        );
    }
    if notes.is_empty() {
        None
    } else {
        Some(notes.join(" "))
    }
}

// ───────────────────────── tests ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn route_registration_captures_handler_idents_per_method() {
        let registrations = extract_route_registrations(
            r#"
            // .route("/api/commented/decoy", get(decoy))
            .route("/api/things", get(things_list).post(things_create))
            .route(
                "/api/auth/oidc/callback",
                get(crate::oidc_callback::oidc_callback),
            )
            .route("/api/closure", get(|| async { "ok" }))
            "#,
        );
        assert_eq!(registrations.len(), 3);
        assert_eq!(registrations[0].path, "/api/things");
        let methods: Vec<(&str, Option<&str>)> = registrations[0]
            .methods
            .iter()
            .map(|entry| (entry.method.as_str(), entry.handler.as_deref()))
            .collect();
        assert!(methods.contains(&("GET", Some("things_list"))));
        assert!(methods.contains(&("POST", Some("things_create"))));
        assert_eq!(
            registrations[1].methods[0].handler.as_deref(),
            Some("crate::oidc_callback::oidc_callback")
        );
        // A closure is not a fn ident: no fabricated handler name.
        assert_eq!(registrations[2].methods[0].method, "GET");
        assert_eq!(registrations[2].methods[0].handler, None);
    }

    #[test]
    fn scan_file_indexes_handler_docs_extractors_and_body_flags() {
        let source = r##"
/// GET /api/widgets — lists widgets (#7). Second sentence with detail.
async fn widgets_list(
    AuthExtractor(session): AuthExtractor,
    Query(page): Query<WidgetListQuery>,
) -> Result<Json<Value>, ProblemDetails> {
    let headers = total_count_headers(total);
    Ok(json!({"items": [], "total": 0, "limit": 1, "offset": 0}))
}

/// Creates a widget.
async fn widgets_create(Json(body): Json<CreateWidget>) -> ApiResult {
    // add_page_meta mentioned in a comment must NOT count
    Ok(Json(json!({})))
}

/// GET /api/requests — lists requests with optional totals and cursors.
async fn requests_list(Query(page): Query<RequestListParams>) -> ApiResult {
    let headers = request_list_headers(None, None, false);
    Ok(Json(json!([])))
}

fn helper_with_raw_string() -> &'static str {
    r#"{"not": "a } trap"}"#
}
"##;
        let mut scan = SourceScan::default();
        scan_file(source, "sources/ryuki-api/src/contracts.rs", &mut scan);

        let list = &scan.handlers["widgets_list"][0];
        assert_eq!(
            list.doc.as_deref(),
            Some("GET /api/widgets — lists widgets (#7). Second sentence with detail.")
        );
        assert_eq!(
            extractor_type(list.params.as_deref().unwrap(), "Query").as_deref(),
            Some("WidgetListQuery")
        );
        assert!(list.body_flags.total_count_headers);
        assert!(list.body_flags.paginated_object);
        assert!(list.returns.contains("ProblemDetails"));

        let create = &scan.handlers["widgets_create"][0];
        assert_eq!(create.doc.as_deref(), Some("Creates a widget."));
        assert_eq!(
            extractor_type(create.params.as_deref().unwrap(), "Json").as_deref(),
            Some("CreateWidget")
        );
        assert!(!create.body_flags.total_count_headers);
        assert!(!create.body_flags.request_list_headers);
        // the comment-only add_page_meta mention is stripped before flag scans
        assert!(!create.body_flags.paginated_object);

        let requests = &scan.handlers["requests_list"][0];
        assert!(requests.body_flags.request_list_headers);
        assert!(!requests.body_flags.total_count_headers);
        let response_headers = success_response_headers(requests);
        assert_eq!(response_headers.len(), 4);
        assert_eq!(
            response_headers
                .iter()
                .map(|header| header.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "X-Total-Count",
                "X-Total-Count-Capped",
                "X-Total-Count-Unavailable",
                "X-Next-Cursor",
            ]
        );
        assert!(response_headers.iter().all(|header| !header.required));
        assert!(response_headers.iter().any(|header| {
            header.name == "X-Total-Count-Unavailable"
                && header.description.contains("statement budget")
        }));
        assert!(response_notes_for(requests)
            .is_some_and(|notes| notes.contains("include_total defaults to false")));

        let total_headers = success_response_headers(list);
        assert_eq!(total_headers.len(), 1);
        assert_eq!(total_headers[0].name, "X-Total-Count");
        assert!(total_headers[0].required);

        let mut both_flags = requests.clone();
        both_flags.body_flags.total_count_headers = true;
        let both_headers = success_response_headers(&both_flags);
        assert_eq!(both_headers.len(), 4);
        assert!(both_headers.iter().all(|header| !header.required));
        assert!(response_notes_for(&both_flags)
            .is_some_and(|notes| !notes.contains("filtered total is exposed")));

        // the raw string's unbalanced-looking brace did not desync the scanner
        assert!(scan.handlers.contains_key("helper_with_raw_string"));
    }

    #[test]
    fn struct_fields_capture_option_serde_rename_default_and_docs() {
        let source = r#"
/// Query shape for widget lists.
#[derive(Debug, Deserialize)]
struct WidgetListQuery {
    /// Max rows per page.
    limit: Option<i64>,
    offset: Option<i64>,
    #[serde(rename = "siteCode")]
    site: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(skip)]
    internal: bool,
    plain: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenamedAll {
    target_ci_key: String,
}

struct CommentTrap {
    // prose with arrow -> and an unbalanced ( parenthesis must not desync
    #[serde(default)]
    fields: std::collections::BTreeMap<String, String>,
}

struct Tuple(String);
"#;
        let mut scan = SourceScan::default();
        scan_file(source, "sources/ryuki-api/src/contracts.rs", &mut scan);

        let fields = scan.structs["WidgetListQuery"][0].fields.clone().unwrap();
        let by_name: BTreeMap<&str, &ApiField> = fields
            .iter()
            .map(|field| (field.name.as_str(), field))
            .collect();
        assert_eq!(fields.len(), 5, "skip field must be excluded");
        assert_eq!(by_name["limit"].type_, "i64");
        assert!(by_name["limit"].optional);
        assert_eq!(by_name["limit"].doc.as_deref(), Some("Max rows per page."));
        assert!(by_name.contains_key("siteCode"), "serde rename must win");
        assert_eq!(by_name["siteCode"].type_, "String");
        assert!(by_name["tags"].optional, "serde default implies optional");
        assert_eq!(by_name["tags"].type_, "Vec<String>");
        assert!(!by_name["plain"].optional);
        assert_eq!(by_name["plain"].doc, None);

        let renamed = scan.structs["RenamedAll"][0].fields.clone().unwrap();
        assert_eq!(renamed[0].name, "targetCiKey");

        // comment prose ("->", unbalanced parens) must not truncate types at
        // commas inside generics
        let trapped = scan.structs["CommentTrap"][0].fields.clone().unwrap();
        assert_eq!(trapped.len(), 1);
        assert_eq!(
            trapped[0].type_,
            "std::collections::BTreeMap<String, String>"
        );
        assert!(trapped[0].optional, "serde default implies optional");

        assert!(scan.structs["Tuple"][0].fields.is_none());
    }

    #[test]
    fn path_params_resolve_tuple_and_struct_extractors() {
        let source = r#"
struct NamedPath {
    site: String,
    sequence: i64,
}

async fn tuple_handler(Path((site, id)): Path<(String, i64)>) {}
async fn struct_handler(Path(path): Path<NamedPath>) {}
"#;
        let mut scan = SourceScan::default();
        scan_file(source, "sources/ryuki-api/src/path_test.rs", &mut scan);

        let tuple = path_params_for(
            "/api/sites/{site}/items/{id}",
            Some(&scan.handlers["tuple_handler"][0]),
            &scan,
        );
        assert_eq!(tuple.len(), 2);
        assert_eq!(
            (tuple[0].name.as_str(), tuple[0].type_.as_str()),
            ("site", "String")
        );
        assert_eq!(
            (tuple[1].name.as_str(), tuple[1].type_.as_str()),
            ("id", "i64")
        );
        assert!(tuple.iter().all(|field| !field.optional));

        let named = path_params_for(
            "/api/sites/{site}/items/{sequence}",
            Some(&scan.handlers["struct_handler"][0]),
            &scan,
        );
        assert_eq!(named.len(), 2);
        assert_eq!(named[0].type_, "String");
        assert_eq!(named[1].type_, "i64");
    }

    #[test]
    fn request_body_states_distinguish_json_raw_none_and_unknown() {
        let source = r#"
struct Payload { value: String }
async fn json_handler(Json(body): Json<Payload>) {}
async fn raw_handler(body: axum::body::Bytes) {}
async fn no_body_handler(headers: HeaderMap) {}
"#;
        let mut scan = SourceScan::default();
        scan_file(source, "sources/ryuki-api/src/body_test.rs", &mut scan);

        assert_eq!(
            request_body_state_for(Some(&scan.handlers["json_handler"][0])),
            RequestBodyState::Json
        );
        assert_eq!(
            request_body_state_for(Some(&scan.handlers["raw_handler"][0])),
            RequestBodyState::Raw
        );
        assert_eq!(
            request_body_state_for(Some(&scan.handlers["no_body_handler"][0])),
            RequestBodyState::None
        );
        assert_eq!(request_body_state_for(None), RequestBodyState::Unknown);
    }

    #[test]
    fn query_parameter_states_distinguish_known_none_and_unknown_maps() {
        let source = r#"
struct KnownQuery { limit: Option<i64> }
async fn known_handler(Query(query): Query<KnownQuery>) {}
async fn health(Query(params): Query<HashMap<String, String>>) {}
async fn unknown_map(Query(params): Query<HashMap<String, String>>) {}
async fn no_query(headers: HeaderMap) {}
"#;
        let mut scan = SourceScan::default();
        scan_file(source, "sources/ryuki-api/src/query_test.rs", &mut scan);

        let known_info = &scan.handlers["known_handler"][0];
        let known = query_params_for(Some("known_handler"), known_info, &scan);
        assert_eq!(known.as_ref().expect("known query")[0].name, "limit");
        assert_eq!(
            query_params_state_for(Some(known_info), known.as_deref()),
            QueryParamsState::Known
        );

        let health_info = &scan.handlers["health"][0];
        let health = query_params_for(Some("health"), health_info, &scan);
        let simulate = &health.as_ref().expect("curated map query")[0];
        assert_eq!(simulate.name, "simulate");
        assert!(simulate.optional);

        let unknown_info = &scan.handlers["unknown_map"][0];
        let unknown = query_params_for(Some("unknown_map"), unknown_info, &scan);
        assert!(unknown.is_none());
        assert_eq!(
            query_params_state_for(Some(unknown_info), unknown.as_deref()),
            QueryParamsState::Unknown
        );

        let no_query_info = &scan.handlers["no_query"][0];
        assert_eq!(
            query_params_state_for(Some(no_query_info), None),
            QueryParamsState::None
        );
        assert_eq!(
            query_params_state_for(None, None),
            QueryParamsState::Unknown
        );
    }

    #[test]
    fn request_headers_follow_access_body_and_protocol_evidence() {
        let source = r#"
struct Payload { value: String }
async fn agent_handler(_pv: ProtocolVersion, Json(body): Json<Payload>) {}
async fn webhook_handler(body: Bytes) {}
"#;
        let mut scan = SourceScan::default();
        scan_file(source, "sources/ryuki-api/src/header_test.rs", &mut scan);
        let agent_info = &scan.handlers["agent_handler"][0];
        let agent = request_headers_for(
            "POST",
            "/api/agents/register",
            Some("agent"),
            false,
            Some(agent_info),
            RequestBodyState::Json,
        );
        let agent_by_name: BTreeMap<&str, &ApiHeader> = agent
            .iter()
            .map(|header| (header.name.as_str(), header))
            .collect();
        assert!(agent_by_name["Authorization"].required);
        assert!(agent_by_name["Content-Type"].required);
        assert!(agent_by_name["x-ryuki-protocol-version"].required);
        assert!(!agent_by_name.contains_key("Idempotency-Key"));

        let human = request_headers_for(
            "POST",
            "/api/ops/emergency/initiate",
            Some("admin"),
            false,
            Some(agent_info),
            RequestBodyState::Json,
        );
        let human_by_name: BTreeMap<&str, &ApiHeader> = human
            .iter()
            .map(|header| (header.name.as_str(), header))
            .collect();
        assert!(!human_by_name["Authorization"].required);
        assert!(!human_by_name["X-Ryuki-Session-Id"].required);
        assert!(human_by_name["Idempotency-Key"].required);

        let token_mint = request_headers_for(
            "POST",
            "/api/admin/tokens",
            Some("admin"),
            false,
            Some(agent_info),
            RequestBodyState::Json,
        );
        let token_mint_by_name: BTreeMap<&str, &ApiHeader> = token_mint
            .iter()
            .map(|header| (header.name.as_str(), header))
            .collect();
        assert!(token_mint_by_name["Authorization"]
            .description
            .contains("explicitly rejected"));
        assert!(token_mint_by_name["X-Ryuki-Session-Id"]
            .description
            .contains("never the administrative session UUID"));

        let webhook_info = &scan.handlers["webhook_handler"][0];
        let webhook = request_headers_for(
            "POST",
            "/api/integrations/{connection_id}/webhook",
            Some("webhook"),
            false,
            Some(webhook_info),
            RequestBodyState::Raw,
        );
        assert_eq!(webhook.len(), 3);
        let webhook_by_name: BTreeMap<&str, &ApiHeader> = webhook
            .iter()
            .map(|header| (header.name.as_str(), header))
            .collect();
        assert!(webhook_by_name["X-Hub-Signature-256"].required);
        assert!(webhook_by_name["X-Hub-Signature-256"]
            .description
            .contains("v1 canonical message"));
        assert!(webhook_by_name["X-Ryuki-Webhook-Timestamp"].required);
        assert!(webhook_by_name["X-Ryuki-Webhook-Delivery-Id"].required);
    }

    #[test]
    fn fallback_summary_is_deterministic_and_source_derived() {
        assert_eq!(
            fallback_summary("POST", "/api/widgets", Some("widgets_create")),
            "Create widgets."
        );
        assert_eq!(
            fallback_summary("GET", "/api/requests", Some("requests_list")),
            "List requests."
        );
        assert_eq!(
            fallback_summary(
                "POST",
                "/api/integrations/{id}/circuit/reset",
                Some("integration_circuit_reset")
            ),
            "Reset integration circuit."
        );
        assert_eq!(fallback_summary("GET", "/health", None), "GET /health.");
    }

    #[test]
    fn success_responses_extract_status_schema_headers_and_bodyless_branch() {
        let source = r#"
struct CreatedResponse {
    id: String,
}

async fn create_handler() -> Result<(StatusCode, Json<CreatedResponse>), Error> {
    Ok((StatusCode::CREATED, Json(CreatedResponse { id: String::new() })))
}

async fn poll_handler() -> impl IntoResponse {
    if true {
        return StatusCode::NO_CONTENT.into_response();
    }
    Json(json!({"job": null})).into_response()
}

async fn secret_handler() -> Result<Json<Value>, Error> {
    Ok(([(axum::http::header::CACHE_CONTROL, "no-store")], Json(json!({})))))
}

async fn text_handler() -> Response {
    Response::builder()
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from("metric 1\n"))
        .unwrap()
}

async fn mapped_json_handler() -> ApiResult {
    build_result()
        .map(|result| Json(serde_json::to_value(result).unwrap_or_default()))
        .map_err(status_400)
}
"#;
        let mut scan = SourceScan::default();
        scan_file(source, "sources/ryuki-api/src/response_test.rs", &mut scan);

        let created = success_responses_for(&scan.handlers["create_handler"][0], &scan);
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].status, 201);
        let created_body = created[0].body.as_ref().expect("created JSON body");
        assert_eq!(created_body.type_, "CreatedResponse");
        assert_eq!(
            created_body.fields.as_ref().expect("resolved fields")[0].name,
            "id"
        );

        let poll = success_responses_for(&scan.handlers["poll_handler"][0], &scan);
        assert_eq!(
            poll.iter()
                .map(|response| response.status)
                .collect::<Vec<_>>(),
            vec![200, 204]
        );
        assert!(poll[0].body.is_some());
        assert!(poll[1].body.is_none());

        let secret = success_responses_for(&scan.handlers["secret_handler"][0], &scan);
        assert_eq!(secret[0].status, 200);
        assert!(secret[0]
            .headers
            .iter()
            .any(|header| header.name == "Cache-Control"));

        let text = success_responses_for(&scan.handlers["text_handler"][0], &scan);
        assert_eq!(text.len(), 1);
        assert_eq!(text[0].status, 200);
        assert_eq!(text[0].body_state, ResponseBodyState::Raw);
        assert!(text[0].body.is_none());

        let mapped = success_responses_for(&scan.handlers["mapped_json_handler"][0], &scan);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].status, 200);
        assert_eq!(mapped[0].body_state, ResponseBodyState::Json);
        assert_eq!(
            mapped[0].body.as_ref().expect("mapped JSON body").type_,
            "Value"
        );
    }

    #[test]
    fn literal_json_response_fields_merge_success_branches_without_decoys() {
        let source = r#"
async fn literal_handler(flag: bool) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _local = json!({"local_only": true});
    let _closure = || Json(json!({"closure_only": true}));
    let _future = async { Json(json!({"async_only": true})) };
    if flag {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid", "id": "not-success"})),
        ));
    }
    if flag {
        return Ok(axum::Json(serde_json::json!({
            "id": "widget-1",
            "nested": {"value": 1, "label": "comma, safe"},
            "items": [1, 2],
            "active": true,
            "count": 2,
            "ratio": 1.5,
        })));
    }
    Ok(Json(json!({
        "id": "widget-2",
        "nested": {"different": true},
        "items": [],
        "active": false,
        "extra": null,
    })))
}
"#;
        let mut scan = SourceScan::default();
        scan_file(
            source,
            "sources/ryuki-api/src/literal_response_test.rs",
            &mut scan,
        );

        let fields = literal_success_response_fields(&scan.handlers["literal_handler"][0])
            .expect("both successful object branches are statically complete");
        let by_name: BTreeMap<&str, &ApiField> = fields
            .iter()
            .map(|field| (field.name.as_str(), field))
            .collect();

        assert_eq!(by_name["id"].type_, "String");
        assert_eq!(by_name["nested"].type_, "Value");
        assert_eq!(by_name["items"].type_, "Vec<Value>");
        assert_eq!(by_name["active"].type_, "bool");
        assert_eq!(by_name["count"].type_, "i64");
        assert_eq!(by_name["ratio"].type_, "f64");
        assert_eq!(by_name["extra"].type_, "null");
        assert!(!by_name["id"].optional);
        assert!(by_name["count"].optional);
        assert!(by_name["ratio"].optional);
        assert!(by_name["extra"].optional);
        assert!(!by_name.contains_key("error"));
        assert!(!by_name.contains_key("local_only"));
        assert!(!by_name.contains_key("closure_only"));
        assert!(!by_name.contains_key("async_only"));
    }

    #[test]
    fn literal_json_response_fields_reject_ambiguous_success_shapes() {
        let source = r#"
async fn dynamic_key_handler(key: String) -> Json<Value> {
    Json(json!({(key): "value"}))
}

async fn delegated_handler(flag: bool) -> Json<Value> {
    if flag {
        return delegated_response().await;
    }
    Json(json!({"id": "known-only-on-one-branch"}))
}

async fn mixed_handler(flag: bool) -> Json<Value> {
    if flag {
        return Json(json!([1, 2, 3]));
    }
    Json(json!({"id": "object"}))
}
"#;
        let mut scan = SourceScan::default();
        scan_file(
            source,
            "sources/ryuki-api/src/ambiguous_response_test.rs",
            &mut scan,
        );

        for handler in ["dynamic_key_handler", "delegated_handler", "mixed_handler"] {
            assert!(
                literal_success_response_fields(&scan.handlers[handler][0]).is_none(),
                "{handler} must not publish a partial or guessed response schema"
            );
        }
    }

    #[test]
    fn literal_json_response_fields_reject_incompatible_or_dynamic_status_branches() {
        let source = r#"
async fn bodyless_ok_handler(flag: bool) -> Response {
    if flag {
        return StatusCode::OK.into_response();
    }
    (StatusCode::CREATED, Json(json!({"id": "created"}))).into_response()
}

async fn text_ok_handler(flag: bool) -> Response {
    if flag {
        return (StatusCode::OK, "plain text").into_response();
    }
    (StatusCode::CREATED, Json(json!({"id": "created"}))).into_response()
}

async fn dynamic_status_handler(status: StatusCode, flag: bool) -> Response {
    if flag {
        return (StatusCode::OK, (Json(json!({"id": "known"})))).into_response();
    }
    (status, Json(json!({"error": "possibly an error"}))).into_response()
}

async fn parenthesized_error_status_handler(flag: bool) -> Response {
    if flag {
        return ((StatusCode::BAD_REQUEST), Json(json!({"error": "bad"}))).into_response();
    }
    Json(json!({"id": "known"})).into_response()
}
"#;
        let mut scan = SourceScan::default();
        scan_file(
            source,
            "sources/ryuki-api/src/status_response_test.rs",
            &mut scan,
        );

        for handler in [
            "bodyless_ok_handler",
            "text_ok_handler",
            "dynamic_status_handler",
        ] {
            assert!(
                literal_success_response_fields(&scan.handlers[handler][0]).is_none(),
                "{handler} must not attach one branch's JSON schema to an incompatible status"
            );
        }

        let fields = literal_success_response_fields(
            &scan.handlers["parenthesized_error_status_handler"][0],
        )
        .expect("a parenthesized explicit error status must be excluded");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "id");
    }

    #[test]
    fn literal_json_response_field_splitter_handles_comparisons_and_turbofish() {
        let source = r#"
async fn comparison_handler(left: i64, right: i64) -> Json<Value> {
    Json(json!({
        "less": left < right,
        "less_or_equal": left <= right,
        "generic": Vec::<Result<String, String>>::new(),
        "after": true,
    }))
}
"#;
        let mut scan = SourceScan::default();
        scan_file(
            source,
            "sources/ryuki-api/src/comparison_response_test.rs",
            &mut scan,
        );

        let fields = literal_success_response_fields(&scan.handlers["comparison_handler"][0])
            .expect("comparison operators must not swallow later JSON fields");
        assert_eq!(
            fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<Vec<_>>(),
            vec!["less", "less_or_equal", "generic", "after"]
        );
        assert_eq!(fields[3].type_, "bool");
    }

    #[test]
    fn success_response_does_not_promote_error_json_or_dynamic_status_to_200() {
        let source = r#"
async fn redirect_handler() -> Result<Response, (StatusCode, Json<ApiError>)> {
    if false {
        return Err((StatusCode::BAD_REQUEST, Json(ApiError::new("bad", "bad"))));
    }
    Ok((StatusCode::FOUND, [(LOCATION, "/")]).into_response())
}

async fn redirect_wrapper() -> Result<Redirect, (StatusCode, Json<ApiError>)> {
    redirect_helper().await
}

async fn webhook_wrapper() -> WebhookResult<(StatusCode, Json<Value>)> {
    webhook_receive_with_pool().await
}
"#;
        let mut scan = SourceScan::default();
        scan_file(
            source,
            "sources/ryuki-api/src/dynamic_status_test.rs",
            &mut scan,
        );

        let redirect = success_responses_for(&scan.handlers["redirect_handler"][0], &scan);
        assert_eq!(redirect.len(), 1);
        assert_eq!(redirect[0].status, 302);
        assert!(redirect[0].body.is_none());
        assert!(redirect[0]
            .headers
            .iter()
            .any(|header| header.name == "Location"));

        let unresolved_redirect =
            success_responses_for(&scan.handlers["redirect_wrapper"][0], &scan);
        assert!(unresolved_redirect.is_empty());

        let webhook = success_responses_for(&scan.handlers["webhook_wrapper"][0], &scan);
        assert!(
            webhook.is_empty(),
            "a delegated dynamic StatusCode is not evidence for default 200"
        );
    }

    #[test]
    fn array_type_semicolon_preserves_created_no_store_response_contract() {
        let source = r#"
struct TokenRequest { name: String }
struct TokenReply { token: String }
async fn admin_tokens_create(
    Json(body): Json<TokenRequest>,
) -> Result<
    (
        StatusCode,
        [(axum::http::header::HeaderName, &'static str); 1],
        Json<TokenReply>,
    ),
    (StatusCode, Json<ApiError>),
> {
    Ok((
        StatusCode::CREATED,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(TokenReply { token: String::new() }),
    ))
}
"#;
        let mut scan = SourceScan::default();
        scan_file(
            source,
            "sources/ryuki-api/src/array_signature_test.rs",
            &mut scan,
        );
        let info = &scan.handlers["admin_tokens_create"][0];
        assert!(info.returns.contains("; 1]"));
        assert!(
            info.body.is_some(),
            "array semicolon must not truncate the fn"
        );

        let responses = success_responses_for(info, &scan);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].status, 201);
        assert_eq!(
            responses[0].body.as_ref().expect("created body").type_,
            "TokenReply"
        );
        assert!(responses[0]
            .headers
            .iter()
            .any(|header| header.name == "Cache-Control"));

        let headers = request_headers_for(
            "POST",
            "/api/admin/tokens",
            Some("admin"),
            false,
            Some(info),
            RequestBodyState::Json,
        );
        assert!(
            !headers
                .iter()
                .any(|header| header.name == "Idempotency-Key"),
            "no-store token responses are intentionally not replayable"
        );
    }

    #[test]
    fn real_token_and_webhook_handlers_keep_conservative_response_facts() {
        let scan = scan_repository(&repo_root()).expect("repository scan must succeed");

        let token = &scan.handlers["admin_tokens_create"][0];
        let token_responses = success_responses_for(token, &scan);
        assert_eq!(token_responses.len(), 1);
        assert_eq!(token_responses[0].status, 201);
        assert!(token_responses[0]
            .headers
            .iter()
            .any(|header| header.name == "Cache-Control"));
        let token_headers = request_headers_for(
            "POST",
            "/api/admin/tokens",
            Some("admin"),
            false,
            Some(token),
            RequestBodyState::Json,
        );
        assert!(!token_headers
            .iter()
            .any(|header| header.name == "Idempotency-Key"));

        let webhook = &scan.handlers["webhook_receive"][0];
        assert!(
            success_responses_for(webhook, &scan).is_empty(),
            "the wrapper exposes a dynamic status but not its helper's 202"
        );
        let webhook_override = success_response_override(Some("webhook_receive"));
        assert_eq!(webhook_override.len(), 1);
        assert_eq!(webhook_override[0].status, 202);
        assert_eq!(webhook_override[0].body_state, ResponseBodyState::Json);
        assert_eq!(
            webhook_override[0]
                .body
                .as_ref()
                .and_then(|body| body.fields.as_ref())
                .expect("curated webhook response fields")[1]
                .name,
            "event_id"
        );

        let live_apply = success_response_override(Some("requests_approve_live_apply"));
        assert_eq!(live_apply.len(), 1);
        assert_eq!(live_apply[0].status, 200);
        assert_eq!(
            live_apply[0]
                .body
                .as_ref()
                .and_then(|body| body.fields.as_ref())
                .expect("curated live-apply response fields")
                .len(),
            4
        );
    }

    #[test]
    fn api_route_serializes_the_additive_contract_fields() {
        let source = r#"
struct Payload { value: String }
struct Reply { id: String }
async fn widget_create(
    Path(id): Path<String>,
    Json(body): Json<Payload>,
) -> Json<Reply> {
    Json(Reply { id })
}
"#;
        let file = "sources/ryuki-api/src/serialization_test.rs";
        let mut scan = SourceScan::default();
        scan_file(source, file, &mut scan);
        let seed = RouteSeed {
            handler: Some("widget_create".to_string()),
            source_file: file,
        };
        let route = build_route(
            "/api/widgets/{id}",
            "POST",
            &seed,
            Some("admin".to_string()),
            false,
            &scan,
        );
        let value = serde_json::to_value(route).expect("route must serialize");
        assert!(value["path_params"].is_array());
        assert_eq!(value["query_params_state"], "none");
        assert!(value["request_headers"].is_array());
        assert_eq!(value["request_body_state"], "json");
        assert!(value["success_responses"].is_array());
        assert_eq!(value["success_responses"][0]["status"], 200);
        assert_eq!(value["success_responses"][0]["body_state"], "json");
        assert_eq!(value["success_responses"][0]["body"]["type"], "Reply");
        assert!(value["success_responses"][0]["body"]["fields"].is_array());
        assert!(
            value.get("response_notes").is_some(),
            "legacy field remains"
        );
    }

    #[test]
    fn first_sentence_splits_on_real_boundaries_only() {
        assert_eq!(
            first_sentence("GET /api/x — the LIVE queue (#29). The table was seeded."),
            "GET /api/x — the LIVE queue (#29)."
        );
        assert_eq!(
            first_sentence("Uses e.g. lowered text before ending. Second."),
            "Uses e.g. lowered text before ending."
        );
        assert_eq!(
            first_sentence("No terminal period at all"),
            "No terminal period at all"
        );
        assert_eq!(
            first_sentence("Multi\nline doc\ncomment. Tail."),
            "Multi line doc comment."
        );
    }

    #[test]
    fn area_titles_humanize_keys_and_uppercase_acronyms() {
        assert_eq!(area_title("cmdb"), "CMDB");
        assert_eq!(area_title("vm"), "VM");
        assert_eq!(area_title("requests"), "Requests");
        assert_eq!(area_title("platform"), "Platform");
    }

    // Smoke gate: the api-doc extraction must see EXACTLY the surface that
    // generate-endpoints-doc publishes, and every curated area description
    // must map to a real area key.
    #[test]
    fn api_doc_routes_match_endpoints_doc_surface() {
        let root = repo_root();
        let mut api_doc_count = 0usize;
        let mut areas: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut routes: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
        for source_path in crate::RUST_API_ROUTE_SOURCES {
            let source = crate::read(&root, source_path).expect("API source must be readable");
            for registration in extract_route_registrations(&source) {
                areas.insert(crate::endpoints_doc_section(&registration.path));
                routes
                    .entry(registration.path)
                    .or_default()
                    .extend(registration.methods.into_iter().map(|entry| entry.method));
            }
        }
        api_doc_count += routes
            .values()
            .map(std::collections::BTreeSet::len)
            .sum::<usize>();
        let (_, endpoints_count) =
            crate::generate_endpoints_doc(&root).expect("endpoints doc must build");
        assert_eq!(api_doc_count, endpoints_count);
        assert_eq!(api_doc_count, 796, "production API route inventory drifted");
        assert!(
            crate::RUST_API_ROUTE_SOURCES.contains(&crate::RUST_API_INTEGRATION_PATH),
            "integration.rs must remain a production route source"
        );
        assert!(
            crate::RUST_API_ROUTE_SOURCES.contains(&crate::RUST_API_INBOUND_WEBHOOKS_PATH),
            "inbound_webhooks.rs must remain a production route source"
        );
        assert!(
            routes["/api/integrations/{id}/webhook-secret"].contains("POST"),
            "integration management routes must be covered"
        );
        assert!(
            routes["/api/integrations/{connection_id}/webhook"].contains("POST"),
            "the inbound webhook route must be covered"
        );

        for (key, _) in AREA_DESCRIPTIONS {
            assert!(
                areas.contains(*key),
                "AREA_DESCRIPTIONS entry '{key}' does not match any extracted area"
            );
        }
    }

    #[test]
    fn api_doc_preserves_canonical_secret_reference_projection_field() {
        let scan = scan_repository(&repo_root()).expect("API sources must be scannable");
        let handler = scan
            .handlers
            .get("catalog_secret_references")
            .and_then(|handlers| {
                handlers
                    .iter()
                    .find(|handler| handler.file == "sources/ryuki-api/src/contracts.rs")
            })
            .expect("secret-reference catalog handler must be indexed");
        let fields = literal_success_response_fields(handler)
            .expect("secret-reference response must have a literal object schema");
        let names: Vec<&str> = fields.iter().map(|field| field.name.as_str()).collect();

        assert!(
            names.contains(&"secretReferenceKinds"),
            "the API projection must retain its canonical field name"
        );
        assert!(
            !names.contains(&"referenceKinds"),
            "the catalog-source field must not leak into the API projection"
        );
    }
}
