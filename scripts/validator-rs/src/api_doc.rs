//! `generate-api-doc` — the extraction layer behind `docs/api/api-doc.json`
//! and `docs/api/openapi.json`.
//!
//! Design contract (no invented facts — every field is read from code or is
//! explicitly `null`):
//!
//! * Routes come from the SAME `.route("path", get(handler))` registrations
//!   (and the same three source files) as `generate-endpoints-doc`, extended
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
//! * Handler summaries/descriptions are the handler's own `///` doc comment
//!   (summary = first sentence). Missing doc => `null`.
//! * `query_params` / `request_body` come from the `Query<T>` / `Json<T>`
//!   extractors in the handler signature; `T`'s field list is parsed from its
//!   `struct` definition (name honours `#[serde(rename)]` / `rename_all`,
//!   `optional` = `Option<...>` or `#[serde(default)]`). Unfindable or
//!   non-struct types degrade to `null` fields, never guesses.
//! * `response_notes` uses only unambiguous body/signature evidence:
//!   `total_count_headers(` (bare array + X-Total-Count), `add_page_meta(` or
//!   inline `"total"/"limit"/"offset"` keys (paginated object), and a
//!   `ProblemDetails`/`Json<ApiError>` error arm (RFC 9457-shaped error body,
//!   matching the wording of the curated OpenAPI document).
//! * Area keys reuse `endpoints_doc_section` verbatim; per-area descriptions
//!   are a curated, evidence-based table (route inventory, handler docs,
//!   `docs/*.md` guides). Areas without evidence get the plain
//!   "Routes for <Title>." placeholder.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use serde::Serialize;

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
    body_flags: BodyFlags,
}

#[derive(Clone, Copy, Default)]
struct BodyFlags {
    total_count_headers: bool,
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
    let name: String = after[rel..].chars().take_while(|c| is_ident_char(*c)).collect();
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
    let end = match find_code_char(chars, cursor, &['{', ';']) {
        Some(idx) if chars[idx] == '{' => {
            if !generic {
                info.returns = chars[cursor..idx].iter().collect();
            }
            let close = matching_delimiter(chars, idx, '{', '}').unwrap_or(chars.len() - 1);
            let body: String = chars[idx + 1..close].iter().collect();
            let body = crate::strip_source_comments(&body);
            info.body_flags = BodyFlags {
                total_count_headers: body.contains("total_count_headers("),
                paginated_object: body.contains("add_page_meta(")
                    || (body.contains("\"total\":")
                        && body.contains("\"limit\":")
                        && body.contains("\"offset\":")),
            };
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
        (Some(parse_struct_fields(&body, rename_all.as_deref())), close)
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
    match ty.strip_prefix("Option<").and_then(|rest| rest.strip_suffix('>')) {
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
    let plain = !ty.is_empty()
        && ty
            .chars()
            .all(|ch| is_ident_char(ch) || ch == ':');
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
    summary: Option<String>,
    description: Option<String>,
    query_params: Option<Vec<ApiField>>,
    request_body: Option<ApiRequestBody>,
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
    (
        "images",
        "Contract endpoint for the golden-image factory.",
    ),
    (
        "integrations",
        "Adapter readiness and contract-test surface for external providers (backup, \
         monitoring, virtualization, ITSM), reporting per-provider readiness.",
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
    let (query_params, request_body, response_notes) = match handler_info {
        Some(info) => (
            query_params_for(info, scan),
            request_body_for(info, scan),
            response_notes_for(info),
        ),
        None => (None, None, None),
    };
    ApiRoute {
        method: method.to_string(),
        path: path.to_string(),
        tier,
        auth_exempt,
        handler: seed.handler.clone(),
        summary: doc.as_deref().map(first_sentence),
        description: doc,
        query_params,
        request_body,
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

fn query_params_for(info: &HandlerInfo, scan: &SourceScan) -> Option<Vec<ApiField>> {
    let params = info.params.as_deref()?;
    let ty = extractor_type(params, "Query")?;
    resolve_struct(scan, &ty, &info.file)
        .and_then(|found| found.fields.clone())
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
    if info.body_flags.total_count_headers {
        notes.push(
            "Returns a bare JSON array; the filtered total is exposed via the \
             X-Total-Count response header.",
        );
    }
    if info.body_flags.paginated_object {
        notes.push("Returns a paginated JSON object with total/limit/offset keys.");
    }
    if info.returns.contains("ProblemDetails") || info.returns.contains("Json<ApiError>") {
        notes.push(
            "Error responses use the RFC 9457-shaped error body (error, message, \
             optional detail).",
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
        // the comment-only add_page_meta mention is stripped before flag scans
        assert!(!create.body_flags.paginated_object);

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
        let by_name: BTreeMap<&str, &ApiField> =
            fields.iter().map(|field| (field.name.as_str(), field)).collect();
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
        assert_eq!(trapped[0].type_, "std::collections::BTreeMap<String, String>");
        assert!(trapped[0].optional, "serde default implies optional");

        assert!(scan.structs["Tuple"][0].fields.is_none());
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
        assert_eq!(first_sentence("No terminal period at all"), "No terminal period at all");
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
        api_doc_count += routes.values().map(std::collections::BTreeSet::len).sum::<usize>();
        let (_, endpoints_count) =
            crate::generate_endpoints_doc(&root).expect("endpoints doc must build");
        assert_eq!(api_doc_count, endpoints_count);

        for (key, _) in AREA_DESCRIPTIONS {
            assert!(
                areas.contains(*key),
                "AREA_DESCRIPTIONS entry '{key}' does not match any extracted area"
            );
        }
    }
}
