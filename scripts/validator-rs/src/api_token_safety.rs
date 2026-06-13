//! API-token literal safety scan (design doc feature 3).
//!
//! A minted API token is `ryk_<43 base64url chars>` — 256 bits of CSPRNG
//! entropy. The plaintext is returned exactly once at creation and is NEVER
//! persisted; only its SHA-256 hash is stored. This slice enforces that no real
//! minted token literal is ever committed to the repository's data artifacts:
//! it scans `migrations/` and `fixtures/` and FAILS if any file contains a
//! `ryk_` followed by 20+ token-ish characters.
//!
//! The bare prefix string `ryk_` (the dispatch discriminator) and the
//! `strip_prefix("ryk_")` source idiom are intentionally NOT flagged: source
//! directories are out of scope of this scan (only `migrations/` and
//! `fixtures/` are walked), and a bare `ryk_` with fewer than 20 following
//! token chars never matches.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

/// Directories whose file CONTENTS are scanned for committed token literals.
const SCANNED_DIRS: &[&str] = &["migrations", "fixtures"];

/// Minimum count of token-ish chars after `ryk_` for a match to be treated as a
/// real minted token (a genuine token has 43). Below this threshold the bare
/// `ryk_` prefix and short illustrative strings are allowed.
const MIN_TOKEN_CHARS: usize = 20;

#[derive(Debug, Deserialize)]
struct Context {
    /// Repository root to scan, relative or absolute.
    root: String,
}

/// Returns true if `text` contains a `ryk_` immediately followed by at least
/// `MIN_TOKEN_CHARS` characters from the base64url/token alphabet
/// (`[A-Za-z0-9_-]`). Equivalent to the regex `ryk_[A-Za-z0-9_-]{20,}`.
pub fn contains_token_literal(text: &str) -> bool {
    let bytes = text.as_bytes();
    let needle = b"ryk_";
    let mut i = 0;
    while i + needle.len() <= bytes.len() {
        if &bytes[i..i + needle.len()] == needle {
            let mut run = 0usize;
            let mut j = i + needle.len();
            while j < bytes.len() && is_token_char(bytes[j]) {
                run += 1;
                j += 1;
            }
            if run >= MIN_TOKEN_CHARS {
                return true;
            }
            // Skip past this prefix occurrence; the run we just measured can be
            // reused (overlapping `ryk_` inside a token run is not meaningful).
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Recursively collects every regular file under `dir`.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    let entries =
        fs::read_dir(dir).map_err(|error| format!("failed to read {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("failed to read dir entry: {error}"))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// Scans the configured data-artifact directories under `root` for committed
/// `ryk_` token literals. Returns one error string per offending file.
pub fn scan_root(root: &Path) -> Result<Vec<String>, String> {
    let mut errors = Vec::new();
    for dir_name in SCANNED_DIRS {
        let dir = root.join(dir_name);
        let mut files = Vec::new();
        collect_files(&dir, &mut files)?;
        for file in files {
            // Files may be non-UTF-8 (unlikely under migrations/fixtures); skip
            // any that cannot be read as text rather than failing the scan.
            let Ok(contents) = fs::read_to_string(&file) else {
                continue;
            };
            if contains_token_literal(&contents) {
                errors.push(format!(
                    "committed API token literal (ryk_…) found in {}: minted tokens must never be \
                     committed — generate them at runtime",
                    file.display()
                ));
            }
        }
    }
    Ok(errors)
}

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let context: Context = serde_json::from_str(&payload)
        .map_err(|error| format!("invalid api-token-safety context JSON: {error}"))?;
    scan_root(Path::new(&context.root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn allows_bare_prefix_and_strip_idiom() {
        // The bare dispatch discriminator and the source idiom are allowed.
        assert!(!contains_token_literal("ryk_"));
        assert!(!contains_token_literal(r#"token.strip_prefix("ryk_")"#));
        assert!(!contains_token_literal("the ryk_ prefix"));
        // A short illustrative suffix (< 20 chars) is allowed.
        assert!(!contains_token_literal("ryk_abc123"));
    }

    #[test]
    fn flags_real_token_literal() {
        // A 43-char base64url suffix is unambiguously a minted token.
        let planted = format!("token = \"ryk_{}\"", "A".repeat(43));
        assert!(contains_token_literal(&planted));
        // Exactly the 20-char threshold matches.
        assert!(contains_token_literal(&format!("ryk_{}", "a".repeat(20))));
        // 19 chars does not.
        assert!(!contains_token_literal(&format!("ryk_{}", "a".repeat(19))));
    }

    #[test]
    fn clean_dir_passes() {
        let tmp = std::env::temp_dir().join(format!("ryk-clean-{}", std::process::id()));
        let migrations = tmp.join("migrations");
        fs::create_dir_all(&migrations).unwrap();
        fs::write(
            migrations.join("001.sql"),
            "CREATE TABLE api_tokens (token_hash TEXT NOT NULL); -- ryk_ prefix is the discriminator",
        )
        .unwrap();
        let errors = scan_root(&tmp).unwrap();
        fs::remove_dir_all(&tmp).ok();
        assert!(errors.is_empty(), "clean dir should pass: {errors:?}");
    }

    #[test]
    fn planted_literal_fails() {
        let tmp = std::env::temp_dir().join(format!("ryk-planted-{}", std::process::id()));
        let fixtures = tmp.join("fixtures");
        fs::create_dir_all(&fixtures).unwrap();
        let planted = format!("ryk_{}", "Z".repeat(43));
        fs::write(
            fixtures.join("seed.json"),
            format!("{{\"token\":\"{planted}\"}}"),
        )
        .unwrap();
        let errors = scan_root(&tmp).unwrap();
        fs::remove_dir_all(&tmp).ok();
        assert_eq!(errors.len(), 1, "planted literal should fail: {errors:?}");
        assert!(errors[0].contains("committed API token literal"));
    }
}
