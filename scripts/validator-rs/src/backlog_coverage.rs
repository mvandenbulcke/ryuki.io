use std::fs;
use std::path::Path;

pub fn validate_context_file(path: &Path) -> Result<Vec<String>, String> {
    let _payload = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    Ok(Vec::new())
}
