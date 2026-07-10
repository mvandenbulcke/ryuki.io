#!/usr/bin/env bash
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  printf 'rg is required for no-secret-scan\n' >&2
  exit 2
fi

paths=("$@")
if [ "${#paths[@]}" -eq 0 ]; then
  # Default scope includes existing paths plus Rust source crates under sources/
  source_crates=()
  for d in sources/ryuki-*/; do
    [ -d "$d" ] && source_crates+=("$d")
  done
  paths=(docs catalog fixtures scripts deploy portal "${source_crates[@]}")
fi

patterns=(
  'AKIA[0-9A-Z]{16}'
  '-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'
  'xox[baprs]-[0-9A-Za-z-]+'
  'gh[pousr]_[0-9A-Za-z_]{36,255}'
  'AIza[0-9A-Za-z_-]{35}'
  '(?i)(password|passwd|pwd|client_secret|secret_key|access_token|refresh_token|bearer)[[:space:]]*[:=][[:space:]]*["'\''`]?[^[:space:]"'\''`]{8,}'
  'ryk_[A-Za-z0-9_-]{20,}'
)

pattern_names=(
  'AWS access key'
  'private key block'
  'Slack token'
  'GitHub token'
  'Google API key'
  'secret assignment'
  'Ryuki API token'
)

# Inline allowlist marker. A line carrying this marker is exempt from the
# heuristic "secret assignment" check ONLY. Use it for a reviewed provider
# argument that references a variable rather than a literal credential. The
# marker stays visible in every diff, so suppression is explicit and auditable.
# High-confidence formats are never suppressible.
allow_marker='secret-scan-allow'

found_any=false

for i in "${!patterns[@]}"; do
  pattern="${patterns[$i]}"
  category="${pattern_names[$i]}"

  # The heuristic category supports inline suppressions. Candidate content is
  # filtered in memory; diagnostics name only the category and file so a secret
  # can never be copied into local or CI logs.
  if [ "$category" = "secret assignment" ]; then
    set +e
    candidate_files=$(rg --hidden --glob '!.git/**' --files-with-matches -- "$pattern" "${paths[@]}" 2>/dev/null)
    status=$?
    set -e

    if [ "$status" -gt 1 ]; then
      printf 'No-secret scan failed while reading scoped paths.\n' >&2
      exit "$status"
    fi

    if [ "$status" -eq 0 ] && [ -n "$candidate_files" ]; then
      while IFS= read -r file; do
        [ -z "$file" ] && continue
        raw=$(rg --no-heading -- "$pattern" "$file" 2>/dev/null || true)
        flagged=$(printf '%s\n' "$raw" | rg --invert-match -- "$allow_marker" || true)
        if [ -n "$flagged" ]; then
          found_any=true
          printf 'category=%s path=%s\n' "$category" "$file" >&2
        fi
      done <<< "$candidate_files"
    fi

    continue
  fi

  set +e
  matched_files=$(rg --hidden --glob '!.git/**' --files-with-matches -- "$pattern" "${paths[@]}" 2>/dev/null)
  status=$?
  set -e

  if [ "$status" -eq 0 ] && [ -n "$matched_files" ]; then
    found_any=true
    while IFS= read -r file; do
      printf 'category=%s path=%s\n' "$category" "$file" >&2
    done <<< "$matched_files"
  fi

  if [ "$status" -gt 1 ]; then
    printf 'No-secret scan failed while reading scoped paths.\n' >&2
    exit "$status"
  fi
done

if [ "$found_any" = true ]; then
  exit 1
fi

printf 'No secret patterns found in scoped paths: %s\n' "${paths[*]}"
