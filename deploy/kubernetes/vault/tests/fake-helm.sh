#!/usr/bin/env bash
set -Eeuo pipefail

: "${FAKE_HELM_LOG:?set FAKE_HELM_LOG}"
: "${FAKE_CHART_VERSION:?set FAKE_CHART_VERSION}"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

case "${1:-}" in
  show)
    [[ "${2:-}" == "chart" && "$#" -eq 3 ]] || exit 90
    operation="show"
    archive="$3"
    ;;
  template)
    [[ "${2:-}" == "vault" && "$#" -ge 3 ]] || exit 91
    operation="template"
    archive="$3"
    ;;
  lint)
    [[ "$#" -ge 2 ]] || exit 92
    operation="lint"
    archive="$2"
    ;;
  upgrade)
    [[ "${2:-}" == "--install" && "${3:-}" == "vault" && "$#" -ge 4 ]] || exit 93
    operation="upgrade"
    archive="$4"
    ;;
  *) exit 94 ;;
esac

[[ -f "$archive" ]] || exit 95
[[ "$archive" != "${FAKE_ORIGINAL_ARCHIVE:-}" ]] || exit 96
printf '%s|%s|%s\n' "$operation" "$archive" "$(sha256_file "$archive")" >>"$FAKE_HELM_LOG"

if [[ "$operation" == "show" ]]; then
  if [[ -n "${FAKE_ORIGINAL_ARCHIVE:-}" ]]; then
    printf 'mutated-untrusted-source\n' >"$FAKE_ORIGINAL_ARCHIVE"
  fi
  printf 'apiVersion: v2\nname: vault\nversion: %s\n' "$FAKE_CHART_VERSION"
fi

if [[ "${FAKE_TAMPER_SNAPSHOT_ON:-}" == "$operation" ]]; then
  chmod u+w "$archive"
  printf 'tampered-private-snapshot\n' >"$archive"
fi
