#!/usr/bin/env bash
# Versioned release-note handoff control. Changes require an explicit validator
# digest update and security review.
set -euo pipefail

[[ -n "${RAW_NOTES}" ]] || {
  echo "::error::Generated release notes are empty"
  exit 1
}
note_bytes="$(printf '%s' "${RAW_NOTES}" | LC_ALL=C wc -c | tr -d '[:space:]')"
[[ "${note_bytes}" =~ ^[0-9]+$ && "${note_bytes}" -le 131072 ]] || {
  echo "::error::Generated release notes exceed the 128 KiB handoff limit"
  exit 1
}
version="${RELEASE_TAG#v}"
first_heading="$(printf '%s\n' "${RAW_NOTES}" | awk 'NF { print; exit }')"
[[ "${first_heading}" == "## [${version}]"* ]] || {
  echo "::error::Generated release notes do not match the validated tag"
  exit 1
}
encoded="$(printf '%s' "${RAW_NOTES}" | base64 -w 0)"
printf 'content-b64=%s\n' "${encoded}" >> "${GITHUB_OUTPUT}"
