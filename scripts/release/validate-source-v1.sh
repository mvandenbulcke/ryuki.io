#!/usr/bin/env bash
# Versioned release-source trust control. Changes require an explicit validator
# digest update and security review.
set -euo pipefail

fail() {
  echo "::error::$1"
  exit 1
}

semver_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
[[ "${RELEASE_TAG}" =~ ${semver_re} ]] || \
  fail "Release tag must be an exact v-prefixed SemVer"
[[ "${RELEASE_SHA}" =~ ^[0-9a-f]{40}$ ]] || \
  fail "Release event SHA must be a full lowercase commit SHA"

tag_ref="refs/tags/${RELEASE_TAG}"
tag_object="$(git show-ref --verify --hash "${tag_ref}")" || \
  fail "Release tag ref is missing from the authenticated checkout"
[[ "${tag_object}" =~ ^[0-9a-f]{40}$ ]] || \
  fail "Release tag object must have one full lowercase object ID"
[[ "$(git cat-file -t "${tag_object}")" == "tag" ]] || \
  fail "Release tag must be annotated; lightweight tags are forbidden"
signed_tag_name="$(
  git cat-file tag "${tag_object}" |
    awk '
      BEGIN { in_header = 1 }
      in_header && /^$/ { in_header = 0; next }
      in_header && /^tag / {
        if (found) {
          invalid = 1
          next
        }
        found = 1
        name = substr($0, 5)
      }
      END {
        if (!found || invalid) {
          exit 1
        }
        print name
      }
    '
)" || fail "Release tag object has an invalid signed tag name"
[[ "${signed_tag_name}" == "${RELEASE_TAG}" ]] || \
  fail "Release tag ref name does not match the signed tag name"

expected_fingerprint="$(printf '%s' "${RELEASE_SIGNING_FINGERPRINT}" | tr '[:lower:]' '[:upper:]')"
[[ "${expected_fingerprint}" =~ ^([0-9A-F]{40}|[0-9A-F]{64})$ ]] || \
  fail "RELEASE_SIGNING_FINGERPRINT must name one full OpenPGP fingerprint"
[[ -n "${RELEASE_SIGNING_PUBLIC_KEY_B64}" ]] || \
  fail "RELEASE_SIGNING_PUBLIC_KEY_B64 release trust policy is not configured"

signing_key="$(mktemp)"
export GNUPGHOME
GNUPGHOME="$(mktemp -d)"
trap 'rm -f "${signing_key}"; rm -rf "${GNUPGHOME}"' EXIT
chmod 700 "${GNUPGHOME}"
printf '%s' "${RELEASE_SIGNING_PUBLIC_KEY_B64}" | base64 --decode > "${signing_key}" || \
  fail "Release signing public key is not valid base64"

mapfile -t policy_fingerprints < <(
  gpg --batch --with-colons --import-options show-only --import "${signing_key}" |
    awk -F: '$1 == "pub" { want_fingerprint = 1; next } want_fingerprint && $1 == "fpr" { print toupper($10); want_fingerprint = 0 }'
)
[[ "${#policy_fingerprints[@]}" -eq 1 ]] || \
  fail "Release signing policy must contain exactly one primary public key"
[[ "${policy_fingerprints[0]}" == "${expected_fingerprint}" ]] || \
  fail "Release signing public key does not match the configured fingerprint"
gpg --batch --import "${signing_key}" >/dev/null 2>&1 || \
  fail "Release signing public key could not be imported"

verification_status="$(git -c gpg.program=gpg verify-tag --raw "${tag_object}" 2>&1)" || {
  printf '%s\n' "${verification_status}" >&2
  fail "Release tag signature is missing or invalid"
}
if printf '%s\n' "${verification_status}" | grep -Eq \
  '^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED|KEYREVOKED|NO_PUBKEY|NODATA|FAILURE)( |$)'; then
  printf '%s\n' "${verification_status}" >&2
  fail "Release tag signature or signing key is unusable"
fi
mapfile -t good_signatures < <(
  printf '%s\n' "${verification_status}" |
    awk '/^\[GNUPG:\] GOODSIG / { print $3 }'
)
[[ "${#good_signatures[@]}" -eq 1 ]] || \
  fail "Release tag must contain exactly one good signature"
mapfile -t valid_signers < <(
  printf '%s\n' "${verification_status}" |
    awk '/^\[GNUPG:\] VALIDSIG / { print toupper($3) " " toupper($NF) }'
)
[[ "${#valid_signers[@]}" -eq 1 ]] || \
  fail "Release tag must contain exactly one valid configured signature"
[[ " ${valid_signers[0]} " == *" ${expected_fingerprint} "* ]] || \
  fail "Release tag was not signed by the configured release identity"

tag_commit="$(git rev-parse "${tag_object}^{commit}")"
event_commit="$(git rev-parse "${RELEASE_SHA}^{commit}")"
[[ "${tag_commit}" == "${event_commit}" ]] || \
  fail "Release tag commit does not match the event SHA"
# fetch-depth: 0 populated all authenticated remote branches before checkout
# removed its temporary credential from Git configuration.
git show-ref --verify --quiet refs/remotes/origin/main
if ! git merge-base --is-ancestor "${tag_commit}" origin/main; then
  fail "Release commit is not contained in origin/main"
fi
{
  printf 'commit-sha=%s\n' "${tag_commit}"
  printf 'tag-object-sha=%s\n' "${tag_object}"
} >> "${GITHUB_OUTPUT}"
