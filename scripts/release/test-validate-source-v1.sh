#!/usr/bin/env bash
set -Eeuo pipefail

# Offline regression for validate-source-v1.sh. The signing identity and Git
# repository exist only beneath one private temporary directory and are always
# removed on exit. No private key bytes are printed or exported.

if (( BASH_VERSINFO[0] < 4 )); then
  printf 'SKIP: release-source regression requires Bash 4 or newer (found %s)\n' \
    "${BASH_VERSION}" >&2
  exit 77
fi

for tool in awk base64 git gpg grep mktemp; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    printf 'SKIP: release-source regression requires %s\n' "${tool}" >&2
    exit 77
  fi
done

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
validator="${root_dir}/scripts/release/validate-source-v1.sh"
[[ -f "${validator}" ]] || {
  printf 'not ok - release-source validator is missing\n' >&2
  exit 1
}

umask 077
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/ryuki-release-source-test.XXXXXX")"

cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "${work_dir}"
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

signer_home="${work_dir}/signer-gnupg"
repo="${work_dir}/repo"
mkdir -p "${signer_home}" "${repo}"
chmod 700 "${signer_home}"

signing_identity='Ryuki Release Source Regression <release-source-test@invalid.example>'
if ! GNUPGHOME="${signer_home}" gpg --batch --quiet \
  --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "${signing_identity}" rsa2048 sign 0 \
  >"${work_dir}/keygen.log" 2>&1; then
  printf 'not ok - could not create the disposable signing identity\n' >&2
  exit 1
fi

fingerprint="$({
  GNUPGHOME="${signer_home}" gpg --batch --with-colons \
    --list-secret-keys "${signing_identity}" 2>/dev/null
} | awk -F: '
  $1 == "sec" { want_fingerprint = 1; next }
  want_fingerprint && $1 == "fpr" { print toupper($10); exit }
')"
[[ "${fingerprint}" =~ ^[0-9A-F]{40}$|^[0-9A-F]{64}$ ]] || {
  printf 'not ok - disposable signing identity has no full fingerprint\n' >&2
  exit 1
}

public_key_b64="$({
  GNUPGHOME="${signer_home}" gpg --batch --export "${fingerprint}"
} | base64 | tr -d '\r\n')"
[[ -n "${public_key_b64}" ]] || {
  printf 'not ok - disposable public key export is empty\n' >&2
  exit 1
}

git init --quiet --initial-branch=main "${repo}"
git -C "${repo}" config user.name 'Ryuki Release Source Regression'
git -C "${repo}" config user.email 'release-source-test@invalid.example'
git -C "${repo}" config user.signingkey "${fingerprint}"
git -C "${repo}" config gpg.program gpg
git -C "${repo}" config maintenance.auto false
git -C "${repo}" config gc.auto 0

printf 'trusted main source\n' >"${repo}/source.txt"
git -C "${repo}" add source.txt
git -C "${repo}" commit --quiet -m 'test: trusted main source'
main_commit="$(git -C "${repo}" rev-parse HEAD)"
# The production checkout obtains this remote-tracking ref via fetch-depth: 0.
# A direct ref creates the same ancestry input without requiring a network.
git -C "${repo}" update-ref refs/remotes/origin/main "${main_commit}"

git -C "${repo}" tag v1.0.0 "${main_commit}"

git -C "${repo}" switch --quiet -c untrusted-side-branch
printf 'side branch source\n' >>"${repo}/source.txt"
git -C "${repo}" commit --quiet -am 'test: side branch source'
side_commit="$(git -C "${repo}" rev-parse HEAD)"
GNUPGHOME="${signer_home}" git -C "${repo}" tag --sign v1.0.1 \
  --message 'signed side branch release' "${side_commit}"

git -C "${repo}" switch --quiet main
GNUPGHOME="${signer_home}" git -C "${repo}" tag --sign v01.0.2 \
  --message 'signed malformed release tag' "${main_commit}"
GNUPGHOME="${signer_home}" git -C "${repo}" tag --sign v1.0.2 \
  --message 'signed trusted main release' "${main_commit}"

run_validator() {
  local release_tag="$1"
  local release_sha="$2"
  local github_output="$3"
  (
    cd "${repo}"
    RELEASE_TAG="${release_tag}" \
      RELEASE_SHA="${release_sha}" \
      RELEASE_SIGNING_FINGERPRINT="${fingerprint}" \
      RELEASE_SIGNING_PUBLIC_KEY_B64="${public_key_b64}" \
      GITHUB_OUTPUT="${github_output}" \
      bash "${validator}"
  )
}

expect_rejected() {
  local label="$1"
  local release_tag="$2"
  local release_sha="$3"
  local expected_error="$4"
  local output="${work_dir}/${label}.output"
  local log="${work_dir}/${label}.log"
  : >"${output}"

  if run_validator "${release_tag}" "${release_sha}" "${output}" \
    >"${log}" 2>&1; then
    printf 'not ok - %s was accepted\n' "${label}" >&2
    exit 1
  fi
  if ! grep -Fq "${expected_error}" "${log}"; then
    printf 'not ok - %s failed for an unexpected reason\n' "${label}" >&2
    sed -n '1,20p' "${log}" >&2
    exit 1
  fi
  [[ ! -s "${output}" ]] || {
    printf 'not ok - %s emitted trusted provenance outputs\n' "${label}" >&2
    exit 1
  }
  printf 'ok - %s rejected\n' "${label}"
}

expect_rejected \
  lightweight-unsigned-tag \
  v1.0.0 \
  "${main_commit}" \
  'Release tag must be annotated; lightweight tags are forbidden'
expect_rejected \
  signed-side-branch-tag \
  v1.0.1 \
  "${side_commit}" \
  'Release commit is not contained in origin/main'
expect_rejected \
  malformed-provenance \
  v01.0.2 \
  "${main_commit}" \
  'Release tag must be an exact v-prefixed SemVer'

valid_output="${work_dir}/valid-main.output"
: >"${valid_output}"
if ! run_validator v1.0.2 "${main_commit}" "${valid_output}" \
  >"${work_dir}/valid-main.log" 2>&1; then
  printf 'not ok - valid signed main tag was rejected\n' >&2
  sed -n '1,20p' "${work_dir}/valid-main.log" >&2
  exit 1
fi

valid_tag_object="$(git -C "${repo}" rev-parse refs/tags/v1.0.2)"
grep -Fxq "commit-sha=${main_commit}" "${valid_output}" || {
  printf 'not ok - valid signed main tag emitted the wrong commit\n' >&2
  exit 1
}
grep -Fxq "tag-object-sha=${valid_tag_object}" "${valid_output}" || {
  printf 'not ok - valid signed main tag emitted the wrong tag object\n' >&2
  exit 1
}
printf 'ok - valid signed main tag accepted with exact provenance outputs\n'
