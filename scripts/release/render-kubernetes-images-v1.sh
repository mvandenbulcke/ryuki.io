#!/usr/bin/env bash
# Deterministic release-image render. This replaces only the reviewed image
# placeholders and the platform-api digest-derived migration identity. It does
# not claim registry provenance, admission, or running-image readback.
set -euo pipefail

fail() {
  echo "::error::$1" >&2
  exit 1
}

root=""
output=""
api_repository=""
api_digest=""
portal_repository=""
portal_digest=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --root)
      [[ "$#" -ge 2 ]] || fail "--root requires a value"
      root="$2"
      shift 2
      ;;
    --output)
      [[ "$#" -ge 2 ]] || fail "--output requires a value"
      output="$2"
      shift 2
      ;;
    --api-repository)
      [[ "$#" -ge 2 ]] || fail "--api-repository requires a value"
      api_repository="$2"
      shift 2
      ;;
    --api-digest)
      [[ "$#" -ge 2 ]] || fail "--api-digest requires a value"
      api_digest="$2"
      shift 2
      ;;
    --portal-repository)
      [[ "$#" -ge 2 ]] || fail "--portal-repository requires a value"
      portal_repository="$2"
      shift 2
      ;;
    --portal-digest)
      [[ "$#" -ge 2 ]] || fail "--portal-digest requires a value"
      portal_digest="$2"
      shift 2
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -d "${root}" ]] || fail "--root must name the checked-out repository"
[[ -n "${output}" ]] || fail "--output is required"

digest_re='^sha256:[0-9a-f]{64}$'
repository_re='^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(/[a-z0-9]+([._-][a-z0-9]+)*)+$'
for name in api portal; do
  if [[ "${name}" == "api" ]]; then
    repository="${api_repository}"
    digest="${api_digest}"
  else
    repository="${portal_repository}"
    digest="${portal_digest}"
  fi
  [[ "${repository}" =~ ${repository_re} ]] || \
    fail "${name} repository must be a lowercase qualified registry/repository without a tag or digest"
  [[ "${repository}" != registry.example.invalid/* ]] || \
    fail "${name} repository must not use the reserved registry.example.invalid fixture"
  [[ "${digest}" =~ ${digest_re} ]] || \
    fail "${name} digest must be sha256 followed by 64 lowercase hexadecimal characters"
  [[ "${digest}" != "sha256:$(printf '0%.0s' {1..64})" ]] || \
    fail "${name} digest must not use the all-zero source-template sentinel"
done
[[ "${api_digest}" != "${portal_digest}" ]] || \
  fail "API and portal releases must have distinct image digests"

api_image="${api_repository}@${api_digest}"
portal_image="${portal_repository}@${portal_digest}"
api_digest_prefix="${api_digest#sha256:}"
api_digest_prefix="${api_digest_prefix:0:12}"

api_image_placeholder="registry.example.invalid/ryuki/platform-api@sha256:1111111111111111111111111111111111111111111111111111111111111111"
portal_image_placeholder="registry.example.invalid/ryuki/portal-ui@sha256:0000000000000000000000000000000000000000000000000000000000000000"
api_prefix_placeholder="111111111111"
manifest_paths=(
  "deploy/kubernetes/base/namespace.yaml"
  "deploy/kubernetes/base/serviceaccounts.yaml"
  "deploy/kubernetes/base/configmap.yaml"
  "deploy/kubernetes/base/deployments.yaml"
  "deploy/kubernetes/base/services.yaml"
  "deploy/kubernetes/base/ingress.yaml"
  "deploy/kubernetes/base/networkpolicies.yaml"
  "deploy/kubernetes/operations/migration-job.yaml"
  "deploy/kubernetes/vault/workload-auth.yaml"
)

output_parent="$(dirname "${output}")"
[[ -d "${output_parent}" ]] || fail "output parent directory does not exist: ${output_parent}"
[[ ! -L "${output}" ]] || fail "output must not be a symbolic link"
temporary="${output}.tmp"
[[ ! -e "${temporary}" ]] || fail "temporary output already exists: ${temporary}"
trap 'rm -f "${temporary}"' EXIT
umask 077

api_image_replacements=0
portal_image_replacements=0
api_prefix_replacements=0
first_file=true
{
  for relative_path in "${manifest_paths[@]}"; do
    input="${root}/${relative_path}"
    [[ -f "${input}" && ! -L "${input}" ]] || \
      fail "release render input must be a regular file: ${relative_path}"
    if [[ "${first_file}" == false ]]; then
      printf '%s\n' '---'
    fi
    first_file=false

    while IFS= read -r line || [[ -n "${line}" ]]; do
      if [[ "${line}" == *"${api_image_placeholder}"* ]]; then
        api_image_replacements=$((api_image_replacements + 1))
        line="${line//${api_image_placeholder}/${api_image}}"
      fi
      if [[ "${line}" == *"${portal_image_placeholder}"* ]]; then
        portal_image_replacements=$((portal_image_replacements + 1))
        line="${line//${portal_image_placeholder}/${portal_image}}"
      fi
      if [[ "${relative_path}" == "deploy/kubernetes/operations/migration-job.yaml" \
        && "${line}" == *"${api_prefix_placeholder}"* ]]; then
        api_prefix_replacements=$((api_prefix_replacements + 1))
        line="${line//${api_prefix_placeholder}/${api_digest_prefix}}"
      fi
      printf '%s\n' "${line}"
    done < "${input}"
  done
} > "${temporary}"

[[ "${api_image_replacements}" -eq 3 ]] || \
  fail "expected exactly three platform-api image placeholders; found ${api_image_replacements}"
[[ "${portal_image_replacements}" -eq 1 ]] || \
  fail "expected exactly one portal-ui image placeholder; found ${portal_image_replacements}"
[[ "${api_prefix_replacements}" -gt 0 ]] || \
  fail "platform-api migration identity placeholder was not found"
if grep -Fq "${api_image_placeholder}" "${temporary}" \
  || grep -Fq "${portal_image_placeholder}" "${temporary}" \
  || grep -Fq "${api_prefix_placeholder}" "${temporary}"; then
  fail "release render retained an image or migration identity placeholder"
fi

mv "${temporary}" "${output}"
trap - EXIT
