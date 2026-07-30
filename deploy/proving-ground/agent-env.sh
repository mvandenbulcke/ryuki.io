#!/usr/bin/env bash
# Parse only the values the host-side execution agent needs. Values are
# treated as literal text: this file never evals or sources the Compose env.

validate_private_agent_env_file() {
  local env_file="${1:?environment file path required}"
  local mode

  if mode="$(stat -f '%Lp' "$env_file" 2>/dev/null)"; then
    :
  elif mode="$(stat -c '%a' "$env_file" 2>/dev/null)"; then
    :
  else
    printf 'error: cannot inspect environment file permissions: %s\n' "$env_file" >&2
    return 1
  fi

  case "$mode" in
    '' | *[!0-7]*)
      printf 'error: invalid environment file permissions for %s\n' "$env_file" >&2
      return 1
      ;;
  esac
  if (( (8#$mode & 077) != 0 )); then
    printf 'error: environment file must not be accessible by group or others: %s\n' \
      "$env_file" >&2
    return 1
  fi
}

validate_private_agent_state_dir() {
  local state_dir="${1:?agent state directory required}"
  local stat_fields mode owner effective_uid

  [[ "$state_dir" == /* ]] || {
    printf 'error: agent state directory must be an absolute path\n' >&2
    return 1
  }
  [[ ! -L "$state_dir" && -d "$state_dir" ]] || {
    printf 'error: agent state directory must be a real directory: %s\n' \
      "$state_dir" >&2
    return 1
  }
  if stat_fields="$(stat -f '%Lp %u' "$state_dir" 2>/dev/null)"; then
    :
  elif stat_fields="$(stat -c '%a %u' "$state_dir" 2>/dev/null)"; then
    :
  else
    printf 'error: cannot inspect agent state directory: %s\n' "$state_dir" >&2
    return 1
  fi
  read -r mode owner <<< "$stat_fields"
  [[ "$mode" =~ ^[0-7]+$ && "$owner" =~ ^[0-9]+$ ]] || {
    printf 'error: invalid agent state directory metadata: %s\n' "$state_dir" >&2
    return 1
  }
  effective_uid="$(id -u)" || return 1
  ((owner == effective_uid)) || {
    printf 'error: agent state directory must be owned by the current user: %s\n' \
      "$state_dir" >&2
    return 1
  }
  (( (8#$mode & 077) == 0 )) || {
    printf 'error: agent state directory must not be accessible by group or others: %s\n' \
      "$state_dir" >&2
    return 1
  }
}

# The staging command accepts an already-authenticated PlatformAdmin session
# only through a private one-line curl header file. This prevents shell history,
# process arguments, and the proving-ground .env from becoming credential
# carriers, and rejects management UUIDs or injected extra headers.
validate_agent_enrollment_session_header() {
  local header_file="${1:?session header file required}"
  local stat_fields owner effective_uid byte_count
  local header_line="" extra_line="" has_extra_line=false

  [[ "$header_file" == /* ]] || {
    printf 'error: enrollment session header file must use an absolute path\n' >&2
    return 1
  }
  [[ ! -L "$header_file" && -f "$header_file" && -r "$header_file" ]] || {
    printf 'error: enrollment session header must be one readable regular file\n' >&2
    return 1
  }
  validate_private_agent_env_file "$header_file" || return 1
  if stat_fields="$(stat -f '%u' "$header_file" 2>/dev/null)"; then
    :
  elif stat_fields="$(stat -c '%u' "$header_file" 2>/dev/null)"; then
    :
  else
    printf 'error: cannot inspect enrollment session header ownership\n' >&2
    return 1
  fi
  owner="$stat_fields"
  effective_uid="$(id -u)" || return 1
  [[ "$owner" =~ ^[0-9]+$ ]] && ((owner == effective_uid)) || {
    printf 'error: enrollment session header must be owned by the current user\n' >&2
    return 1
  }
  # macOS ships Bash 3.2, which has no `mapfile`. Read through one shared file
  # descriptor so a second (even empty) line is detected without a subshell.
  {
    if IFS= read -r header_line; then
      :
    elif [[ -z "$header_line" ]]; then
      printf 'error: enrollment session header must not be empty\n' >&2
      return 1
    fi
    if IFS= read -r extra_line; then
      has_extra_line=true
    elif [[ -n "$extra_line" ]]; then
      has_extra_line=true
    fi
  } < "$header_file"
  byte_count="$(wc -c < "$header_file")" || return 1
  byte_count="${byte_count//[[:space:]]/}"
  if [[ "$byte_count" != "67" && "$byte_count" != "68" ]] || \
     [[ "$has_extra_line" == "true" || \
        ! "$header_line" =~ ^X-Ryuki-Session-Id:\ rys_[A-Za-z0-9_-]{43}$ ]]; then
    printf 'error: enrollment session header must contain exactly one canonical rys_ bearer\n' >&2
    return 1
  fi
}

# Validate the one-time API response before exposing either field to the agent.
# Unknown fields, a mismatched identity/platform, or non-canonical material all
# fail closed. The server remains authoritative for expiry and atomic consume.
validate_staged_agent_enrollment() {
  local enrollment_file="${1:?staged enrollment file required}"
  local expected_agent_id="${2:?expected agent id required}"
  local expected_platform="${3:?expected platform required}"
  local challenge_id challenge agent_id platform fingerprint expires_at

  [[ ! -L "$enrollment_file" && -f "$enrollment_file" ]] || {
    printf 'error: staged enrollment must be one regular non-symlink file\n' >&2
    return 1
  }
  validate_private_agent_env_file "$enrollment_file" || return 1
  command -v jq >/dev/null 2>&1 || {
    printf 'error: jq is required to validate staged enrollment material\n' >&2
    return 1
  }
  jq -e '
    type == "object" and
    (keys | sort) == [
      "agent_id",
      "enrollment_challenge",
      "enrollment_challenge_id",
      "expires_at",
      "platform",
      "public_key_fingerprint"
    ] and
    all(.[]; type == "string")
  ' "$enrollment_file" >/dev/null 2>&1 || {
    printf 'error: control plane returned a malformed enrollment response\n' >&2
    return 1
  }
  challenge_id="$(jq -er '.enrollment_challenge_id' "$enrollment_file")" || return 1
  challenge="$(jq -er '.enrollment_challenge' "$enrollment_file")" || return 1
  agent_id="$(jq -er '.agent_id' "$enrollment_file")" || return 1
  platform="$(jq -er '.platform' "$enrollment_file")" || return 1
  fingerprint="$(jq -er '.public_key_fingerprint' "$enrollment_file")" || return 1
  expires_at="$(jq -er '.expires_at' "$enrollment_file")" || return 1

  [[ "$challenge_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ && \
     "$challenge" =~ ^ryc_[0-9a-f]{64}$ && \
     "$fingerprint" =~ ^sha256:[0-9a-f]{64}$ && \
     "$expires_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T && \
     "$agent_id" == "$expected_agent_id" && "$platform" == "$expected_platform" ]] || {
    unset challenge
    printf 'error: staged enrollment is non-canonical or bound to a different identity\n' >&2
    return 1
  }
  unset challenge
}

load_agent_env() {
  local env_file="${1:?environment file path required}"
  local line key value trimmed
  local line_number=0
  local seen_keys=" "

  if [[ ! -r "$env_file" ]]; then
    printf 'error: cannot read agent environment file: %s\n' "$env_file" >&2
    return 1
  fi

  # Discard inherited PG_* agent values before reading the selected file.
  unset PG_AGENT_PLATFORM PG_AGENT_ALLOW_LIVE PG_AGENT_BACKEND_HCL
  unset PG_AGENT_DEPLOYMENT_ID PG_AGENT_TRUST_DOMAIN_ID
  unset PG_TERRAFORM_EXECUTABLE PG_TERRAFORM_EXPECTED_VERSION \
    PG_TERRAFORM_EXECUTABLE_SHA256
  unset PG_ANSIBLE_PLAYBOOK_EXECUTABLE PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION \
    PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256
  unset PG_VSPHERE_USER PG_VSPHERE_PASSWORD PG_VSPHERE_SERVER
  unset PG_PROVIDER_AUTHORITY_ID PG_PROVIDER_AUTHORITY_VERSION
  unset PG_BACKEND_CREDENTIAL_AUTHORITY_ID PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION
  PG_AGENT_PLATFORM=""
  PG_AGENT_ALLOW_LIVE="false"
  PG_AGENT_BACKEND_HCL=""
  PG_AGENT_DEPLOYMENT_ID=""
  PG_AGENT_TRUST_DOMAIN_ID=""
  PG_TERRAFORM_EXECUTABLE=""
  PG_TERRAFORM_EXPECTED_VERSION=""
  PG_TERRAFORM_EXECUTABLE_SHA256=""
  PG_ANSIBLE_PLAYBOOK_EXECUTABLE=""
  PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION=""
  PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256=""
  PG_VSPHERE_USER=""
  PG_VSPHERE_PASSWORD=""
  PG_VSPHERE_SERVER=""
  PG_PROVIDER_AUTHORITY_ID=""
  PG_PROVIDER_AUTHORITY_VERSION=""
  PG_BACKEND_CREDENTIAL_AUTHORITY_ID=""
  PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    line="${line%$'\r'}"

    trimmed="${line#"${line%%[![:space:]]*}"}"
    case "$trimmed" in
      ''|'#'*) continue ;;
    esac

    if [[ "$line" != *=* ]]; then
      printf 'error: malformed line %d in %s (expected KEY=value)\n' \
        "$line_number" "$env_file" >&2
      return 1
    fi

    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      PG_AGENT_PLATFORM | PG_AGENT_ALLOW_LIVE | PG_AGENT_BACKEND_HCL | \
        PG_AGENT_DEPLOYMENT_ID | PG_AGENT_TRUST_DOMAIN_ID | \
        PG_TERRAFORM_EXECUTABLE | PG_TERRAFORM_EXPECTED_VERSION | \
        PG_TERRAFORM_EXECUTABLE_SHA256 | PG_ANSIBLE_PLAYBOOK_EXECUTABLE | \
        PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION | \
        PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256 | \
        PG_VSPHERE_USER | PG_VSPHERE_PASSWORD | PG_VSPHERE_SERVER | \
        PG_PROVIDER_AUTHORITY_ID | PG_PROVIDER_AUTHORITY_VERSION | \
        PG_BACKEND_CREDENTIAL_AUTHORITY_ID | \
        PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION)
        case "$seen_keys" in
          *" $key "*)
            printf 'error: duplicate %s on line %d in %s\n' \
              "$key" "$line_number" "$env_file" >&2
            return 1
            ;;
        esac
        seen_keys="${seen_keys}${key} "
        printf -v "$key" '%s' "$value"
        ;;
      *)
        # Compose-only values, including database and Vault credentials, are
        # intentionally ignored and never assigned by this parser.
        ;;
    esac
  done < "$env_file"
}

validate_agent_env() {
  if [[ -z "$PG_AGENT_PLATFORM" ]]; then
    printf 'error: PG_AGENT_PLATFORM is missing or empty\n' >&2
    return 1
  fi

  case "$PG_AGENT_ALLOW_LIVE" in
    true | false) ;;
    *)
      printf 'error: PG_AGENT_ALLOW_LIVE must be the literal true or false\n' >&2
      return 1
      ;;
  esac

  if [[ -n "$PG_AGENT_DEPLOYMENT_ID" || -n "$PG_AGENT_TRUST_DOMAIN_ID" ]]; then
    if [[ ! "$PG_AGENT_DEPLOYMENT_ID" =~ ^deployment:[a-z0-9][a-z0-9._-]{2,126}$ ]]; then
      printf 'error: PG_AGENT_DEPLOYMENT_ID must be a canonical deployment: id\n' >&2
      return 1
    fi
    if [[ ! "$PG_AGENT_TRUST_DOMAIN_ID" =~ ^trust-domain:[a-z0-9][a-z0-9._-]{2,126}$ ]]; then
      printf 'error: PG_AGENT_TRUST_DOMAIN_ID must be a canonical trust-domain: id\n' >&2
      return 1
    fi
  fi

  if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && \
    ( -z "$PG_AGENT_DEPLOYMENT_ID" || -z "$PG_AGENT_TRUST_DOMAIN_ID" ) ]]; then
    printf 'error: live execution requires PG_AGENT_DEPLOYMENT_ID and PG_AGENT_TRUST_DOMAIN_ID\n' >&2
    return 1
  fi

  if [[ -n "$PG_AGENT_BACKEND_HCL" && "$PG_AGENT_BACKEND_HCL" != *'{STATE_KEY}'* ]]; then
    printf 'error: PG_AGENT_BACKEND_HCL must contain {STATE_KEY}\n' >&2
    return 1
  fi

  if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && -z "$PG_AGENT_BACKEND_HCL" ]]; then
    printf 'error: live execution requires PG_AGENT_BACKEND_HCL\n' >&2
    return 1
  fi

  if [[ -n "$PG_PROVIDER_AUTHORITY_ID" || -n "$PG_PROVIDER_AUTHORITY_VERSION" ]]; then
    if [[ -z "$PG_PROVIDER_AUTHORITY_ID" || -z "$PG_PROVIDER_AUTHORITY_VERSION" ]]; then
      printf 'error: PG_PROVIDER_AUTHORITY_ID and PG_PROVIDER_AUTHORITY_VERSION are all-or-none\n' >&2
      return 1
    fi
    local authority_suffix
    authority_suffix="${PG_PROVIDER_AUTHORITY_ID#provider-authority/vsphere/}"
    if [[ "$authority_suffix" == "$PG_PROVIDER_AUTHORITY_ID" || \
      -z "$authority_suffix" || ${#PG_PROVIDER_AUTHORITY_ID} -gt 256 || \
      "$authority_suffix" == /* || "$authority_suffix" == */ || \
      "$authority_suffix" == *//* || \
      ! "$authority_suffix" =~ ^[a-z0-9._/-]+$ ]]; then
      printf 'error: PG_PROVIDER_AUTHORITY_ID must be a canonical opaque provider-authority/vsphere/... reference\n' >&2
      return 1
    fi
    if [[ ${#PG_PROVIDER_AUTHORITY_VERSION} -lt 2 || \
      ${#PG_PROVIDER_AUTHORITY_VERSION} -gt 64 || \
      ! "$PG_PROVIDER_AUTHORITY_VERSION" =~ ^v[a-z0-9._-]+$ ]]; then
      printf 'error: PG_PROVIDER_AUTHORITY_VERSION must be a canonical v-prefixed version\n' >&2
      return 1
    fi
  fi

  if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && \
    ( -z "$PG_PROVIDER_AUTHORITY_ID" || -z "$PG_PROVIDER_AUTHORITY_VERSION" ) ]]; then
    printf 'error: live execution requires PG_PROVIDER_AUTHORITY_ID and PG_PROVIDER_AUTHORITY_VERSION\n' >&2
    return 1
  fi

  if [[ -n "$PG_BACKEND_CREDENTIAL_AUTHORITY_ID" || \
    -n "$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION" ]]; then
    if [[ -z "$PG_BACKEND_CREDENTIAL_AUTHORITY_ID" || \
      -z "$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION" ]]; then
      printf 'error: PG_BACKEND_CREDENTIAL_AUTHORITY_ID and PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION are all-or-none\n' >&2
      return 1
    fi
    local backend_authority_suffix
    backend_authority_suffix="${PG_BACKEND_CREDENTIAL_AUTHORITY_ID#backend-credential-authority/local/}"
    if [[ "$backend_authority_suffix" == "$PG_BACKEND_CREDENTIAL_AUTHORITY_ID" || \
      -z "$backend_authority_suffix" || \
      ${#PG_BACKEND_CREDENTIAL_AUTHORITY_ID} -gt 256 || \
      "$backend_authority_suffix" == /* || "$backend_authority_suffix" == */ || \
      "$backend_authority_suffix" == *//* || \
      ! "$backend_authority_suffix" =~ ^[a-z0-9._/-]+$ ]]; then
      printf 'error: PG_BACKEND_CREDENTIAL_AUTHORITY_ID must be a canonical opaque backend-credential-authority/local/... reference\n' >&2
      return 1
    fi
    if [[ ${#PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION} -lt 2 || \
      ${#PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION} -gt 64 || \
      ! "$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION" =~ ^v[a-z0-9._-]+$ ]]; then
      printf 'error: PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION must be a canonical v-prefixed revision\n' >&2
      return 1
    fi
  fi

  if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && \
    ( -z "$PG_BACKEND_CREDENTIAL_AUTHORITY_ID" || \
      -z "$PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION" ) ]]; then
    printf 'error: live execution requires PG_BACKEND_CREDENTIAL_AUTHORITY_ID and PG_BACKEND_CREDENTIAL_AUTHORITY_REVISION\n' >&2
    return 1
  fi

  local executable_var version_var digest_var executable version digest
  for executable_var in PG_TERRAFORM_EXECUTABLE PG_ANSIBLE_PLAYBOOK_EXECUTABLE; do
    case "$executable_var" in
      PG_TERRAFORM_EXECUTABLE)
        version_var=PG_TERRAFORM_EXPECTED_VERSION
        digest_var=PG_TERRAFORM_EXECUTABLE_SHA256
        ;;
      PG_ANSIBLE_PLAYBOOK_EXECUTABLE)
        version_var=PG_ANSIBLE_PLAYBOOK_EXPECTED_VERSION
        digest_var=PG_ANSIBLE_PLAYBOOK_EXECUTABLE_SHA256
        ;;
    esac
    executable="${!executable_var}"
    version="${!version_var}"
    digest="${!digest_var}"
    [[ "$executable" == /* ]] || {
      printf 'error: %s must be an absolute path\n' "$executable_var" >&2
      return 1
    }
    [[ "$version" =~ ^[A-Za-z0-9._+-]{1,64}$ ]] || {
      printf 'error: %s must be a short unadorned version token\n' "$version_var" >&2
      return 1
    }
    if [[ -n "$digest" && ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
      printf 'error: %s must be empty or one lowercase SHA-256 digest\n' "$digest_var" >&2
      return 1
    fi
    if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && -z "$digest" ]]; then
      printf 'error: live execution requires %s to contain an approved SHA-256 digest\n' \
        "$digest_var" >&2
      return 1
    fi
  done
}

# Run a version probe for at most five seconds and retain at most roughly
# 64 KiB. The Rust runner applies the stronger process-group supervisor; this
# host-side guard keeps proving-ground startup and out-of-band cleanup from
# hanging before that boundary is available.
run_bounded_identity_probe() {
  local executable="${1:?executable required}"
  shift
  local output_file pid attempt status first_line

  output_file="$(mktemp "${TMPDIR:-/tmp}/ryuki-tool-probe.XXXXXX")" || return 1
  (
    ulimit -f 128
    exec env -i "PATH=${PATH:-/usr/bin:/bin}" "HOME=${HOME:-/tmp}" \
      "TMPDIR=${TMPDIR:-/tmp}" "$executable" "$@"
  ) > "$output_file" 2>/dev/null &
  pid=$!

  for ((attempt = 0; attempt < 50; attempt++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      if wait "$pid"; then
        status=0
      else
        status=$?
      fi
      if ((status != 0)); then
        rm -f "$output_file"
        return "$status"
      fi
      if ! IFS= read -r first_line < "$output_file"; then
        rm -f "$output_file"
        return 1
      fi
      rm -f "$output_file"
      printf '%s' "$first_line"
      return 0
    fi
    sleep 0.1
  done

  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$output_file"
  return 124
}

# Hash one private executable copy without trusting output formatting beyond one
# canonical lowercase SHA-256 token.
approved_executable_sha256() {
  local executable="${1:?approved executable path required}"
  local digest_line digest remainder

  command -v shasum >/dev/null 2>&1 || {
    printf 'error: shasum is required for executable digest validation\n' >&2
    return 1
  }
  digest_line="$(command shasum -a 256 "$executable")" || return 1
  read -r digest remainder <<< "$digest_line"
  [[ "$digest" =~ ^[0-9a-f]{64}$ && -n "$remainder" ]] || {
    printf 'error: shasum returned a non-canonical executable digest\n' >&2
    return 1
  }
  printf '%s' "$digest"
}

# Content-addressed approved tools are current-user-owned, non-writable, and
# single-linked beneath a private directory. This prevents a second pathname
# from changing an accepted inode after it has been hashed.
validate_private_approved_executable() {
  local executable="${1:?approved executable path required}"
  local expected_digest="${2:?approved executable digest required}"
  local stat_fields mode owner links effective_uid actual_digest

  [[ ! -L "$executable" && -f "$executable" && -x "$executable" ]] || {
    printf 'error: approved executable must be one regular non-symlink file: %s\n' \
      "$executable" >&2
    return 1
  }
  if stat_fields="$(stat -f '%Lp %u %l' "$executable" 2>/dev/null)"; then
    :
  elif stat_fields="$(stat -c '%a %u %h' "$executable" 2>/dev/null)"; then
    :
  else
    printf 'error: cannot inspect approved executable metadata: %s\n' \
      "$executable" >&2
    return 1
  fi
  read -r mode owner links <<< "$stat_fields"
  effective_uid="$(id -u)" || return 1
  [[ "$mode" == "500" && "$owner" =~ ^[0-9]+$ && \
    "$links" == "1" ]] && ((owner == effective_uid)) || {
    printf 'error: approved executable must be current-user-owned, mode 0500, and single-linked: %s\n' \
      "$executable" >&2
    return 1
  }
  actual_digest="$(approved_executable_sha256 "$executable")" || return 1
  [[ "$actual_digest" == "$expected_digest" ]] || {
    printf 'error: private approved executable digest changed: %s\n' \
      "$executable" >&2
    return 1
  }
}

# Copy a configured top-level infrastructure CLI into the agent-owned private
# state directory, hash that copy, and only then execute its identity probe.
# Callers must use APPROVED_EXECUTABLE_PATH and APPROVED_EXECUTABLE_SHA256;
# executing the configured source path after this function would reopen the
# pathname race this boundary is designed to close.
stage_approved_executable() {
  local tool="${1:?tool identity required}"
  local executable="${2:?executable path required}"
  local expected_version="${3:?expected version required}"
  local expected_digest="${4-}"
  local state_dir="${5:?private agent state directory required}"
  local configured_dir basename canonical_dir canonical_path
  local effective_uid stat_fields mode owner mode_value parent sticky_safe
  local approved_dir staging_path approved_path actual_digest
  local first_line expected_line probe_argument

  APPROVED_EXECUTABLE_PATH=""
  APPROVED_EXECUTABLE_SHA256=""

  case "$tool" in
    terraform)
      expected_line="Terraform v$expected_version"
      probe_argument="version"
      ;;
    ansible-playbook)
      expected_line="ansible-playbook [core $expected_version]"
      probe_argument="--version"
      ;;
    *)
      printf 'error: unsupported executable identity: %s\n' "$tool" >&2
      return 1
      ;;
  esac
  if [[ -n "$expected_digest" && ! "$expected_digest" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'error: %s approved digest must be one lowercase SHA-256 digest\n' \
      "$tool" >&2
    return 1
  fi
  if [[ "${PG_AGENT_ALLOW_LIVE:-false}" == "true" && -z "$expected_digest" ]]; then
    printf 'error: live %s staging requires an approved SHA-256 digest\n' \
      "$tool" >&2
    return 1
  fi
  validate_private_agent_state_dir "$state_dir" || return 1

  [[ "$executable" == /* ]] || {
    printf 'error: %s executable path must be absolute\n' "$tool" >&2
    return 1
  }
  [[ ! -L "$executable" ]] || {
    printf 'error: %s executable must not be a symlink: %s\n' "$tool" "$executable" >&2
    return 1
  }
  [[ -f "$executable" && -x "$executable" ]] || {
    printf 'error: %s executable must be one executable regular file: %s\n' \
      "$tool" "$executable" >&2
    return 1
  }

  configured_dir="${executable%/*}"
  [[ -n "$configured_dir" ]] || configured_dir="/"
  basename="${executable##*/}"
  canonical_dir="$(cd "$configured_dir" 2>/dev/null && pwd -P)" || {
    printf 'error: cannot canonicalize %s executable directory\n' "$tool" >&2
    return 1
  }
  if [[ "$canonical_dir" == "/" ]]; then
    canonical_path="/$basename"
  else
    canonical_path="$canonical_dir/$basename"
  fi
  [[ "$canonical_path" == "$executable" ]] || {
    printf 'error: %s executable path must already be canonical: %s\n' \
      "$tool" "$executable" >&2
    return 1
  }

  effective_uid="$(id -u)" || return 1
  parent="$executable"
  while :; do
    if stat_fields="$(stat -f '%Lp %u' "$parent" 2>/dev/null)"; then
      :
    elif stat_fields="$(stat -c '%a %u' "$parent" 2>/dev/null)"; then
      :
    else
      printf 'error: cannot inspect executable provenance: %s\n' "$parent" >&2
      return 1
    fi
    read -r mode owner <<< "$stat_fields"
    [[ "$mode" =~ ^[0-7]+$ && "$owner" =~ ^[0-9]+$ ]] || {
      printf 'error: invalid executable provenance metadata: %s\n' "$parent" >&2
      return 1
    }
    ((owner == 0 || owner == effective_uid)) || {
      printf 'error: executable path component has an untrusted owner: %s\n' "$parent" >&2
      return 1
    }
    mode_value=$((8#$mode))
    if [[ "$parent" == "$executable" ]]; then
      (( (mode_value & 0111) != 0 )) || {
        printf 'error: configured executable has no execute bit: %s\n' "$parent" >&2
        return 1
      }
      sticky_safe=false
    else
      [[ ! -L "$parent" && -d "$parent" ]] || {
        printf 'error: executable parent must be a real directory: %s\n' "$parent" >&2
        return 1
      }
      sticky_safe=false
      if ((owner == 0 && (mode_value & 01000) != 0)); then
        sticky_safe=true
      fi
    fi
    if (( (mode_value & 0022) != 0 )) && [[ "$sticky_safe" != "true" ]]; then
      printf 'error: executable path component is writable by group or others: %s\n' \
        "$parent" >&2
      return 1
    fi
    [[ "$parent" == "/" ]] && break
    parent="${parent%/*}"
    [[ -n "$parent" ]] || parent="/"
  done

  approved_dir="$state_dir/approved-tools"
  if [[ ! -e "$approved_dir" && ! -L "$approved_dir" ]]; then
    mkdir -m 700 "$approved_dir" || {
      printf 'error: cannot create private approved executable directory\n' >&2
      return 1
    }
  fi
  validate_private_agent_state_dir "$approved_dir" || return 1

  staging_path="$(mktemp "$approved_dir/.${tool}.XXXXXX")" || {
    printf 'error: cannot create private executable staging file\n' >&2
    return 1
  }
  if ! command cp "$executable" "$staging_path"; then
    rm -f "$staging_path"
    printf 'error: cannot copy configured %s executable into private state\n' \
      "$tool" >&2
    return 1
  fi
  chmod 500 "$staging_path" || {
    rm -f "$staging_path"
    printf 'error: cannot make private %s executable non-writable\n' "$tool" >&2
    return 1
  }
  actual_digest="$(approved_executable_sha256 "$staging_path")" || {
    rm -f "$staging_path"
    return 1
  }
  if [[ -n "$expected_digest" && "$actual_digest" != "$expected_digest" ]]; then
    rm -f "$staging_path"
    printf 'error: %s executable digest does not match the approved SHA-256\n' \
      "$tool" >&2
    return 1
  fi

  approved_path="$approved_dir/${tool}-${actual_digest}"
  if [[ ! -e "$approved_path" && ! -L "$approved_path" ]]; then
    if ! ln "$staging_path" "$approved_path" 2>/dev/null && \
      [[ ! -e "$approved_path" && ! -L "$approved_path" ]]; then
      rm -f "$staging_path"
      printf 'error: cannot publish content-addressed %s executable\n' "$tool" >&2
      return 1
    fi
  fi
  rm -f "$staging_path"
  validate_private_approved_executable "$approved_path" "$actual_digest" || return 1

  first_line="$(run_bounded_identity_probe "$approved_path" "$probe_argument")" || {
    printf 'error: %s identity probe failed\n' "$tool" >&2
    return 1
  }
  [[ "$first_line" == "$expected_line" ]] || {
    printf 'error: approved executable copy did not identify as %s version %s\n' \
      "$tool" "$expected_version" >&2
    return 1
  }
  validate_private_approved_executable "$approved_path" "$actual_digest" || {
    printf 'error: %s executable changed during its identity probe\n' "$tool" >&2
    return 1
  }

  APPROVED_EXECUTABLE_PATH="$approved_path"
  APPROVED_EXECUTABLE_SHA256="$actual_digest"
}

provider_authority_record() {
  local authority_id="${1:?provider authority id required}"
  local authority_version="${2:?provider authority version required}"
  printf 'ryuki-proving-ground-provider-authority-v1\n%s\n%s' \
    "$authority_id" "$authority_version"
}

backend_credential_authority_record() {
  local authority_id="${1:?backend credential authority id required}"
  local authority_revision="${2:?backend credential authority revision required}"
  printf 'ryuki-proving-ground-backend-credential-authority-v1\n%s\n%s' \
    "$authority_id" "$authority_revision"
}

render_agent_backend_hcl() {
  local template="${1-}"
  local state_dir="${2:?state directory required}"
  printf '%s' "${template//\{STATE_DIR\}/$state_dir}"
}
