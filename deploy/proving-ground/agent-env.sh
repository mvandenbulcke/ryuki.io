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
  unset PG_VSPHERE_USER PG_VSPHERE_PASSWORD PG_VSPHERE_SERVER
  PG_AGENT_PLATFORM=""
  PG_AGENT_ALLOW_LIVE="false"
  PG_AGENT_BACKEND_HCL=""
  PG_VSPHERE_USER=""
  PG_VSPHERE_PASSWORD=""
  PG_VSPHERE_SERVER=""

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
        PG_VSPHERE_USER | PG_VSPHERE_PASSWORD | PG_VSPHERE_SERVER)
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

  if [[ -n "$PG_AGENT_BACKEND_HCL" && "$PG_AGENT_BACKEND_HCL" != *'{STATE_KEY}'* ]]; then
    printf 'error: PG_AGENT_BACKEND_HCL must contain {STATE_KEY}\n' >&2
    return 1
  fi

  if [[ "$PG_AGENT_ALLOW_LIVE" == "true" && -z "$PG_AGENT_BACKEND_HCL" ]]; then
    printf 'error: live execution requires PG_AGENT_BACKEND_HCL\n' >&2
    return 1
  fi
}

provider_context_fingerprint() {
  local user="${1:?provider user required}"
  local server="${2:?provider server required}"
  local digest_line

  command -v shasum >/dev/null 2>&1 || {
    printf 'error: shasum is required for provider-context binding\n' >&2
    return 1
  }
  digest_line="$({
    printf 'ryuki-proving-ground-provider-v1\0%s\0%s\0' "$user" "$server"
  } | shasum -a 256)" || return 1
  printf '%s' "${digest_line%% *}"
}

render_agent_backend_hcl() {
  local template="${1-}"
  local state_dir="${2:?state directory required}"
  printf '%s' "${template//\{STATE_DIR\}/$state_dir}"
}
