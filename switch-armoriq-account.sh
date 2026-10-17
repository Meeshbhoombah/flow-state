
#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_ROOT="$ROOT/.credentials/armoriq"
BACKUP_ROOT="$PROFILE_ROOT/backups"

ACCOUNT_1="meeshbhoombah2020@gmail.com"
ACCOUNT_2="rohanmishra2017@gmail.com"

usage() {
  echo "Usage:"
  echo "  $0 save <email>"
  echo "  $0 switch <email>"
  exit 2
}

profile_for() {
  case "$1" in
    "$ACCOUNT_1") printf '%s' "$PROFILE_ROOT/meesh" ;;
    "$ACCOUNT_2") printf '%s' "$PROFILE_ROOT/rohan" ;;
    *)
      echo "Error: unrecognized account email." >&2
      exit 2
      ;;
  esac
}

validate_profile() {
  local profile="$1"
  local env_file="$profile/.env"
  local yaml_file="$profile/armoriq.yaml"

  [[ -f "$env_file" ]] || {
    echo "Missing profile: $env_file" >&2
    exit 1
  }
  [[ -f "$yaml_file" ]] || {
    echo "Missing profile: $yaml_file" >&2
    exit 1
  }

  for key in ARMORIQ_API_KEY ARMORIQ_USER_ID ARMORIQ_AGENT_ID USER_EMAIL; do
    if ! grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}=" "$env_file"; then
      echo "Missing $key in $env_file" >&2
      exit 1
    fi
  done

  if ! grep -Fq "USER_EMAIL=$2" "$env_file" &&
     ! grep -Fq "USER_EMAIL=\"$2\"" "$env_file" &&
     ! grep -Fq "USER_EMAIL='$2'" "$env_file"; then
    echo "USER_EMAIL in profile does not match $2." >&2
    echo "Correct the profile before switching." >&2
    exit 1
  fi
}

[[ $# -eq 2 ]] || usage
COMMAND="$1"
EMAIL="$2"
PROFILE="$(profile_for "$EMAIL")"

case "$COMMAND" in
  save)
    [[ -f "$ROOT/.env" && -f "$ROOT/armoriq.yaml" ]] || {
      echo "Expected .env and armoriq.yaml in $ROOT" >&2
      exit 1
    }

    mkdir -p "$PROFILE"
    chmod 700 "$PROFILE"

    cp "$ROOT/.env" "$PROFILE/.env"
    cp "$ROOT/armoriq.yaml" "$PROFILE/armoriq.yaml"
    chmod 600 "$PROFILE/.env" "$PROFILE/armoriq.yaml"

    echo "Saved local configuration for $EMAIL."
    echo "Verify the saved USER_EMAIL and account credentials before switching."
    ;;

  switch)
    validate_profile "$PROFILE" "$EMAIL"

    [[ -f "$ROOT/.env" && -f "$ROOT/armoriq.yaml" ]] || {
      echo "Current .env or armoriq.yaml is missing; refusing to switch." >&2
      exit 1
    }

    mkdir -p "$BACKUP_ROOT"
    chmod 700 "$PROFILE_ROOT" "$BACKUP_ROOT"
    STAMP="$(date +%Y%m%d-%H%M%S)"

    cp "$ROOT/.env" "$BACKUP_ROOT/.env.$STAMP"
    cp "$ROOT/armoriq.yaml" "$BACKUP_ROOT/armoriq.yaml.$STAMP"

    # Stage replacements first, then atomically rename each file.
    cp "$PROFILE/.env" "$ROOT/.env.next"
    cp "$PROFILE/armoriq.yaml" "$ROOT/armoriq.yaml.next"
    chmod 600 "$ROOT/.env.next" "$ROOT/armoriq.yaml.next"

    mv "$ROOT/.env.next" "$ROOT/.env"
    mv "$ROOT/armoriq.yaml.next" "$ROOT/armoriq.yaml"

    echo "Switched local configuration to $EMAIL."
    echo "Backup: $BACKUP_ROOT/"
    echo "Restart Kevlar before running another request."
    ;;

  *)
    usage
    ;;
esac

