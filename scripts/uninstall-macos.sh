#!/usr/bin/env bash
set -euo pipefail

physical_home="$(cd -P "$HOME" && pwd)"
resolve_under_home() {
  local requested="$1" leaf parent next component
  local -a missing=()
  [[ "$requested" == /* ]] || requested="$PWD/$requested"
  leaf="$(basename "$requested")"
  [[ -n "$leaf" && "$leaf" != "." && "$leaf" != ".." ]] || { printf 'Invalid uninstall destination: %s\n' "$requested" >&2; return 1; }
  parent="$(dirname "$requested")"
  while [[ ! -d "$parent" ]]; do
    component="$(basename "$parent")"
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] || { printf 'Invalid uninstall destination: %s\n' "$requested" >&2; return 1; }
    missing=("$component" "${missing[@]}")
    next="$(dirname "$parent")"
    [[ "$next" != "$parent" ]] || { printf 'Could not resolve uninstall destination: %s\n' "$requested" >&2; return 1; }
    parent="$next"
  done
  parent="$(cd -P "$parent" && pwd)"
  for component in "${missing[@]}"; do parent="$parent/$component"; done
  requested="$parent/$leaf"
  case "$requested" in "$physical_home"/*) printf '%s' "$requested" ;; *) printf 'Uninstall destination must stay under HOME: %s\n' "$requested" >&2; return 1 ;; esac
}
destination="$(resolve_under_home "${1:-$physical_home/Applications/SpiffySearch}")"
remove_data="${2:-}"
[[ ! -L "$destination" ]] || { printf 'Uninstall destination cannot be a symbolic link: %s\n' "$destination" >&2; exit 1; }

label="com.spiffyscenes.spiffysearch.agent"
plist="$HOME/Library/LaunchAgents/$label.plist"
if [[ -x "$destination/spiffy-searchctl" ]]; then
  "$destination/spiffy-searchctl" --json stop >/dev/null 2>&1 || true
fi
launchctl bootout "gui/$UID" "$plist" >/dev/null 2>&1 || true
rm -f "$plist"
rm -rf "$destination"

if [[ "$remove_data" == "--remove-data" ]]; then
  data="$HOME/Library/Application Support/SpiffySearch"
  cache="$HOME/Library/Caches/SpiffySearch"
  [[ "$data" == "$HOME/Library/Application Support/SpiffySearch" ]] && rm -rf "$data"
  [[ "$cache" == "$HOME/Library/Caches/SpiffySearch" ]] && rm -rf "$cache"
fi
printf '[Spiffy Search] uninstalled=%s data_removed=%s\n' "$destination" "$([[ "$remove_data" == "--remove-data" ]] && printf true || printf false)"
