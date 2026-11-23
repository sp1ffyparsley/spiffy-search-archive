#!/usr/bin/env bash
set -euo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
physical_home="$(cd -P "$HOME" && pwd)"
resolve_under_home() {
  local requested="$1" leaf parent next component
  local -a missing=()
  [[ "$requested" == /* ]] || requested="$PWD/$requested"
  leaf="$(basename "$requested")"
  [[ -n "$leaf" && "$leaf" != "." && "$leaf" != ".." ]] || { printf 'Invalid install destination: %s\n' "$requested" >&2; return 1; }
  parent="$(dirname "$requested")"
  while [[ ! -d "$parent" ]]; do
    component="$(basename "$parent")"
    [[ -n "$component" && "$component" != "." && "$component" != ".." ]] || { printf 'Invalid install destination: %s\n' "$requested" >&2; return 1; }
    missing=("$component" "${missing[@]}")
    next="$(dirname "$parent")"
    [[ "$next" != "$parent" ]] || { printf 'Could not resolve install destination: %s\n' "$requested" >&2; return 1; }
    parent="$next"
  done
  parent="$(cd -P "$parent" && pwd)"
  for component in "${missing[@]}"; do parent="$parent/$component"; done
  requested="$parent/$leaf"
  case "$requested" in "$physical_home"/*) printf '%s' "$requested" ;; *) printf 'Install destination must stay under HOME: %s\n' "$requested" >&2; return 1 ;; esac
}
destination="$(resolve_under_home "${1:-$physical_home/Applications/SpiffySearch}")"
[[ ! -L "$destination" ]] || { printf 'Install destination cannot be a symbolic link: %s\n' "$destination" >&2; exit 1; }

binaries=(
  spiffy-search-agent
  spiffy-searchctl
  spiffy-search-content-worker
  spiffy-search-mcp
  spiffy-file-dialog-bridge
)
support_files=(
  LICENSE
  README.md
  THIRD_PARTY_NOTICES.md
  PACKAGE_MANIFEST.txt
  uninstall-macos.sh
)
for binary in "${binaries[@]}"; do
  [[ -x "$source_root/$binary" ]] || { printf 'Install package is missing %s\n' "$binary" >&2; exit 1; }
done
for file in "${support_files[@]}"; do
  [[ -f "$source_root/$file" ]] || { printf 'Install package is missing %s\n' "$file" >&2; exit 1; }
done
grep -qx 'product=spiffy-search' "$source_root/PACKAGE_MANIFEST.txt" || { printf 'Install package manifest does not identify Spiffy Search\n' >&2; exit 1; }
(cd "$source_root" && sed -n '/^files:$/,$p' PACKAGE_MANIFEST.txt | sed '1d' | shasum -a 256 -c - >/dev/null)

if [[ -x "$destination/spiffy-searchctl" ]]; then
  "$destination/spiffy-searchctl" --json stop >/dev/null 2>&1 || true
fi
parent="$(dirname "$destination")"
mkdir -p "$parent"
operation_id="$$-$(date +%s)"
staging="$parent/.SpiffySearch-install-$operation_id"
previous="$parent/.SpiffySearch-previous-$operation_id"
trap 'rm -rf "$staging"' EXIT
mkdir "$staging"
for binary in "${binaries[@]}"; do cp "$source_root/$binary" "$staging/"; done
for file in "${support_files[@]}"; do cp "$source_root/$file" "$staging/"; done
chmod +x "$staging"/spiffy-* "$staging/uninstall-macos.sh"
if [[ -e "$destination" ]]; then mv "$destination" "$previous"; fi
if ! mv "$staging" "$destination"; then
  [[ -e "$previous" ]] && mv "$previous" "$destination"
  exit 1
fi
rm -rf "$previous"
trap - EXIT

label="com.spiffyscenes.spiffysearch.agent"
launch_agents="$HOME/Library/LaunchAgents"
plist="$launch_agents/$label.plist"
logs="$HOME/Library/Logs/SpiffySearch"
mkdir -p "$launch_agents" "$logs"
xml_agent=$(printf '%s' "$destination/spiffy-search-agent" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
xml_stdout=$(printf '%s' "$logs/launchd.stdout.log" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
xml_stderr=$(printf '%s' "$logs/launchd.stderr.log" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$label</string>
<key>ProgramArguments</key><array><string>$xml_agent</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>10</integer>
<key>StandardOutPath</key><string>$xml_stdout</string>
<key>StandardErrorPath</key><string>$xml_stderr</string>
</dict></plist>
EOF
plutil -lint "$plist" >/dev/null
launchctl bootout "gui/$UID" "$plist" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$UID" "$plist"
printf '[Spiffy Search] installed=%s launch_agent=%s\n' "$destination" "$plist"
