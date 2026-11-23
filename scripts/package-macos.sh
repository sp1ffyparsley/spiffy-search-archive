#!/usr/bin/env bash
set -euo pipefail
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

target="${1:-aarch64-apple-darwin}"
skip_build="${2:-}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
shared="$root/vendor/spiffy-shared-workspace"
target_dir="$root/target/package-build/$target"
release="$target_dir/$target/release"
artifact_root="$root/artifacts/$target"
portable_root="$artifact_root/SpiffySearch"
binaries=(
  spiffy-search-agent
  spiffy-searchctl
  spiffy-search-content-worker
  spiffy-search-mcp
  spiffy-file-dialog-bridge
)

case "$target" in
  aarch64-apple-darwin|x86_64-apple-darwin) ;;
  *) printf 'Unsupported macOS package target: %s\n' "$target" >&2; exit 1 ;;
esac
if [[ -n "$skip_build" && "$skip_build" != "--skip-build" ]]; then
  printf 'Unknown package option: %s\n' "$skip_build" >&2
  exit 1
fi

get_package_source_fingerprint() {
  {
    while IFS= read -r file; do
      relative="${file#"$root/"}"
      printf 'Spiffy Search/%s=%s\n' "$relative" "$(shasum -a 256 "$file" | awk '{print $1}')"
    done < <(find "$root/src" "$root/scripts" -type f -print | LC_ALL=C sort)
    while IFS= read -r file; do
      relative="${file#"$shared/"}"
      printf 'Spiffy Shared/%s=%s\n' "$relative" "$(shasum -a 256 "$file" | awk '{print $1}')"
    done < <(find "$shared/crates/spiffy-shared/src" -type f -print | LC_ALL=C sort)
    for name in Cargo.toml Cargo.lock README.md LICENSE THIRD_PARTY_NOTICES.md; do
      printf 'Spiffy Search/%s=%s\n' "$name" "$(shasum -a 256 "$root/$name" | awk '{print $1}')"
    done
    for name in Cargo.toml crates/spiffy-shared/Cargo.toml; do
      printf 'Spiffy Shared/%s=%s\n' "$name" "$(shasum -a 256 "$shared/$name" | awk '{print $1}')"
    done
  } | shasum -a 256 | awk '{print $1}'
}

printf '[Spiffy Search] root=%s target=%s\n' "$root" "$target"
source_fingerprint="$(get_package_source_fingerprint)"
build_receipt="$target_dir/qualified-source.sha256"
if [[ "$skip_build" != "--skip-build" ]]; then
  cargo build --manifest-path "$root/Cargo.toml" --locked --release --target "$target" --bins --target-dir "$target_dir"
  if [[ "$(get_package_source_fingerprint)" != "$source_fingerprint" ]]; then
    printf 'Search or Shared source changed during build; rerun after source writers finish.\n' >&2
    exit 1
  fi
  mkdir -p "$target_dir"
  printf '%s' "$source_fingerprint" > "$build_receipt.tmp"
  mv "$build_receipt.tmp" "$build_receipt"
elif [[ ! -f "$build_receipt" || "$(cat "$build_receipt")" != "$source_fingerprint" ]]; then
  printf 'SkipBuild refused: binaries do not match current Search/Shared source. Run a maintained build first.\n' >&2
  exit 1
fi

case "$artifact_root" in
  "$root"/artifacts/*) ;;
  *) printf 'Artifact path escaped the repository: %s\n' "$artifact_root" >&2; exit 1 ;;
esac
rm -rf "$artifact_root"
mkdir -p "$portable_root"
for binary in "${binaries[@]}"; do
  if [[ ! -x "$release/$binary" ]]; then
    printf 'Required release binary was not found at %s\n' "$release/$binary" >&2
    exit 1
  fi
  cp "$release/$binary" "$portable_root/"
done
cp "$root/LICENSE" "$root/README.md" "$root/THIRD_PARTY_NOTICES.md" "$portable_root/"
cp "$root/scripts/install-macos.sh" "$root/scripts/uninstall-macos.sh" "$portable_root/"
chmod +x "$portable_root"/*.sh "$portable_root"/spiffy-*

build_info="$("$portable_root/spiffy-searchctl" --json build-info)"
product="$(printf '%s' "$build_info" | /usr/bin/plutil -extract data.product raw -o - -)"
version="$(printf '%s' "$build_info" | /usr/bin/plutil -extract data.version raw -o - -)"
protocol_major="$(printf '%s' "$build_info" | /usr/bin/plutil -extract data.protocol.major raw -o - -)"
protocol_minor="$(printf '%s' "$build_info" | /usr/bin/plutil -extract data.protocol.minor raw -o - -)"
saved_shelf_major="$(printf '%s' "$build_info" | /usr/bin/plutil -extract data.saved_shelf_protocol.major raw -o - -)"
saved_shelf_minor="$(printf '%s' "$build_info" | /usr/bin/plutil -extract data.saved_shelf_protocol.minor raw -o - -)"
[[ "$product" == "spiffy-search" ]] || { printf 'Unexpected packaged product: %s\n' "$product" >&2; exit 1; }
revision="$(git -C "$root" rev-parse HEAD)"
[[ "$revision" =~ ^[0-9a-fA-F]{40,64}$ ]] || { printf 'Invalid Search source revision\n' >&2; exit 1; }
source_changes="$(git -C "$root" status --porcelain --untracked-files=normal)"
source_dirty=false
if [[ -n "$source_changes" ]]; then source_dirty=true; fi
manifest_temp="$artifact_root/.PACKAGE_MANIFEST.txt.tmp"
{
  printf 'schema_version=1\nproduct=%s\nversion=%s\ntarget=%s\n' "$product" "$version" "$target"
  printf 'protocol=%s.%s\nsaved_shelf_protocol=%s.%s\n' "$protocol_major" "$protocol_minor" "$saved_shelf_major" "$saved_shelf_minor"
  printf 'revision=%s\nsource_dirty=%s\nsource_fingerprint_sha256=%s\n' "$revision" "$source_dirty" "$source_fingerprint"
  printf 'generated_at=%s\nfiles:\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  if [[ "$(get_package_source_fingerprint)" != "$source_fingerprint" ]]; then
    printf 'Search or Shared source changed during package assembly; candidate remains inactive.\n' >&2
    exit 1
  fi
  (cd "$portable_root" && for file in *; do [[ -f "$file" ]] && shasum -a 256 "$file"; done)
} > "$manifest_temp"
mv "$manifest_temp" "$portable_root/PACKAGE_MANIFEST.txt"

zip_path="$artifact_root/SpiffySearch-$target-portable.zip"
ditto -c -k --sequesterRsrc --keepParent "$portable_root" "$zip_path"
(cd "$artifact_root" && shasum -a 256 "$(basename "$zip_path")" > SHA256SUMS.txt)
printf '[Spiffy Search] portable=%s checksums=%s\n' "$zip_path" "$artifact_root/SHA256SUMS.txt"
