[CmdletBinding()]
param(
    [string]$Target = "x86_64-pc-windows-msvc",
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$targetDir = Join-Path $root "target\package-build\$Target"
$release = Join-Path $targetDir "$Target\release"
$artifactRoot = Join-Path $root "artifacts\$Target"
$portableRoot = Join-Path $artifactRoot "SpiffySearch"
$binaryNames = @(
    "spiffy-search-agent",
    "spiffy-searchctl",
    "spiffy-search-content-worker",
    "spiffy-search-mcp",
    "spiffy-file-dialog-bridge"
)

function Get-PackageSourceFingerprint {
    $shared = Join-Path $root 'vendor\spiffy-shared-workspace'
    $inputs = [Collections.Generic.List[string]]::new()
    foreach ($tree in @((Join-Path $root 'src'), (Join-Path $root 'scripts'), (Join-Path $shared 'crates\spiffy-shared\src'))) {
        foreach ($file in Get-ChildItem -LiteralPath $tree -Recurse -File | Sort-Object FullName) {
            $label = $file.FullName.Substring((Split-Path $root -Parent).Length + 1).Replace('\','/')
            $inputs.Add("$label=$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash)")
        }
    }
    foreach ($name in @('Cargo.toml','Cargo.lock','README.md','LICENSE','THIRD_PARTY_NOTICES.md','vendor\spiffy-shared-workspace\Cargo.toml','vendor\spiffy-shared-workspace\crates\spiffy-shared\Cargo.toml')) {
        $path = Join-Path $root $name
        $inputs.Add("$name=$((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)")
    }
    $digest = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($digest.ComputeHash([Text.Encoding]::UTF8.GetBytes(($inputs -join "`n"))))).Replace('-','').ToLowerInvariant() }
    finally { $digest.Dispose() }
}

Write-Host "[Spiffy Search] root=$root target=$Target"
$sourceFingerprint = Get-PackageSourceFingerprint
$buildReceipt = Join-Path $targetDir 'qualified-source.sha256'
if (-not $SkipBuild) {
    & cargo build --manifest-path (Join-Path $root "Cargo.toml") --locked --release --target $Target --bins --target-dir $targetDir
    if ($LASTEXITCODE -ne 0) {
        throw "Spiffy Search release build failed with exit code $LASTEXITCODE"
    }
    if ((Get-PackageSourceFingerprint) -ne $sourceFingerprint) { throw 'Search or Shared source changed during build; the candidate is not qualified. Rerun after source writers finish.' }
    [IO.File]::WriteAllText($buildReceipt, $sourceFingerprint, [Text.UTF8Encoding]::new($false))
} elseif (-not (Test-Path -LiteralPath $buildReceipt -PathType Leaf) -or [IO.File]::ReadAllText($buildReceipt) -ne $sourceFingerprint) {
    throw 'SkipBuild refused: these binaries have no matching current Search/Shared source qualification. Run the maintained build first.'
}

$resolvedArtifacts = [IO.Path]::GetFullPath($artifactRoot)
$expectedPrefix = [IO.Path]::GetFullPath((Join-Path $root "artifacts")) + [IO.Path]::DirectorySeparatorChar
if (-not $resolvedArtifacts.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Artifact path escaped the repository artifact root: $resolvedArtifacts"
}
if (Test-Path -LiteralPath $artifactRoot) {
    Remove-Item -LiteralPath $artifactRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $portableRoot -Force | Out-Null

foreach ($binaryName in $binaryNames) {
    $source = Join-Path $release "$binaryName.exe"
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Required release binary was not found at $source"
    }
    Copy-Item -LiteralPath $source -Destination $portableRoot
}

Copy-Item -LiteralPath (Join-Path $root "LICENSE") -Destination $portableRoot
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $portableRoot
Copy-Item -LiteralPath (Join-Path $root "THIRD_PARTY_NOTICES.md") -Destination $portableRoot
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "install-windows.ps1") -Destination $portableRoot
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "uninstall-windows.ps1") -Destination $portableRoot

$control = Join-Path $portableRoot "spiffy-searchctl.exe"
$buildInfoText = (& $control --json build-info | Out-String)
if ($LASTEXITCODE -ne 0) { throw "Packaged Search control binary could not report build information" }
try { $buildInfo = $buildInfoText | ConvertFrom-Json }
catch { throw "Packaged Search build information was not valid JSON: $($_.Exception.Message)" }
if (-not $buildInfo.ok -or $buildInfo.data.product -ne "spiffy-search") {
    throw "Packaged Search control binary reported unexpected build information"
}
$revision = (& git -C $root rev-parse HEAD)
if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-fA-F]{40,64}$') {
    throw "Could not resolve the Search source revision"
}
$sourceChanges = @(& git -C $root status --porcelain --untracked-files=normal)
if ($LASTEXITCODE -ne 0) { throw "Could not inspect the Search source state" }
$manifestLines = [Collections.Generic.List[string]]::new()
$manifestLines.Add("schema_version=1")
$manifestLines.Add("product=$($buildInfo.data.product)")
$manifestLines.Add("version=$($buildInfo.data.version)")
$manifestLines.Add("target=$Target")
$manifestLines.Add("protocol=$($buildInfo.data.protocol.major).$($buildInfo.data.protocol.minor)")
$manifestLines.Add("saved_shelf_protocol=$($buildInfo.data.saved_shelf_protocol.major).$($buildInfo.data.saved_shelf_protocol.minor)")
$manifestLines.Add("revision=$($revision.Trim().ToLowerInvariant())")
$manifestLines.Add("source_dirty=$($sourceChanges.Count -gt 0)")
$manifestLines.Add("source_fingerprint_sha256=$sourceFingerprint")
$manifestLines.Add("generated_at=$([DateTime]::UtcNow.ToString('o'))")
$manifestLines.Add("files:")
if ((Get-PackageSourceFingerprint) -ne $sourceFingerprint) { throw 'Search or Shared source changed during package assembly; candidate remains inactive.' }
foreach ($file in Get-ChildItem -LiteralPath $portableRoot -File | Sort-Object Name) {
    $fileHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifestLines.Add("$fileHash  $($file.Name)")
}
[IO.File]::WriteAllLines(
    (Join-Path $portableRoot "PACKAGE_MANIFEST.txt"),
    $manifestLines,
    [Text.UTF8Encoding]::new($false)
)

$zip = Join-Path $artifactRoot "SpiffySearch-$Target-portable.zip"
Compress-Archive -Path (Join-Path $portableRoot "*") -DestinationPath $zip -CompressionLevel Optimal
$hash = Get-FileHash -LiteralPath $zip -Algorithm SHA256
$checksumPath = Join-Path $artifactRoot "SHA256SUMS.txt"
[IO.File]::WriteAllText(
    $checksumPath,
    ("{0}  {1}`n" -f $hash.Hash.ToLowerInvariant(), (Split-Path $zip -Leaf)),
    [Text.UTF8Encoding]::new($false)
)
Write-Host "[Spiffy Search] portable=$zip checksums=$checksumPath"
