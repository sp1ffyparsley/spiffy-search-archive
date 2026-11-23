[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $env:LOCALAPPDATA "Programs\SpiffySearch"),
    [switch]$NoStart,
    [switch]$NoStartupRegistration
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw "LOCALAPPDATA is unavailable; a per-user installation cannot be created"
}

$source = [IO.Path]::GetFullPath($PSScriptRoot)
$destination = [IO.Path]::GetFullPath($Destination)
$localRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
if (-not $destination.StartsWith($localRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Install destination must stay under LOCALAPPDATA: $destination"
}

$required = @(
    "spiffy-search-agent.exe",
    "spiffy-searchctl.exe",
    "spiffy-search-content-worker.exe",
    "spiffy-search-mcp.exe",
    "spiffy-file-dialog-bridge.exe",
    "LICENSE",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "PACKAGE_MANIFEST.txt",
    "uninstall-windows.ps1"
)
foreach ($name in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $name) -PathType Leaf)) {
        throw "Install package is missing $name at $source"
    }
}

$manifestPath = Join-Path $source "PACKAGE_MANIFEST.txt"
$manifestLines = [IO.File]::ReadAllLines($manifestPath)
if ($manifestLines -notcontains "product=spiffy-search") {
    throw "Install package manifest does not identify Spiffy Search"
}
$hashRecords = @($manifestLines | Where-Object { $_ -match '^([0-9a-f]{64})  (.+)$' } | ForEach-Object {
    [pscustomobject]@{ Hash = $Matches[1]; Name = $Matches[2] }
})
if ($hashRecords.Count -eq 0) { throw "Install package manifest contains no payload hashes" }
foreach ($record in $hashRecords) {
    $payload = Join-Path $source $record.Name
    if (-not (Test-Path -LiteralPath $payload -PathType Leaf)) {
        throw "Manifest payload is missing: $($record.Name)"
    }
    $actualHash = (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $record.Hash) {
        throw "Manifest hash mismatch for $($record.Name)"
    }
}

$existingControl = Join-Path $destination "spiffy-searchctl.exe"
if (Test-Path -LiteralPath $existingControl -PathType Leaf) {
    & $existingControl --json stop 2>$null | Out-Null
}

$parent = Split-Path -Parent $destination
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$operationId = [guid]::NewGuid().ToString("N")
$staging = Join-Path $parent ".SpiffySearch-install-$operationId"
$previous = Join-Path $parent ".SpiffySearch-previous-$operationId"
try {
    New-Item -ItemType Directory -Path $staging | Out-Null
    foreach ($name in $required) {
        Copy-Item -LiteralPath (Join-Path $source $name) -Destination $staging
    }
    Copy-Item -LiteralPath (Join-Path $source "install-windows.ps1") -Destination $staging
    if (Test-Path -LiteralPath $destination) {
        Move-Item -LiteralPath $destination -Destination $previous
    }
    try {
        Move-Item -LiteralPath $staging -Destination $destination
    }
    catch {
        if (Test-Path -LiteralPath $previous) {
            Move-Item -LiteralPath $previous -Destination $destination
        }
        throw
    }
    if (Test-Path -LiteralPath $previous) {
        Remove-Item -LiteralPath $previous -Recurse -Force
    }
}
finally {
    if (Test-Path -LiteralPath $staging) {
        Remove-Item -LiteralPath $staging -Recurse -Force
    }
}

$control = Join-Path $destination "spiffy-searchctl.exe"
if (-not $NoStartupRegistration) {
    $escapedControl = $control.Replace("'", "''")
    $runCommand = "powershell.exe -NoProfile -WindowStyle Hidden -Command `"& '$escapedControl' --json start | Out-Null`""
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    New-Item -Path $runKey -Force | Out-Null
    New-ItemProperty -Path $runKey -Name "SpiffySearchAgent" -Value $runCommand -PropertyType String -Force | Out-Null
}

if (-not $NoStart) {
    & $control --json start
    if ($LASTEXITCODE -ne 0) {
        throw "Spiffy Search was installed, but its agent failed to start"
    }
    & $control --json doctor
    if ($LASTEXITCODE -ne 0) {
        throw "Spiffy Search was installed, but Doctor reported a failure"
    }
}
Write-Host "[Spiffy Search] installed=$destination startup_registered=$(-not $NoStartupRegistration)"
