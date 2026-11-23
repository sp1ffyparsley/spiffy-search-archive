[CmdletBinding()]
param(
    [string]$Destination = (Join-Path $env:LOCALAPPDATA "Programs\SpiffySearch"),
    [switch]$RemoveData,
    [switch]$PreserveStartupRegistration,
    [switch]$NoStop
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
    throw "LOCALAPPDATA is unavailable; refusing an unbounded uninstall"
}

$destination = [IO.Path]::GetFullPath($Destination)
$localRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
if (-not $destination.StartsWith($localRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Uninstall destination must stay under LOCALAPPDATA: $destination"
}

$control = Join-Path $destination "spiffy-searchctl.exe"
if (-not $NoStop -and (Test-Path -LiteralPath $control -PathType Leaf)) {
    & $control --json stop 2>$null | Out-Null
}
if (-not $PreserveStartupRegistration) {
    $runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    Remove-ItemProperty -Path $runKey -Name "SpiffySearchAgent" -ErrorAction SilentlyContinue
}
if (Test-Path -LiteralPath $destination) {
    Remove-Item -LiteralPath $destination -Recurse -Force
}

if ($RemoveData) {
    $data = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "SpiffySearch"))
    if ($data -ne (Join-Path $localRoot "SpiffySearch")) {
        throw "Resolved data path was unexpected: $data"
    }
    if (Test-Path -LiteralPath $data) {
        Remove-Item -LiteralPath $data -Recurse -Force
    }
}
Write-Host "[Spiffy Search] uninstalled=$destination data_removed=$([bool]$RemoveData)"
