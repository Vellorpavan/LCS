<#
.SYNOPSIS
Call Me Safe Uninstaller (Windows PowerShell)
Removes Call Me launcher wrappers, isolated virtual environment, and host slash-command integrations.
Preserves user data and databases in $env:USERPROFILE\.lcs unless -Purge is specified.
#>

[CmdletBinding()]
param (
    [switch]$Purge,
    [string]$InstallDir = "$env:USERPROFILE\.call-me",
    [string]$BinDir = "$env:USERPROFILE\.local\bin"
)

$ErrorActionPreference = "Stop"
$VenvDir = Join-Path $InstallDir "venv"
$CallMeCmdPath = Join-Path $BinDir "call-me.cmd"
$LcsCmdPath = Join-Path $BinDir "lcs.cmd"
$VenvCallMeExe = Join-Path $VenvDir "Scripts\call-me.exe"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host " CALL ME — WINDOWS UNINSTALLATION" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# 1. Remove host integrations using Call Me CLI if available
if (Test-Path $VenvCallMeExe) {
    Write-Host "[+] Removing AI host command integrations..."
    try {
        & $VenvCallMeExe uninstall-command --global | Out-Null
    } catch { }
} elseif (Test-Path $CallMeCmdPath) {
    Write-Host "[+] Removing AI host command integrations..."
    try {
        & $CallMeCmdPath uninstall-command --global | Out-Null
    } catch { }
}

# 2. Remove binary wrappers
Write-Host "[+] Removing launcher wrappers from: $BinDir"
if (Test-Path $CallMeCmdPath) { Remove-Item -Path $CallMeCmdPath -Force }
if (Test-Path $LcsCmdPath) { Remove-Item -Path $LcsCmdPath -Force }

# 3. Remove isolated virtual environment
if (Test-Path $VenvDir) {
    Write-Host "[+] Removing isolated virtual environment at: $VenvDir"
    Remove-Item -Path $VenvDir -Recurse -Force
}

# 4. Handle user data
$UserLcsDir = Join-Path $env:USERPROFILE ".lcs"
if ($Purge) {
    Write-Host "[+] Purging user data and databases at $InstallDir and $UserLcsDir..." -ForegroundColor Yellow
    if (Test-Path $InstallDir) { Remove-Item -Path $InstallDir -Recurse -Force }
    if (Test-Path $UserLcsDir) { Remove-Item -Path $UserLcsDir -Recurse -Force }
    Write-Host "    Data purged completely."
} else {
    Write-Host "[i] User state and databases at $UserLcsDir were preserved."
    Write-Host "    To delete all data and databases, run: .\uninstall.ps1 -Purge"
}

Write-Host "========================================================================" -ForegroundColor Green
Write-Host " Call Me has been successfully uninstalled." -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
