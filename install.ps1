<#
.SYNOPSIS
Call Me Windows Installer (PowerShell)
Supported platforms: Windows 10/11, Windows Server 2019/2022
Requires: PowerShell 5.1+ and Python 3.10+

.DESCRIPTION
Installs Call Me into an isolated virtual environment, configures
call-me and lcs on PATH, and registers AI host slash commands.
#>

[CmdletBinding()]
param (
    [switch]$Force,
    [string]$InstallDir = "$env:USERPROFILE\.call-me",
    [string]$BinDir = "$env:USERPROFILE\.local\bin"
)

$ErrorActionPreference = "Stop"
$Version = "3.2.0rc4"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host " CALL ME — MULTI-AGENT CAPABILITY ORCHESTRATOR INSTALLER v$Version" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# 1. Python Detection (Requirement: >= 3.10)
$PythonCandidates = @("python", "py", "python3")
$PythonPath = $null

foreach ($cand in $PythonCandidates) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) {
        try {
            $ver = & $cand -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>$null
            if ($ver) {
                $parts = $ver.Trim().Split(".")
                $major = [int]$parts[0]
                $minor = [int]$parts[1]
                if ($major -eq 3 -and $minor -ge 10) {
                    $PythonPath = $cand
                    Write-Host "[+] Found compatible Python: $cand (v$ver)" -ForegroundColor Green
                    break
                }
            }
        } catch { }
    }
}

if (-not $PythonPath) {
    Write-Host "[ERROR] Python 3.10 or higher is required but was not found on PATH." -ForegroundColor Red
    Write-Host ""
    Write-Host "Remediation (Windows winget):" -ForegroundColor Yellow
    Write-Host "  winget install Python.Python.3.12"
    Write-Host "Then restart PowerShell and re-run this script."
    exit 1
}

# 2. Prepare Isolated Virtual Environment
$VenvDir = Join-Path $InstallDir "venv"
Write-Host "[+] Preparing isolated environment at: $VenvDir"

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

if (-not (Test-Path $VenvDir)) {
    & $PythonPath -m venv $VenvDir
} else {
    Write-Host "    Updating existing isolated environment..."
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvPip = Join-Path $VenvDir "Scripts\pip.exe"

# Upgrade pip quietly
& $VenvPython -m pip install --quiet --upgrade pip

# 3. Package Installation
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyprojectPath = Join-Path $ScriptDir "pyproject.toml"

if (Test-Path $PyprojectPath) {
    Write-Host "[+] Installing Call Me from local repository: $ScriptDir"
    & $VenvPip install --quiet $ScriptDir
} else {
    Write-Host "[+] Installing Call Me from package..."
    & $VenvPip install --quiet lcs-core
}

# 4. Create Command Wrappers
Write-Host "[+] Exposing executables in: $BinDir"

$CallMeCmdPath = Join-Path $BinDir "call-me.cmd"
$LcsCmdPath = Join-Path $BinDir "lcs.cmd"

$CallMeExe = Join-Path $VenvDir "Scripts\call-me.exe"
$LcsExe = Join-Path $VenvDir "Scripts\lcs.exe"

"@echo off`r`n`"$CallMeExe`" %*" | Out-File -FilePath $CallMeCmdPath -Encoding ascii -Force
"@echo off`r`n`"$LcsExe`" %*" | Out-File -FilePath $LcsCmdPath -Encoding ascii -Force

Write-Host "    Created $CallMeCmdPath"
Write-Host "    Created $LcsCmdPath"

# 5. Automatic Host Integration
Write-Host "`n[+] Configuring AI host integrations..."
& $CallMeExe setup --repair

# 6. User PATH Check
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$BinDir*") {
    Write-Host "`n[NOTICE] '$BinDir' is not in your User PATH." -ForegroundColor Yellow
    Write-Host "Adding to User PATH..." -ForegroundColor Yellow
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$BinDir", "User")
    Write-Host "[+] Added $BinDir to User PATH. (Restart PowerShell to apply)" -ForegroundColor Green
}

Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host " CALL ME v$Version INSTALLED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "Quick Start:"
Write-Host "  In your AI host:     Type /call-me <any objective>"
Write-Host "  From your terminal:  Type call-me `"<objective>`""
Write-Host "  Diagnostics:         Type call-me setup --doctor`n"
