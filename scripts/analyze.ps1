#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run vmp_devirt against a target binary and capture the full analysis
    output as a shareable bundle (log + JSON + stdout).

.DESCRIPTION
    One-shot debug/triage wrapper: runs vmp_devirt with --verbose plus
    --export-analysis, tees the full stderr/stdout stream to a log file,
    and drops all three artefacts next to each other so the pair can be
    zipped and handed off in a bug report or issue attachment.

    Produces three files next to the binary (or in -OutDir if given):
      <name>.log      — full merged stderr+stdout from vmp_devirt -v
      <name>.json     — --export-analysis unified report (see AnalysisReport
                        in src/lib.rs for the schema)
      <name>.stdout   — human-readable decoded-instruction table (empty if
                        --vip was omitted on a VMP binary; see docs)

.PARAMETER Binary
    Path to the PE binary to analyse. Relative or absolute.

.PARAMETER OutDir
    Directory to drop the three artefacts into. Defaults to current dir.

.PARAMETER Vip
    Optional --vip <hex> override — hand to the tool as-is. Use this to
    point at a specific virtualised function's dispatch entry instead of
    the PE entry point (which for a VMP binary is the entry stub, NOT
    virtualised bytecode).

.PARAMETER ForceVersion
    Optional --force-version <vmp1|vmp2|vmp30|vmp35|vmp36>. Bypasses the
    detector for research on ambiguous samples.

.PARAMETER Profile
    'release' (default, faster) or 'debug' (slower but with panic
    backtraces if the tool crashes on a hostile input).

.EXAMPLE
    .\scripts\analyze.ps1 target\debug\guard.dll

.EXAMPLE
    .\scripts\analyze.ps1 -Binary sample.exe -OutDir .\dumps -Profile debug

.EXAMPLE
    .\scripts\analyze.ps1 sample.exe -Vip 0x140012340 -ForceVersion vmp36
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Binary,

    [string]$OutDir = ".",

    [string]$Vip = "",

    [ValidateSet('vmp1','vmp2','vmp30','vmp35','vmp36')]
    [string]$ForceVersion = "",

    [ValidateSet('debug','release')]
    [string]$Profile = 'release'
)

$ErrorActionPreference = 'Stop'

# --- locate the binary and tool ---
if (-not (Test-Path -LiteralPath $Binary)) {
    Write-Error "Binary not found: $Binary"
    exit 2
}
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
$binName    = [System.IO.Path]::GetFileNameWithoutExtension($binaryPath)

if (-not (Test-Path -LiteralPath $OutDir)) {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}
$outDirAbs = (Resolve-Path -LiteralPath $OutDir).Path

# vmp_devirt binary — try repo-local first, fall back to $PATH.
$repoRoot = Split-Path -Parent $PSScriptRoot
$devirt = Join-Path $repoRoot "target\$Profile\vmp_devirt.exe"
if (-not (Test-Path -LiteralPath $devirt)) {
    $devirtFromPath = Get-Command 'vmp_devirt' -ErrorAction SilentlyContinue
    if ($devirtFromPath) {
        $devirt = $devirtFromPath.Source
    } else {
        Write-Error "vmp_devirt.exe not found at $devirt and not on PATH. Build first: cargo build --$Profile"
        exit 2
    }
}

# --- artefact paths ---
$logFile    = Join-Path $outDirAbs "$binName.log"
$jsonFile   = Join-Path $outDirAbs "$binName.json"
$stdoutFile = Join-Path $outDirAbs "$binName.stdout"

# --- build arg list ---
$devirtArgs = @($binaryPath, '-v', '--export-analysis', $jsonFile)
if ($Vip)          { $devirtArgs += '--vip';           $devirtArgs += $Vip }
if ($ForceVersion) { $devirtArgs += '--force-version'; $devirtArgs += $ForceVersion }

Write-Host ""
Write-Host "=== vmp_devirt analyze wrapper ==="
Write-Host "  Binary:  $binaryPath"
Write-Host "  Tool:    $devirt"
Write-Host "  Command: vmp_devirt $($devirtArgs -join ' ')"
Write-Host ""

# --- run, capture stderr and stdout separately for clarity ---
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName  = $devirt
foreach ($a in $devirtArgs) { [void]$psi.ArgumentList.Add($a) }
$psi.RedirectStandardError  = $true
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute        = $false
$psi.CreateNoWindow         = $true

$proc = [System.Diagnostics.Process]::Start($psi)
$stdoutText = $proc.StandardOutput.ReadToEnd()
$stderrText = $proc.StandardError.ReadToEnd()
$proc.WaitForExit()
$exitCode = $proc.ExitCode

# --- persist artefacts ---
# Log = the diagnostic stream users actually read (family/version/handlers/
# register roles + any error / warn). Anchor at the top so you can grep by
# section. Include the invocation for reproducibility.
$logHeader = @(
    "=== vmp_devirt analyze bundle ===",
    "  Binary:   $binaryPath",
    "  Tool:     $devirt",
    "  Argv:     $($devirtArgs -join ' ')",
    "  Exit:     $exitCode",
    "  UTC:      $((Get-Date).ToUniversalTime().ToString('o'))",
    "",
    "--- stderr ---",
    ""
) -join "`r`n"
Set-Content -LiteralPath $logFile -Value ($logHeader + $stderrText + "`r`n--- stdout ---`r`n" + $stdoutText) -Encoding UTF8
Set-Content -LiteralPath $stdoutFile -Value $stdoutText -Encoding UTF8

# --- summarise for the human ---
Write-Host "=== artefacts ==="
Write-Host "  Log:      $logFile"
if (Test-Path -LiteralPath $jsonFile) {
    Write-Host "  JSON:     $jsonFile"
} else {
    Write-Host "  JSON:     (not written — pipeline exited before --export-analysis fired)"
}
Write-Host "  Stdout:   $stdoutFile"
Write-Host "  Exit:     $exitCode"
Write-Host ""

# Cheap top-line summary so the user doesn't have to grep the log.
$family  = ($stderrText | Select-String -Pattern 'Protector family:\s*(.*?)\s*\(confidence' | Select-Object -First 1).Matches.Groups[1].Value
$version = ($stderrText | Select-String -Pattern 'Detected VMP version:\s*(.+)$'          | Select-Object -First 1).Matches.Groups[1].Value
$dt      = ($stderrText | Select-String -Pattern 'Dispatch table VA:\s*(0x[0-9a-fA-F]+)' | Select-Object -First 1).Matches.Groups[1].Value
$handlers= ($stderrText | Select-String -Pattern 'Handlers extracted:\s*(\d+)'            | Select-Object -First 1).Matches.Groups[1].Value

if ($family -or $version -or $dt) {
    Write-Host "=== summary (grepped from log) ==="
    if ($family)   { Write-Host "  family:         $family" }
    if ($version)  { Write-Host "  version:        $version" }
    if ($dt)       { Write-Host "  dispatch:       $dt" }
    if ($handlers) { Write-Host "  handlers:       $handlers" }
}

# Interpret common non-zero exits so triage doesn't need to hunt.
switch ($exitCode) {
    0 { Write-Host ""; Write-Host "vmp_devirt exited cleanly." }
    2 { Write-Host ""; Write-Host "Exit 2 (EXIT_NOT_VMP): detector saw no VMP signals. clmods.dll-style behavior. Bypass with --force-version." }
    3 { Write-Host ""; Write-Host "Exit 3 (EXIT_UNSUPPORTED_FAMILY): detected a vendor we don't devirt (Themida/Enigma/Denuvo/UPX/...). Bypass with --force-version if you want to force VMP treatment for research." }
    default { Write-Host ""; Write-Host "vmp_devirt exited $exitCode (non-standard — check the log for stderr)." }
}

exit $exitCode
