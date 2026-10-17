<#
.SYNOPSIS
  Build the easy-install Setup.exe for a Muse-built Windows app.

.DESCRIPTION
  REUSABLE template - all per-app values come from
  packaging\app-config.json (see TEMPLATE-NOTES.md). Steps:
    1. Run the app's unit tests + --self-test (build gate).
    2. PyInstaller: single-file windowed exe into dist\.
    3. Smoke-test the exe headlessly (--version, --self-test) and
       check exit codes only (a windowed exe has no console).
    4. Inno Setup (ISCC): per-user installer dist\<App>-Setup.exe.

  Run from anywhere; paths resolve relative to this script.
  Requires (Windows only): Python 3.12 with pip, Inno Setup 6.
  Installs PyInstaller via pip if missing. Nothing here signs the
  binaries - SmartScreen's "More info -> Run anyway" step applies.

.PARAMETER SkipInno
  Build only the standalone exe, not the installer.

.PARAMETER SkipTests
  Skip the test gate. Not recommended; CI never skips.
#>
[CmdletBinding()]
param(
    [switch]$SkipInno,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$PackagingDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $PackagingDir
$Config = Get-Content (Join-Path $PackagingDir "app-config.json") -Raw | ConvertFrom-Json

$ExePath = Join-Path $RepoRoot ("dist\" + $Config.exe_name)
$SetupPath = Join-Path $RepoRoot ("dist\" + $Config.setup_name)

Push-Location $RepoRoot
try {
    if (-not $SkipTests) {
        Write-Host "== Test gate: unit tests + self-test =="
        python -m unittest discover -s tests
        if ($LASTEXITCODE -ne 0) { throw "unit tests failed" }
        python $Config.source_file --self-test
        if ($LASTEXITCODE -ne 0) { throw "self-test failed" }
    }

    Write-Host "== PyInstaller: $($Config.exe_name) =="
    python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) {
        python -m pip install "pyinstaller>=6,<7"
        if ($LASTEXITCODE -ne 0) { throw "pip install pyinstaller failed" }
    }
    python -m PyInstaller --noconfirm --clean `
        (Join-Path $PackagingDir "pyinstaller.spec") `
        --distpath (Join-Path $RepoRoot "dist") `
        --workpath (Join-Path $RepoRoot "build\pyinstaller")
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }
    if (-not (Test-Path $ExePath)) { throw "exe not produced: $ExePath" }

    Write-Host "== Smoke test (exit codes; windowed exe has no console) =="
    foreach ($arg in "--version", "--self-test") {
        $p = Start-Process $ExePath -ArgumentList $arg -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "exe $arg exited $($p.ExitCode)" }
    }

    if ($SkipInno) {
        Write-Host "Built: $ExePath"
        return
    }

    Write-Host "== Inno Setup: $($Config.setup_name) =="
    $Iscc = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Source -First 1
    if (-not $Iscc) {
        foreach ($cand in @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
            "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) {
            if (Test-Path $cand) { $Iscc = $cand; break }
        }
    }
    if (-not $Iscc) {
        throw "ISCC.exe not found. Install Inno Setup 6 from https://jrsoftware.org/isdl.php (or: choco install innosetup)"
    }
    & $Iscc `
        "/DMyAppId=$($Config.app_id)" `
        "/DMyAppName=$($Config.display_name)" `
        "/DMyAppVersion=$($Config.version)" `
        "/DMyAppPublisher=$($Config.publisher)" `
        "/DMyExeName=$($Config.exe_name)" `
        "/DMyInstallFolder=$($Config.install_folder)" `
        "/DMySetupBaseName=$([IO.Path]::GetFileNameWithoutExtension($Config.setup_name))" `
        "/DMySourceExe=$ExePath" `
        "/DMyOutputDir=$(Join-Path $RepoRoot 'dist')" `
        (Join-Path $PackagingDir "setup.iss")
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup compile failed" }
    if (-not (Test-Path $SetupPath)) { throw "installer not produced: $SetupPath" }

    Write-Host ""
    Write-Host "Built:"
    Write-Host "  $ExePath"
    Write-Host "  $SetupPath"
    Write-Host "Unsigned: first run shows SmartScreen - 'More info' -> 'Run anyway'."
}
finally {
    Pop-Location
}
