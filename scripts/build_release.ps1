<#
.SYNOPSIS
    Build a USBHawk release: the standalone Windows exe, the Python wheel, smoke tests on both, and SHA-256 hashes.

.DESCRIPTION
    Run from anywhere, with the project's .venv set up (pip install -e ".[dev,build]"):

        powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1
        powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1 -SkipTests     # skip pytest (not for releases)

    Writes to dist\:
        usbhawk-<version>-windows-x64.zip     usbhawk.exe + README, LICENSE, CHANGELOG, docs, examples, ideas, config,
                                              the dataset fetch scripts, collect_local.ps1 (live collection) and the lab Sysmon config
        usbhawk-<version>-py3-none-any.whl    the Python package (pip install it; Python 3.11+)
        SHA256SUMS.txt                        hashes of both

    Every step must succeed: the test suite, both builds, and scripts\smoke_test.py run against the exe (from the
    unzipped release folder) and against the wheel installed into a fresh virtual environment.
#>
param([switch]$SkipTests)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "No .venv found. Run: py -3 -m venv .venv; .\.venv\Scripts\pip install -e "".[dev,build]""" }

function Invoke-Native {
    # Native tools write progress to stderr; in Windows PowerShell 5.1 that must not count as failure. Exit code does.
    param([string]$What, [string]$Exe, [string[]]$Arguments)
    Write-Host "==> $What" -ForegroundColor Cyan
    $old = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    & $Exe @Arguments
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    if ($code -ne 0) { throw "$What failed (exit $code)" }
}

Push-Location $root
try {
    $version = (& $py -c "import usbhawk; print(usbhawk.__version__)").Trim()
    $name = "usbhawk-$version-windows-x64"
    $dist = Join-Path $root "dist"
    $work = Join-Path $root "build\release"
    Write-Host "USBHawk $version release build" -ForegroundColor Green

    foreach ($d in @($dist, $work)) { if (Test-Path $d) { Remove-Item -Recurse -Force $d } }
    New-Item -ItemType Directory -Force $dist, $work | Out-Null

    if (-not $SkipTests) {
        Invoke-Native "test suite" $py @("-m", "pytest", "-q")
    } else {
        Write-Host "==> test suite SKIPPED (-SkipTests): not a release build" -ForegroundColor Yellow
    }

    # ------------------------------------------------------------------ wheel
    Invoke-Native "build the wheel" $py @("-m", "pip", "wheel", "--no-deps", "--wheel-dir", $dist, $root)
    $wheel = Get-ChildItem $dist -Filter "usbhawk-$version-*.whl" | Select-Object -First 1
    if (-not $wheel) { throw "wheel not found in $dist" }

    # ------------------------------------------------------------------ exe
    $verFile = Join-Path $work "version_info.txt"
    $v = ($version.Split(".") + @("0", "0", "0"))[0..3] -join ", "
    @"
VSVersionInfo(
  ffi=FixedFileInfo(filevers=($v), prodvers=($v), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
                    date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
      StringStruct('ProductName', 'USBHawk'),
      StringStruct('FileDescription', 'USBHawk - USB forensics for threat hunting and incident response'),
      StringStruct('FileVersion', '$version'),
      StringStruct('ProductVersion', '$version'),
      StringStruct('OriginalFilename', 'usbhawk.exe'),
      StringStruct('LegalCopyright', 'MIT License')])]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])])]
)
"@ | Set-Content -Encoding utf8 $verFile

    $rules = Join-Path $root "src\usbhawk\detections\rules"
    Invoke-Native "build usbhawk.exe (PyInstaller, one file)" $py @(
        "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--console", "--name", "usbhawk",
        "--distpath", (Join-Path $work "exe"), "--workpath", (Join-Path $work "pyinstaller"), "--specpath", $work,
        "--paths", (Join-Path $root "src"),
        "--add-data", "$rules;usbhawk\detections\rules",
        "--collect-data", "tzdata",
        "--version-file", $verFile,
        (Join-Path $root "src\usbhawk\__main__.py"))

    # ------------------------------------------------------------------ release folder + zip
    $rel = Join-Path $work $name
    New-Item -ItemType Directory -Force $rel, (Join-Path $rel "scripts") | Out-Null
    Copy-Item (Join-Path $work "exe\usbhawk.exe") $rel
    foreach ($f in @("README.md", "LICENSE", "CHANGELOG.md")) { Copy-Item (Join-Path $root $f) $rel }
    foreach ($d in @("docs", "examples", "ideas", "config")) { Copy-Item -Recurse (Join-Path $root $d) $rel }
    foreach ($f in @("fetch_demo_datasets.py", "fetch_test_samples.py", "collect_local.ps1")) {
        Copy-Item (Join-Path $root "scripts\$f") (Join-Path $rel "scripts")
    }
    # The lab Sysmon config the docs tell responders to install (GETTING-STARTED, "Turn on the telemetry")
    New-Item -ItemType Directory -Force (Join-Path $rel "scripts\lab") | Out-Null
    Copy-Item (Join-Path $root "scripts\lab\sysmon-usbhawk-lab.xml") (Join-Path $rel "scripts\lab")
    # Every file the docs send users to inside the release folder must be there
    foreach ($need in @("scripts\collect_local.ps1", "scripts\lab\sysmon-usbhawk-lab.xml", "config\scoring.toml",
                        "examples\tamper\wiped-host\Windows\System32\config\SYSTEM", "docs\GETTING-STARTED.md")) {
        if (-not (Test-Path (Join-Path $rel $need))) { throw "release folder is missing $need" }
    }
    $zip = Join-Path $dist "$name.zip"
    # Python's zipfile, not Compress-Archive: Windows PowerShell 5.1 writes "\" in entry names (against the zip
    # spec), which unzip on Linux/macOS turns into flat files named "usbhawk-1.0.1-windows-x64\docs\...".
    Invoke-Native "zip the release folder" $py @("-m", "zipfile", "-c", $zip, $rel)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($zip)
    try { $bad = @($archive.Entries | Where-Object { $_.FullName.Contains("\") } | ForEach-Object { $_.FullName }) }
    finally { $archive.Dispose() }
    if ($bad.Count) { throw "backslash in zip entry names: $($bad[0..2] -join ', ')" }

    # ------------------------------------------------------------------ smoke tests
    $samples = Join-Path $root "tests\data"
    $unzipped = Join-Path $work "unzipped"
    Expand-Archive -Path $zip -DestinationPath $unzipped
    $exe = Join-Path $unzipped "$name\usbhawk.exe"
    Invoke-Native "smoke test: usbhawk.exe from the zip" $py @(
        (Join-Path $root "scripts\smoke_test.py"), "--usbhawk", $exe, "--examples", (Join-Path $unzipped "$name\examples"),
        "--triage", $samples, "--version", $version)

    $venv = Join-Path $work "wheel-venv"
    Invoke-Native "fresh virtual environment for the wheel" $py @("-m", "venv", $venv)
    Invoke-Native "install the wheel" (Join-Path $venv "Scripts\python.exe") @("-m", "pip", "install", "-q", $wheel.FullName)
    Invoke-Native "smoke test: the wheel" $py @(
        (Join-Path $root "scripts\smoke_test.py"), "--usbhawk", (Join-Path $venv "Scripts\usbhawk.exe"),
        "--examples", (Join-Path $root "examples"), "--triage", $samples, "--version", $version)

    # ------------------------------------------------------------------ hashes
    # LF line endings and plain ASCII, so `sha256sum -c SHA256SUMS.txt` works on Linux and macOS too (Set-Content
    # writes CRLF, and sha256sum then looks for files named "...whl\r").
    $sums = Join-Path $dist "SHA256SUMS.txt"
    $lines = Get-ChildItem $dist -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | Sort-Object Name | ForEach-Object {
        "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
    }
    [IO.File]::WriteAllText($sums, (($lines -join "`n") + "`n"), [Text.Encoding]::ASCII)
    if ((Get-Content $sums -Raw) -match "`r") { throw "SHA256SUMS.txt must use LF line endings" }

    Write-Host ""
    Write-Host "Release $version built and smoke-tested:" -ForegroundColor Green
    Get-ChildItem $dist -File | ForEach-Object { "  {0,-42} {1,12:N0} bytes" -f $_.Name, $_.Length }
    Get-Content $sums | ForEach-Object { "  $_" }
}
finally {
    Pop-Location
}
