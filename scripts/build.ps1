# Windows build inside Docker (a Linux container + cargo-xwin).
# Examples:
#   .\scripts\build.ps1                 # release build of tm.exe → dist\
#   .\scripts\build.ps1 -Debug          # debug build
#   .\scripts\build.ps1 -Test           # build the tm-core tests in the container and run them here, on Windows
#   .\scripts\build.ps1 -Cargo "check"  # an arbitrary cargo xwin command
param(
    [switch]$Debug,
    [switch]$Test,
    [string]$Cargo = ""
)
# Continue: otherwise PowerShell 5.1 treats docker output on stderr as an error
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$profileDir = if ($Debug) { 'debug' } else { 'release' }
$target = 'x86_64-pc-windows-msvc'
$release = if ($Debug) { '' } else { ' --release' }
$tmExe = Join-Path $root 'dist\tm.exe'

$copy = "mkdir -p /src/dist && find /target/$target/$profileDir -maxdepth 1 -name '*.exe' -exec cp {} /src/dist/ \;"
if ($Test) {
    $Cargo = "test --no-run --target $target$release -p tm-core"
    $copy = "mkdir -p /src/dist/tests && cp `$(ls -t /target/$target/$profileDir/deps/tm_core-*.exe | head -1) /src/dist/tests/tm_core_tests.exe"
} elseif (-not $Cargo) {
    $Cargo = "build --target $target$release"
}

# A running engine keeps dist\tm.exe open — stop it for the build and start it again afterwards.
$wasRunning = $false
$appExe = Join-Path $root 'dist\tm-app.exe'
$wasApp = $false
if (-not $Test -and (Test-Path $tmExe)) {
    $st = & $tmExe daemon status --json 2>$null | Out-String
    if ($st -match '"running":\s*true') {
        $wasRunning = $true
        $wasApp = [bool](Get-Process tm-app -ErrorAction SilentlyContinue)
        & $tmExe daemon stop | Out-Null
    }
    # wait until the app and its WebView have really closed and released the exe
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-Process tm-app -ErrorAction SilentlyContinue) -and $sw.Elapsed.TotalSeconds -lt 10) { Start-Sleep -Milliseconds 200 }
    Start-Sleep -Milliseconds 500
}

# Caches in named volumes: the crates registry, the xwin SDK and target — the build stays fast between runs.
$dockerArgs = @(
    'run', '--rm',
    '--name', 'tm-build-run',   # a fixed name: Docker will not let a second parallel run start
    '--cpus', '6',              # leave some cores to the system so the computer does not lag
    '-v', "${root}:/src",
    '-v', 'tm-cargo-registry:/usr/local/cargo/registry',
    '-v', 'tm-xwin-cache:/xwin-cache',
    '-v', 'tm-target:/target',
    'tm-build',
    'sh', '-c', "cargo xwin $Cargo && $copy"
)
& docker @dockerArgs 2>&1 | ForEach-Object { "$_" }
$code = $LASTEXITCODE

if ($wasRunning) {
    if ($wasApp) { Start-Process $appExe -ArgumentList '--tray' } else { & $tmExe daemon start | Out-Null }
}
if ($code -ne 0) { throw "Build failed (code $code)" }

if ($Test) {
    & (Join-Path $root 'dist\tests\tm_core_tests.exe')
    if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
} else {
    Get-ChildItem (Join-Path $root 'dist') -Filter *.exe | Select-Object Name, Length, LastWriteTime
}
