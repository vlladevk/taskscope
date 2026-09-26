# Сборка под Windows внутри Docker (Linux-контейнер + cargo-xwin).
# Примеры:
#   .\scripts\build.ps1                 # release-сборка tm.exe → dist\
#   .\scripts\build.ps1 -Debug          # debug-сборка
#   .\scripts\build.ps1 -Test           # собрать тесты tm-core в контейнере и запустить их здесь, в Windows
#   .\scripts\build.ps1 -Cargo "check"  # произвольная команда cargo xwin
param(
    [switch]$Debug,
    [switch]$Test,
    [string]$Cargo = ""
)
# Continue: PowerShell 5.1 иначе считает вывод docker в stderr ошибкой
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

# Работающий движок держит dist\tm.exe открытым — останавливаем на время сборки и потом запускаем снова.
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
    # ждём, пока приложение и его WebView действительно закроются и отпустят exe
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ((Get-Process tm-app -ErrorAction SilentlyContinue) -and $sw.Elapsed.TotalSeconds -lt 10) { Start-Sleep -Milliseconds 200 }
    Start-Sleep -Milliseconds 500
}

# Кэши в именованных томах: реестр crates, xwin SDK и target — сборка остаётся быстрой между запусками.
$dockerArgs = @(
    'run', '--rm',
    '--name', 'tm-build-run',   # фиксированное имя: второй параллельный запуск Docker не даст создать
    '--cpus', '6',              # оставляем часть ядер системе, чтобы компьютер не подтормаживал
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
if ($code -ne 0) { throw "Сборка упала (код $code)" }

if ($Test) {
    & (Join-Path $root 'dist\tests\tm_core_tests.exe')
    if ($LASTEXITCODE -ne 0) { throw "Тесты упали" }
} else {
    Get-ChildItem (Join-Path $root 'dist') -Filter *.exe | Select-Object Name, Length, LastWriteTime
}
