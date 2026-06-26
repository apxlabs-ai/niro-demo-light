# Windows equivalent of start.sh. Same UX: ensure venv, install deps,
# seed DB, background uvicorn on :8000, poll /health, exit when ready.
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($env:HELPDESK_SECRET) -or $env:HELPDESK_SECRET -eq 'dev-secret-do-not-use-in-prod') {
    throw 'HELPDESK_SECRET must be set to a non-placeholder JWT signing secret.'
}

# Find a usable Python. The Microsoft Store stub at
# %LOCALAPPDATA%\Microsoft\WindowsApps\python.exe is not a real Python
# - it prints a "not found" hint to stderr. Filter by requiring that
# `--version` outputs a real "Python 3.x" string with exit code 0.
function Find-Python {
    $candidates = @(
        @{ Exe = 'py';      Args = @('-3') },
        @{ Exe = 'python3'; Args = @() },
        @{ Exe = 'python';  Args = @() }
    )
    foreach ($c in $candidates) {
        $cmd = Get-Command $c.Exe -ErrorAction SilentlyContinue
        if (-not $cmd) { continue }
        try {
            $out = & $cmd.Source @($c.Args + '--version') 2>$null | Out-String
        } catch { continue }
        if ($LASTEXITCODE -eq 0 -and $out -match 'Python\s+3\.') {
            return @{ Exe = $cmd.Source; Args = $c.Args }
        }
    }
    $roots = @(
        "$env:LOCALAPPDATA\Programs\Python",
        "$env:ProgramFiles\Python*",
        "${env:ProgramFiles(x86)}\Python*"
    )
    foreach ($root in $roots) {
        $exes = Get-ChildItem -Path $root -Filter 'python.exe' -Recurse -ErrorAction SilentlyContinue
        foreach ($exe in $exes) {
            try {
                $out = & $exe.FullName --version 2>$null | Out-String
            } catch { continue }
            if ($LASTEXITCODE -eq 0 -and $out -match 'Python\s+3\.') {
                return @{ Exe = $exe.FullName; Args = @() }
            }
        }
    }
    throw "no Python 3 found - install from python.org or via 'winget install Python.Python.3.12'"
}

$py = Find-Python
$vpy = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'

if (-not (Test-Path $vpy)) {
    & $py.Exe @($py.Args + @('-m', 'venv', '.venv'))
    if ($LASTEXITCODE -ne 0) { throw "venv creation failed" }
}

& $vpy -m pip install --quiet --disable-pip-version-check -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

& $vpy seed.py
if ($LASTEXITCODE -ne 0) { throw "seed.py failed" }

# Background uvicorn. Start-Process with -WindowStyle Hidden detaches it
# from this shell so the server survives this session ending. stop.ps1
# finds it by port (Get-NetTCPConnection :8000), so no PID file needed.
# Two log files because Start-Process can't merge stdout/stderr to one
# file the way bash's `2>&1` can.
$uvicorn = Join-Path $PSScriptRoot '.venv\Scripts\uvicorn.exe'
$null = Start-Process -FilePath $uvicorn `
    -ArgumentList @('app.main:app','--host','0.0.0.0','--port','8000','--reload') `
    -RedirectStandardOutput 'helpdesk.log' `
    -RedirectStandardError 'helpdesk.err.log' `
    -WindowStyle Hidden `
    -PassThru

# Wait until /health responds, then exit clean.
for ($i = 0; $i -lt 60; $i++) {
    try {
        $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/health' -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
        if ($r.StatusCode -eq 200) {
            Write-Output "-> helpdesk ready on http://127.0.0.1:8000 (logs: .\helpdesk.log, .\helpdesk.err.log)"
            exit 0
        }
    } catch { }
    Start-Sleep -Milliseconds 500
}

Write-Error "helpdesk failed to start within 30s; see .\helpdesk.log and .\helpdesk.err.log"
exit 1
