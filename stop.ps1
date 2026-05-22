# Windows equivalent of stop.sh. Stop whatever is listening on port 8000
# (the helpdesk server started by start.ps1). Safe to run when nothing is
# listening — exits silently.
$ErrorActionPreference = 'Stop'

$port = if ($env:PORT) { [int]$env:PORT } else { 8000 }

$conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if (-not $conns) {
    Write-Output "nothing listening on port $port"
    exit 0
}

# Unique PIDs (multiple bindings can share one process).
$pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique

# uvicorn --reload spawns a worker child; killing only the listener can
# leave the worker holding state. Walk the children too, then stop the
# whole set in one go.
$all = New-Object System.Collections.Generic.HashSet[int]
foreach ($p in $pids) { [void]$all.Add([int]$p) }
foreach ($p in $pids) {
    Get-CimInstance Win32_Process -Filter "ParentProcessId=$p" -ErrorAction SilentlyContinue |
        ForEach-Object { [void]$all.Add([int]$_.ProcessId) }
}

$ids = [int[]]@($all)
Stop-Process -Id $ids -Force -ErrorAction SilentlyContinue
Write-Output "stopped pid(s) on port ${port}: $($ids -join ' ')"
