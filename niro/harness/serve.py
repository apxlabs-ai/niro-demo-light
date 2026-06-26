#!/usr/bin/env python3
"""Detached uvicorn lifecycle for the Niro harness."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib import request

CONFIG_DIR = Path(__file__).resolve().parents[1]
DEFAULT_PROJECT_ROOT = CONFIG_DIR.parent
PROJECT_ROOT = Path(os.environ.get("NIRO_PROJECT_ROOT", DEFAULT_PROJECT_ROOT)).resolve()
RUN_DIR = CONFIG_DIR / "harness" / "run"
PID_FILE = RUN_DIR / "uvicorn.pid"
LOG_FILE = RUN_DIR / "uvicorn.log"
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"
HEALTH_URL = "http://127.0.0.1:8000/health"


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_pid() -> int | None:
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def stop() -> None:
    pid = _read_pid()
    if pid is not None and _is_alive(pid):
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 10
        while time.time() < deadline:
            if not _is_alive(pid):
                break
            time.sleep(0.2)
        if _is_alive(pid):
            os.kill(pid, signal.SIGKILL)
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass


def _wait_for_health() -> None:
    deadline = time.time() + 30
    last_error = "not attempted"
    while time.time() < deadline:
        try:
            with request.urlopen(HEALTH_URL, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"target did not become healthy within 30s: {last_error}")


def start() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    pid = _read_pid()
    if pid is not None and _is_alive(pid):
        _wait_for_health()
        print(f"-> harness uvicorn already running pid {pid}")
        return

    env = os.environ.copy()
    harness_pythonpath = str(CONFIG_DIR / "harness" / "pythonpath")
    path_entries = [str(PROJECT_ROOT), harness_pythonpath]
    if env.get("PYTHONPATH"):
        path_entries.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = ":".join(path_entries)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    log = LOG_FILE.open("ab")
    proc = subprocess.Popen(
        [
            str(PYTHON),
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "0.0.0.0",
            "--port",
            "8000",
        ],
        cwd=RUN_DIR,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        close_fds=True,
        start_new_session=True,
    )
    PID_FILE.write_text(f"{proc.pid}\n", encoding="utf-8")
    _wait_for_health()
    print(f"-> harness uvicorn ready on http://127.0.0.1:8000 pid {proc.pid}")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"start", "stop"}:
        raise SystemExit("usage: serve.py start|stop")
    if sys.argv[1] == "start":
        start()
    else:
        stop()


if __name__ == "__main__":
    main()
