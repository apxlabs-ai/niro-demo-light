#!/usr/bin/env python3
"""Detached uvicorn lifecycle for the Niro harness.

Brings up the working-tree app on two listeners, both serving from RUN_DIR so
the sqlite DB stays under harness/run/ (source tree untouched):

  * port 8000 — plain HTTP, Bearer-token auth.
  * port 8443 — HTTPS + mTLS (ssl-cert-reqs=CERT_REQUIRED); client identity is
    the cert CN. Certs come from niro/certs/ (see niro/gen-certs.sh).
"""
from __future__ import annotations

import http.client
import os
import signal
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib import request

CONFIG_DIR = Path(__file__).resolve().parents[1]
DEFAULT_PROJECT_ROOT = CONFIG_DIR.parent
PROJECT_ROOT = Path(os.environ.get("NIRO_PROJECT_ROOT", DEFAULT_PROJECT_ROOT)).resolve()
RUN_DIR = CONFIG_DIR / "harness" / "run"
CERTS = CONFIG_DIR / "certs"
PYTHON = PROJECT_ROOT / ".venv" / "bin" / "python"

HTTP_PORT = 8000
TLS_PORT = 8443

PID_FILE = RUN_DIR / "uvicorn.pid"
LOG_FILE = RUN_DIR / "uvicorn.log"
TLS_PID_FILE = RUN_DIR / "uvicorn-tls.pid"
TLS_LOG_FILE = RUN_DIR / "uvicorn-tls.log"

HEALTH_URL = f"http://127.0.0.1:{HTTP_PORT}/health"


def _is_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_pid(pid_file: Path) -> int | None:
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _stop_one(pid_file: Path) -> None:
    pid = _read_pid(pid_file)
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
        pid_file.unlink()
    except FileNotFoundError:
        pass


def stop() -> None:
    _stop_one(PID_FILE)
    _stop_one(TLS_PID_FILE)


def _base_env() -> dict[str, str]:
    env = os.environ.copy()
    harness_pythonpath = str(CONFIG_DIR / "harness" / "pythonpath")
    path_entries = [str(PROJECT_ROOT), harness_pythonpath]
    if env.get("PYTHONPATH"):
        path_entries.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = ":".join(path_entries)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _spawn(args: list[str], log_file: Path) -> int:
    log = log_file.open("ab")
    proc = subprocess.Popen(
        [str(PYTHON), "-m", "uvicorn", *args],
        cwd=RUN_DIR,
        env=_base_env(),
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        close_fds=True,
        start_new_session=True,
    )
    return proc.pid


def _wait_for_http_health() -> None:
    deadline = time.time() + 30
    last_error = "not attempted"
    while time.time() < deadline:
        try:
            with request.urlopen(HEALTH_URL, timeout=2) as resp:
                if resp.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"HTTP target did not become healthy within 30s: {last_error}")


def _mtls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=str(CERTS / "ca.crt"))
    ctx.load_cert_chain(
        certfile=str(CERTS / "client-agent.crt"),
        keyfile=str(CERTS / "client-agent.key"),
    )
    # The server cert CN is not a hostname (it identifies the service, and
    # clients connect by IP); the CA pin above is what authenticates it.
    ctx.check_hostname = False
    return ctx


def _wait_for_tls_health() -> None:
    deadline = time.time() + 30
    last_error = "not attempted"
    ctx = _mtls_context()
    while time.time() < deadline:
        try:
            conn = http.client.HTTPSConnection("127.0.0.1", TLS_PORT, context=ctx, timeout=2)
            conn.request("GET", "/health")
            resp = conn.getresponse()
            status = resp.status
            resp.read()
            conn.close()
            if status == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(0.5)
    raise RuntimeError(f"mTLS target did not become healthy within 30s: {last_error}")


def _start_http() -> None:
    pid = _read_pid(PID_FILE)
    if pid is not None and _is_alive(pid):
        _wait_for_http_health()
        print(f"-> harness uvicorn (http) already running pid {pid}")
        return
    new_pid = _spawn(
        [
            "app.main:app",
            "--host", "0.0.0.0",
            "--port", str(HTTP_PORT),
        ],
        LOG_FILE,
    )
    PID_FILE.write_text(f"{new_pid}\n", encoding="utf-8")
    _wait_for_http_health()
    print(f"-> harness uvicorn ready on http://127.0.0.1:{HTTP_PORT} pid {new_pid}")


def _start_tls() -> None:
    pid = _read_pid(TLS_PID_FILE)
    if pid is not None and _is_alive(pid):
        _wait_for_tls_health()
        print(f"-> harness uvicorn (mTLS) already running pid {pid}")
        return
    new_pid = _spawn(
        [
            "app.main:app",
            "--host", "0.0.0.0",
            "--port", str(TLS_PORT),
            "--ssl-keyfile", str(CERTS / "server.key"),
            "--ssl-certfile", str(CERTS / "server.crt"),
            "--ssl-ca-certs", str(CERTS / "ca.crt"),
            "--ssl-cert-reqs", "2",
        ],
        TLS_LOG_FILE,
    )
    TLS_PID_FILE.write_text(f"{new_pid}\n", encoding="utf-8")
    _wait_for_tls_health()
    print(f"-> harness uvicorn ready on https://127.0.0.1:{TLS_PORT} (mTLS) pid {new_pid}")


def start() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    _start_http()
    _start_tls()


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"start", "stop"}:
        raise SystemExit("usage: serve.py start|stop")
    if sys.argv[1] == "start":
        start()
    else:
        stop()


if __name__ == "__main__":
    main()
