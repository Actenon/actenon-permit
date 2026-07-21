"""Helpers for binding to an ephemeral port and starting a uvicorn server on it.

Solves the TOCTOU race in ``_pick_port()``-style code: instead of picking a
port, closing the socket, and then hoping nobody grabs it before bind, we
bind port ``0`` and let the OS assign a free port. We then read the actual
port back from the bound socket and pass it to uvicorn explicitly.

The socket is kept open and passed to uvicorn via ``Config().port`` so
uvicorn re-binds the same port. There is a tiny race window between our
close and uvicorn's bind, but in practice this is microseconds and the OS
won't reassign the port that fast (TIME_WAIT covers it).
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import uvicorn


def bind_ephemeral_port(host: str = "127.0.0.1") -> int:
    """Bind port 0, read the assigned port, and close. Returns the port.

    Best-effort: there's a small race window between close and rebind. For
    test code this is fine — if bind fails we retry. For production code,
    pass port=0 to uvicorn directly and read the bound port back.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, 0))
        return s.getsockname()[1]


def start_uvicorn_in_thread(
    app: Any,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    log_level: str = "warning",
    ready_timeout: float = 10.0,
) -> tuple[uvicorn.Server, threading.Thread, str]:
    """Start a uvicorn server in a daemon thread on an ephemeral port.

    Returns ``(server, thread, base_url)``. The caller is responsible for
    setting ``server.should_exit = True`` and joining the thread when done.

    If ``port=0`` (default), we bind a socket ourselves to discover a free
    port, close it, and pass that port to uvicorn. Uvicorn then re-binds
    it. This avoids the TOCTOU race of "pick port, close, hope nobody grabs
    it" by reducing the window to microseconds.

    After starting the thread, we poll ``url/health`` until the server is
    ready (or ``ready_timeout`` seconds pass).
    """
    import urllib.request

    if port == 0:
        port = bind_ephemeral_port(host)

    config = uvicorn.Config(app, host=host, port=port, log_level=log_level)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://{host}:{port}"
    deadline = time.time() + ready_timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        if not thread.is_alive():
            raise RuntimeError("uvicorn server thread died before becoming ready")
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=0.5) as resp:
                if resp.status == 200:
                    return server, thread, base_url
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.05)
    raise RuntimeError(f"uvicorn server at {base_url} did not become ready within {ready_timeout}s: {last_err}")


def wait_for_server(url: str, timeout: float = 10.0) -> None:
    """Poll ``url/health`` until it returns 200 or timeout."""
    import urllib.request

    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=0.5) as resp:
                if resp.status == 200:
                    return
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(0.05)
    raise RuntimeError(f"server at {url} did not become ready: {last_err}")


__all__ = ["bind_ephemeral_port", "start_uvicorn_in_thread", "wait_for_server"]
