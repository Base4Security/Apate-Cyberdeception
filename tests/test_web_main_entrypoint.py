"""`python -m apate.web` -- E1 de docs/improvements.md.

El comando documentado para desarrollo moria en el arranque cuando stdin
no es un TTY: Flask-SocketIO exige `allow_unsafe_werkzeug=True` en ese
caso (`if not sys.stdin or not sys.stdin.isatty()`), asi que funcionaba
desde una terminal interactiva y fallaba bajo `nohup`, `&`, un script de
arranque o CI. Ademas el puerto no era configurable, y el default 5000
lo ocupa AirPlay Receiver en macOS.
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from apate.web import __main__ as entrypoint


# -- Puerto configurable -------------------------------------------------


def test_port_defaults_to_5000_without_env_var(monkeypatch):
    monkeypatch.delenv("APATE_DEV_PORT", raising=False)
    assert entrypoint._development_port() == 5000


def test_port_comes_from_env_var(monkeypatch):
    monkeypatch.setenv("APATE_DEV_PORT", "5055")
    assert entrypoint._development_port() == 5055


def test_invalid_port_falls_back_to_default_instead_of_crashing(monkeypatch):
    for value in ("", "   ", "no-es-un-numero", "80.5"):
        monkeypatch.setenv("APATE_DEV_PORT", value)
        assert entrypoint._development_port() == 5000


# -- La llamada real a socketio.run() ------------------------------------


class _FakeSocketIO:
    def __init__(self) -> None:
        self.kwargs: dict = {}

    def run(self, app, **kwargs) -> None:
        self.kwargs = kwargs


class _FakeApp:
    def __init__(self, socketio: _FakeSocketIO) -> None:
        self.extensions = {"socketio": socketio}
        self.logger = logging.getLogger("apate-test")


@pytest.fixture
def captured_run(monkeypatch):
    fake_socketio = _FakeSocketIO()
    monkeypatch.setattr(entrypoint, "create_app", lambda: _FakeApp(fake_socketio))
    return fake_socketio


def test_main_allows_werkzeug_so_a_non_tty_launch_does_not_crash(captured_run, monkeypatch):
    monkeypatch.delenv("APATE_DEV_PORT", raising=False)
    entrypoint.main()
    assert captured_run.kwargs["allow_unsafe_werkzeug"] is True


def test_main_passes_the_configured_port(captured_run, monkeypatch):
    monkeypatch.setenv("APATE_DEV_PORT", "5099")
    entrypoint.main()
    assert captured_run.kwargs["port"] == 5099


def test_main_keeps_the_host_and_debug_contract(captured_run, monkeypatch):
    monkeypatch.delenv("APATE_DEBUG", raising=False)
    monkeypatch.setenv("APATE_DEV_HOST", "127.0.0.1")
    entrypoint.main()
    assert captured_run.kwargs["host"] == "127.0.0.1"
    assert captured_run.kwargs["debug"] is False


# -- Regresion real: arrancar de verdad sin TTY --------------------------


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_module_actually_serves_when_stdin_is_not_a_tty(tmp_path):
    """Reproduce el fallo original de punta a punta.

    Es la unica forma de cubrir E1 de verdad: la guarda de Flask-SocketIO
    depende de `sys.stdin.isatty()`, que en el proceso de pytest no
    coincide necesariamente con el del servidor. Se lanza el modulo como
    subproceso con stdin cerrado, que es exactamente el caso que fallaba.
    """

    port = _free_port()
    env = {
        **os.environ,
        "APATE_DATA_DIR": str(tmp_path / "datos"),
        "APATE_DEV_PORT": str(port),
        "APATE_DEBUG": "",
        "APATE_MOUNT_EXTERNAL_TOOLS": "False",
    }
    proceso = subprocess.Popen(
        [sys.executable, "-m", "apate.web"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        text=True,
    )
    try:
        limite = time.monotonic() + 30
        ultimo_error: Exception | None = None
        while time.monotonic() < limite:
            if proceso.poll() is not None:
                pytest.fail(f"El servidor murio en el arranque:\n{proceso.stdout.read()}")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/operations/", timeout=2) as r:
                    assert r.status == 200
                    return
            except (urllib.error.URLError, OSError) as exc:  # todavia no escucha
                ultimo_error = exc
                time.sleep(0.3)
        pytest.fail(f"El servidor no respondio en el puerto {port}: {ultimo_error}")
    finally:
        proceso.terminate()
        try:
            proceso.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proceso.kill()
            proceso.wait(timeout=10)
