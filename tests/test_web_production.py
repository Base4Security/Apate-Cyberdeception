"""Regresiones de la instalación WSGI, proxy reverso y cookies de producción."""

from __future__ import annotations

import importlib
import sys
from unittest.mock import Mock, patch

from flask import url_for

from apate.web import create_app
from apate.web import __main__ as web_main


def _app(tmp_path, **overrides):
    config = {
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "data",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
    }
    config.update(overrides)
    return create_app(config)


def test_wsgi_entrypoint_imports_app_without_starting_server(monkeypatch):
    fake_app = object()
    monkeypatch.setattr("apate.web.create_app", lambda: fake_app)
    sys.modules.pop("apate.web.wsgi", None)

    module = importlib.import_module("apate.web.wsgi")

    assert module.app is fake_app


def test_configuracion_de_produccion_toma_directorio_y_proxy_desde_entorno(tmp_path, monkeypatch):
    data_dir = tmp_path / "datos-de-produccion"
    monkeypatch.setenv("APATE_DATA_DIR", str(data_dir))
    monkeypatch.setenv("APATE_TRUSTED_PROXY", "1")
    monkeypatch.setenv("APATE_MOUNT_EXTERNAL_TOOLS", "0")

    app = create_app({"TESTING": True})

    assert app.config["APATE_DATA_DIR"] == data_dir
    assert app.config["APATE_RULES_PATH"] == data_dir / "rules.yaml"
    assert app.config["APATE_MOUNT_EXTERNAL_TOOLS"] is False
    assert app.config["APATE_TRUSTED_PROXY"] is True
    assert app.config["SESSION_COOKIE_SECURE"] is True


def test_trusted_proxy_uses_https_for_external_urls_and_secure_cookie(tmp_path):
    app = _app(tmp_path, APATE_TRUSTED_PROXY=True)

    @app.get("/absolute-url")
    def absolute_url():
        return url_for("index", _external=True)

    client = app.test_client()
    headers = {
        "X-Forwarded-For": "203.0.113.10",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "apate.example",
    }

    response = client.get("/absolute-url", headers=headers)
    session_response = client.post("/operator", data={"operator": "Ana"}, headers=headers)

    assert response.get_data(as_text=True) == "https://apate.example/"
    cookie = session_response.headers["Set-Cookie"]
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_cookie_de_desarrollo_sigue_marcada_con_http_only_y_same_site(tmp_path):
    app = _app(tmp_path)

    response = app.test_client().post("/operator", data={"operator": "Ana"})

    cookie = response.headers["Set-Cookie"]
    assert "Secure" not in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_servidor_de_desarrollo_advierte_si_se_expone(monkeypatch):
    app = Mock()
    app.extensions = {"socketio": Mock()}
    monkeypatch.setattr(web_main, "create_app", lambda: app)
    monkeypatch.setenv("APATE_DEV_HOST", "0.0.0.0")

    web_main.main()

    app.logger.warning.assert_called_once()
    # `port` y `allow_unsafe_werkzeug` se sumaron con E1 de
    # docs/improvements.md; lo que este test cuida es la advertencia al
    # exponer el host, no la lista completa de kwargs.
    app.extensions["socketio"].run.assert_called_once_with(
        app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True
    )


def test_wsgi_entry_point_serves_over_a_real_wsgi_server(tmp_path, monkeypatch):
    """El contrato WSGI se verifica con un servidor real, no con el cliente de
    pruebas de Flask: el objetivo de la fase era que gunicorn pudiera importar y
    servir la app, y el test client nunca pasa por el stack WSGI completo.

    Gunicorn en sí no se puede probar acá (no corre en Windows, donde se
    desarrolla el proyecto), pero `wsgiref` de la biblioteca estándar valida lo
    mismo que gunicorn necesita: que `apate.web.wsgi:app` sea importable sin
    argumentos y responda como aplicación WSGI.
    """

    import importlib
    import threading
    import urllib.request
    from wsgiref.simple_server import make_server

    monkeypatch.setenv("APATE_DATA_DIR", str(tmp_path))

    modulo = importlib.reload(importlib.import_module("apate.web.wsgi"))
    aplicacion = modulo.app

    servidor = make_server("127.0.0.1", 0, aplicacion)
    puerto = servidor.server_address[1]
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{puerto}/", timeout=10) as respuesta:
            assert respuesta.status == 200
            assert respuesta.read()
    finally:
        servidor.shutdown()
        hilo.join(timeout=5)
