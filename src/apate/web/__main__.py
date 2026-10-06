"""Punto de entrada para `python -m apate.web`: levanta el servidor de
desarrollo con la app de APATE.

**Desde M13f, la app siempre tiene una instancia de Flask-SocketIO
real** (`create_app()`, incondicional -- ver `apate.web`), guardada
automaticamente por Flask-SocketIO en `app.extensions['socketio']`
(antes de M13f, esto dependia de `APATE_MOUNT_EXTERNAL_TOOLS`, y con
el flag en `False` no existia ninguna instancia). Un `app.run()` comun
no sirve trafico de WebSocket (las notificaciones en vivo de
`apate.web.blueprints.playground`, M13f, y las métricas en vivo de
DOLOS-T dentro de una operación se quedarían sin datos):
hace falta `socketio.run(app, ...)`, que envuelve el mismo servidor de
desarrollo pero sabe manejar tambien el protocolo de Socket.IO.

**`debug` ya no queda hardcodeado en `True` (revision de seguridad
post-vendorizado, ver docs/roadmap.md).** `python -m apate.web` es el
comando real que arranca la demo (abierta hasta crear el primer usuario) -- con
`debug=True` cualquiera que llegue a la app dispara el debugger
interactivo de Werkzeug ante cualquier excepcion no manejada (RCE real
si la consola queda alcanzable, mas el traceback completo con
variables locales -- incluidas credenciales ya descifradas en memoria
en una ruta de BUDA -- visible a cualquiera sin login). Default ahora
en `False`; `APATE_DEBUG=1` lo habilita a proposito para desarrollo
local, mismo patron que la variable `FLASK_DEBUG` de Flask.

**`allow_unsafe_werkzeug=True` y `APATE_DEV_PORT` (E1 de
docs/improvements.md).** Flask-SocketIO rechaza levantar el servidor de
Werkzeug cuando stdin no es un TTY (`if not sys.stdin or not
sys.stdin.isatty()`), asi que este comando -- el documentado para
desarrollo -- moria en el arranque bajo `nohup`, `&`, un script de
arranque o CI, y solo funcionaba desde una terminal interactiva. La
advertencia de la libreria apunta a produccion, que en este proyecto no
pasa por aca: `apate.web.wsgi:app` bajo Gunicorn es la instalacion
soportada (ver docs/instalacion-produccion.md). El puerto tambien pasa a
ser configurable: el default 5000 de Flask-SocketIO lo ocupa AirPlay
Receiver en macOS, y no habia forma de moverse de ahi."""

from __future__ import annotations

import os

from . import create_app

# Mismo default que Flask-SocketIO, explicito para que `_development_port()`
# lo pueda devolver ante un valor invalido.
_DEFAULT_DEV_PORT = 5000


def _debug_enabled() -> bool:
    """Separada de `main()` para poder probarla sin arrancar un
    `socketio.run()` real (bloqueante)."""

    return os.environ.get("APATE_DEBUG", "").strip().lower() in ("1", "true", "yes")


def _development_host() -> str:
    """Mantiene el servidor de desarrollo privado salvo pedido explícito."""

    return os.environ.get("APATE_DEV_HOST", "127.0.0.1")


def _development_port() -> int:
    """Permite mover el servidor de desarrollo del 5000 por defecto, que
    en macOS ocupa AirPlay Receiver. Un valor no numerico se ignora en
    favor del default en vez de tirar abajo el arranque."""

    raw = os.environ.get("APATE_DEV_PORT", "").strip()
    if not raw:
        return _DEFAULT_DEV_PORT
    try:
        return int(raw)
    except ValueError:
        return _DEFAULT_DEV_PORT


def _is_loopback_host(host: str) -> bool:
    """Reconoce los nombres y direcciones usados para loopback local."""

    return host.strip().lower() in {"localhost", "127.0.0.1", "::1"}


def main() -> None:
    app = create_app()
    socketio = app.extensions["socketio"]
    host = _development_host()
    if not _is_loopback_host(host):
        app.logger.warning(
            "El servidor de desarrollo está expuesto en %s; no es apto para producción. "
            "Usá Gunicorn detrás de un proxy reverso.",
            host,
        )
    socketio.run(
        app,
        host=host,
        port=_development_port(),
        debug=_debug_enabled(),
        # Ver la nota del docstring del modulo: sin esto el arranque
        # falla cuando stdin no es un TTY. La instalacion de produccion
        # no usa este entrypoint.
        allow_unsafe_werkzeug=True,
    )


if __name__ == "__main__":
    main()
