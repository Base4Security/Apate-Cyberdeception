"""Cliente Docker autocontenido para OpenCanary (Thinkst, BSD-3-Clause,
imagen oficial `thinkst/opencanary`) -- tercera y ultima de la tanda de
tareas para ampliar el ecosistema de herramientas orquestables (ver
docs/roadmap.md, docs/prompt-pendiente-opencanary.md para la
investigacion completa contra un contenedor real).

**Verificado contra el codigo real y un contenedor real, en una sesion
previa (no en esta -- ver docs/roadmap.md).** Hallazgos que definen el
diseno de este modulo:

- **Config**: un unico JSON plano (`<servicio>.enabled`/`<servicio>.port`/
  ...), resuelto por el propio proceso de OpenCanary en el orden
  `/etc/opencanaryd/opencanary.conf` -> `~/.opencanary.conf` ->
  `./opencanary.conf`. Sin archivo, `sys.exit(1)` -- falla dura, no
  silenciosa. `build_config()` arma ese JSON de forma **declarativa**
  (mismo criterio que `canarytoken_client.create_token(extra_fields=...)`
  y el mapeo de campos del puente de telemetria generico): no valida
  nombres de servicio/clave contra una lista cerrada -- el proceso real
  de OpenCanary es quien valida eso al arrancar (una clave/servicio
  invalido queda ignorado o hace fallar el arranque, visible en
  `container.logs()`, nunca silencioso desde APATE).

- **Arranque**: `bin/opencanaryd` no corre nativo en Windows y exige
  root para puertos privilegiados -- Docker no es una opcion entre
  otras, es la unica realista desde una app Python multiplataforma
  (mismo motivo que llevo a Docker para DOLOS-T en M8).

- **Inyeccion del config sin bind mount.** Se crea el contenedor sin
  iniciarlo (`containers.create()`), se inyecta `opencanary.conf` via
  `container.put_archive()` (un tar en memoria, sin escribir ningun
  archivo en el host) y recien despues se arranca (`container.start()`).
  Evita bind mounts, que en Docker Desktop sobre Windows exigen
  traduccion de rutas host/contenedor -- prioridad declarada de un demo
  confiable en vivo para BlackHat Arsenal sobre la alternativa (un
  volumen), que no aporta nada mas alla de la config en si.

- **Conflicto de puertos, hallazgo real en `opencanary.tac`**:
  `start_mod()` no verifica el bind en el momento (Twisted lo intenta
  recien cuando corre el reactor); una falla de bind interna a
  OpenCanary no tira abajo los otros servicios ni aparece en su propio
  log JSON. Con `network_mode=host` esa falla seria **silenciosa** desde
  APATE. Con mapeo explicito de puertos (default de este modulo), Docker
  la reporta clara y atrapable ANTES de arrancar nada -- probado en los
  dos niveles (`docker: Error response from daemon: ... port is already
  allocated`, y `docker.errors.APIError` desde el SDK Python).
  `network_mode="host"` sigue disponible como opcion explicita (ver
  `deploy_container()`), documentada de forma visible en la UI (no solo
  aca) porque pierde la IP real del atacante (queda el gateway del
  bridge) a cambio del conflicto de puertos claro -- decision del
  operador, nunca el default.

- **Eventos**: un logger propio de OpenCanary escribe una linea JSON por
  evento al handler `console` (default), que Docker captura en stdout --
  `container.logs()` alcanza, sin volumen ni endpoint entrante nuevo
  (mismo criterio de "polling, nunca push" que
  `apate.plugins.canarytoken_client`). `logdata` trae contenido literal
  tecleado por quien se conecta (usuario/password/comandos/user agents)
  -- cada valor string pasa por `sanitize_payload_text()` antes de
  publicarse a un `PluginEvent` (ver `OpenCanaryHit.from_raw()`), mismo
  criterio que los puentes de telemetria con contenido de una fuente no
  confiable (docs/plugin-event-contract.md seccion 3.4). A diferencia de
  `CanarytokenHit` (que SI necesita una allowlist estructural: el
  `canarydrop` completo trae secretos de OTROS tokens mezclados),
  `logdata` de un evento OpenCanary es exactamente el contenido de ESA
  interaccion puntual -- no hace falta filtrar campos, solo truncar/
  sanitizar el contenido en si.

**Deduplicacion, decision explicita sobre como NO hacerla:** en vez de
parsear el timestamp propio de cada linea JSON (formato heterogeneo
entre versiones/servicios, sin verificar en esta sesion contra un
contenedor real), se usa el timestamp que el propio daemon Docker le
asigna a cada linea de log (`container.logs(since=...)`, filtro nativo
de la API de Docker) -- el llamador (`OpenCanaryPlugin.check_activity()`)
persiste el cursor como el momento en que hizo la consulta, no el
timestamp del hit mas reciente. Limitacion documentada, mismo criterio
que ya acepta este proyecto para el honeypot SSH del Playground (M5,
polling cada 5s): un evento dentro de la misma ventana de granularidad
de `since` podria no deduplicarse perfectamente en el limite exacto del
segundo -- se prioriza no depender de un formato de timestamp propio
sin verificar, sobre una precision de deduplicacion que no se puede
confirmar sin un contenedor real."""

from __future__ import annotations

import io
import json
import tarfile
from dataclasses import dataclass, field
from typing import Any, Optional

from ..i18n import gettext as _
from .base import sanitize_payload_text
from .exceptions import OpenCanaryError

DEFAULT_IMAGE = "thinkst/opencanary"
CONFIG_DIR_IN_CONTAINER = "/etc/opencanaryd"


def container_name(plugin_id: str) -> str:
    """Convencion de nombre de contenedor -- misma forma en
    `OpenCanaryPlugin`/`apate.web.blueprints.operations` (panel/rutas),
    nunca recalculada por separado en mas de un lugar."""

    return f"OpenCanary-{plugin_id}"


@dataclass(frozen=True)
class OpenCanaryHit:
    """Un evento observado ('hit'). `logdata` es el contenido especifico
    del servicio (username/password/comandos/user agent segun el modulo
    -- SSH, FTP, HTTP... traen formas distintas), sanitizado valor por
    valor con `sanitize_payload_text()` -- no es una allowlist
    estructural como `CanarytokenHit`: acá el contenido completo es
    legitimo mostrar (es la interaccion observada en si), solo hace
    falta truncar texto potencialmente enorme."""

    logtype: int
    local_time: str
    src_host: str
    src_port: Optional[int]
    dst_host: Optional[str]
    dst_port: Optional[int]
    node_id: str
    logdata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "OpenCanaryHit":
        raw_logdata = raw.get("logdata")
        logdata = {
            str(key): sanitize_payload_text(value)
            for key, value in (raw_logdata or {}).items()
        }
        return cls(
            logtype=int(raw.get("logtype") or 0),
            local_time=str(raw.get("local_time") or raw.get("utc_time") or ""),
            src_host=sanitize_payload_text(str(raw.get("src_host") or "")),
            src_port=raw.get("src_port"),
            dst_host=raw.get("dst_host"),
            dst_port=raw.get("dst_port"),
            node_id=str(raw.get("node_id") or ""),
            logdata=logdata,
        )


def build_config(*, node_id: str, services: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Aplana `services` (dict declarativo: nombre de servicio -> dict de
    claves SIN el prefijo, ej. `{"ssh": {"enabled": True, "port": 2222}}`)
    al formato JSON plano real que exige `opencanary.conf`
    (`"<servicio>.<clave>": valor`, mas `"device.node_id"`). `host_port`
    es una clave propia de APATE (mapeo de puerto del lado de Docker, ver
    `_port_bindings()`), nunca se escribe al config real de OpenCanary."""

    config: dict[str, Any] = {"device.node_id": node_id}
    for service, options in services.items():
        for key, value in options.items():
            if key == "host_port":
                continue
            config[f"{service}.{key}"] = value
    return config


def _docker_client():
    """Sin conexion a nivel de modulo (a diferencia de
    `DockerManager.get_instance()` de DOLOS-T, que tampoco conecta al
    importar pero mantiene una instancia compartida) -- una llamada
    fresca por operacion es coherente con el resto de este cliente
    (autocontenido, sin estado propio entre llamadas) y evita que un
    error de conexion viejo quede pegado a un singleton."""

    try:
        import docker
    except ImportError as exc:  # pragma: no cover - docker ya es dependencia declarada del proyecto
        raise OpenCanaryError(_("El SDK 'docker' no esta disponible en este entorno.")) from exc
    try:
        return docker.from_env()
    except Exception as exc:
        raise OpenCanaryError(_("No se pudo conectar con Docker: %(error)s", error=exc)) from exc


def _port_bindings(services: dict[str, dict[str, Any]]) -> dict[str, int]:
    bindings: dict[str, int] = {}
    for options in services.values():
        if not options.get("enabled") or not options.get("port"):
            continue
        container_port = int(options["port"])
        host_port = int(options.get("host_port", container_port))
        bindings[f"{container_port}/tcp"] = host_port
    return bindings


def _config_archive(config_bytes: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        info = tarfile.TarInfo(name="opencanary.conf")
        info.size = len(config_bytes)
        tar.addfile(info, io.BytesIO(config_bytes))
    return buffer.getvalue()


def deploy_container(
    *,
    name: str,
    node_id: str,
    services: dict[str, dict[str, Any]],
    image: str = DEFAULT_IMAGE,
    network_mode: str = "bridge",
) -> str:
    """Crea (sin iniciar), inyecta el config real via `put_archive()`
    (sin bind mount -- ver docstring del modulo) y recien ahi arranca el
    contenedor. `network_mode="bridge"` (default) mapea puertos
    explicitos -- un puerto ya ocupado hace fallar `create()` con una
    excepcion clara de docker-py, sin contenedor a medio desplegar.
    `network_mode="host"` no mapea puertos (pierde el aislamiento de
    conflicto a cambio de la IP real del atacante, ver docstring del
    modulo) -- decision del operador, nunca el default."""

    client = _docker_client()
    config = build_config(node_id=node_id, services=services)
    config_bytes = json.dumps(config, indent=2).encode("utf-8")

    kwargs: dict[str, Any] = {"detach": True}
    if network_mode == "host":
        kwargs["network_mode"] = "host"
    else:
        kwargs["ports"] = _port_bindings(services)

    try:
        container = client.containers.create(image, name=name, **kwargs)
        container.put_archive(CONFIG_DIR_IN_CONTAINER, _config_archive(config_bytes))
        container.start()
    except OpenCanaryError:
        raise
    except Exception as exc:
        raise OpenCanaryError(
            _(
                "No se pudo desplegar el contenedor OpenCanary '%(name)s': %(error)s",
                name=name,
                error=exc,
            )
        ) from exc
    return container.id


def restart_container(*, name: str) -> None:
    """Reinicia el proceso de OpenCanary (`docker restart`) -- a
    diferencia de Canarytokens (sin equivalente natural, ver
    `canarytoken_plugin.rotate()`), reiniciar el proceso SI renueva su
    `node_id`/las claves SSH host generadas al arrancar: es una
    aproximacion documentada (mismo criterio que
    `DolosTPlugin.rotate()`/`BudaPlugin.rotate()`, stop+start), no
    inventada para esta tarea."""

    client = _docker_client()
    try:
        container = client.containers.get(name)
        container.restart()
    except Exception as exc:
        raise OpenCanaryError(
            _("No se pudo reiniciar el contenedor '%(name)s': %(error)s", name=name, error=exc)
        ) from exc


def stop_and_remove_container(*, name: str) -> None:
    """`docker stop` + `docker rm`. Si el contenedor ya no existe, no es
    un error -- mismo criterio de idempotencia que
    `HoneytokenPlugin.retire()` (verifica en vez de asumir)."""

    client = _docker_client()
    try:
        container = client.containers.get(name)
    except Exception:
        return
    try:
        container.stop()
        container.remove()
    except Exception as exc:
        raise OpenCanaryError(
            _("No se pudo retirar el contenedor '%(name)s': %(error)s", name=name, error=exc)
        ) from exc


def fetch_logs(*, name: str, since: Optional[float] = None) -> list[OpenCanaryHit]:
    """`container.logs(since=...)` -- una linea JSON por evento (ver
    docstring del modulo). Lineas que no son JSON valido (banners de
    arranque del propio proceso, por ejemplo) se ignoran en silencio,
    no rompen la consulta completa."""

    client = _docker_client()
    try:
        container = client.containers.get(name)
        kwargs: dict[str, Any] = {"stdout": True, "stderr": False}
        if since is not None:
            kwargs["since"] = int(since)
        raw_logs = container.logs(**kwargs)
    except Exception as exc:
        raise OpenCanaryError(
            _("No se pudieron leer los logs de '%(name)s': %(error)s", name=name, error=exc)
        ) from exc

    hits: list[OpenCanaryHit] = []
    for line in raw_logs.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except ValueError:
            continue
        if isinstance(raw, dict):
            hits.append(OpenCanaryHit.from_raw(raw))
    return hits


def container_status(*, name: str) -> dict[str, Any]:
    """Estado EN VIVO del contenedor -- nunca un bit persistido, mismo
    criterio que `_dolost_panel_data()` en `apate.web`. Distingue
    "Docker no responde" (`docker_available=False`, estado
    indeterminado) de "Docker responde pero este contenedor puntual no
    existe" (`docker_available=True`, `status="no desplegado"`) -- la
    UI necesita esa distincion para mostrar un punto gris ("desconocido")
    en vez de rojo ("caido") cuando en realidad no se puede confirmar
    nada."""

    try:
        client = _docker_client()
    except OpenCanaryError:
        return {"docker_available": False, "status": None, "up": None}
    try:
        container = client.containers.get(name)
    except Exception:
        return {"docker_available": True, "status": "no desplegado", "up": False}
    status = container.status
    return {"docker_available": True, "status": status, "up": status == "running"}
