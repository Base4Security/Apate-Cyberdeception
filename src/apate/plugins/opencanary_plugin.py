"""Adaptador de plugin para OpenCanary (Thinkst, BSD-3-Clause, imagen
Docker oficial `thinkst/opencanary`) -- tercera y ultima de la tanda de
tareas para ampliar el ecosistema de herramientas orquestables (ver
docs/roadmap.md, docs/prompt-pendiente-opencanary.md para la
investigacion completa: config real, verificacion end-to-end contra un
contenedor real con una conexion SSH real, el hallazgo de
`start_mod()` sobre conflicto de puertos).

**Por que importa:** honeypot multi-servicio real (SSH, FTP, HTTP,
Telnet, MySQL, RDP... segun que modulos se habiliten), superficie de
red/host que hoy solo cubre DOLOS-T con decoys mas elaborados
(collector + red propia) -- OpenCanary es la opcion liviana, un
contenedor, sin coreografia de red propia. Detecta intentos de
conexion/login/comando con el **contenido literal** tecleado por quien
se conecta (usuario, password, comandos), a diferencia de Canarytokens
(migas puntuales sin sesion) o los decoys de DOLOS-T (senuelos con
contenido de archivo propio).

**Empaquetado: dentro del repo, mismo patron y mismo argumento ya
documentado por `canarytoken_plugin` (segunda de esta tanda) -- no se
repite aca el razonamiento completo, ver ese modulo.** Cliente Docker
propio (`opencanary_client.py`), autocontenido -- **no reutiliza
`DOLOST.services.docker_manager.DockerManager`**, que esta acoplado a
la convencion de nombres/config de DOLOS-T (mismo criterio de "cliente
aparte" ya aplicado en Canarytokens frente a un acoplamiento similar).

**Configuracion requerida en `PluginBinding.config` antes de
`deploy()`:**

- `services` (dict, opcional -- default `{}`, un despliegue sin
  servicios habilitados es valido aunque poco util, mismo criterio de
  leniencia que `DolosTPlugin` con una lista de decoys vacia): nombre
  de servicio de OpenCanary -> dict de sus claves reales SIN el
  prefijo, ej. `{"ssh": {"enabled": True, "port": 2222}}`. Mapeo
  declarativo -- ver docstring de `opencanary_client.build_config()`
  sobre por que no se valida contra una lista cerrada de servicios/
  claves.
- `node_id` (str, opcional): identificador del nodo en los eventos.
  Default: `self.plugin_id`.
- `network_mode` (str, opcional): `"bridge"` (default, mapeo explicito
  de puertos) o `"host"` (pierde el aislamiento de conflicto de
  puertos a cambio de la IP real del atacante -- ver docstring de
  `opencanary_client` sobre el hallazgo real de `start_mod()`;
  decision del operador, expuesta de forma visible en la UI, no solo
  documentada en codigo).
- `ttp_id` (str, opcional): sin mapeo MITRE oficial unico (OpenCanary
  cubre multiples servicios/tacticas segun que modulo dispare), mismo
  criterio que Canarytokens -- sin `ttp_id`, un hit se publica como
  `interaction`, no se promueve a `ttp_observed`.

**`rotate()` SI tiene equivalente real, a diferencia de Canarytokens.**
Reiniciar el contenedor (`docker restart`) renueva `node_id`/las claves
SSH host generadas al arrancar -- aproximacion ya documentada por
`DolosTPlugin.rotate()`/`BudaPlugin.rotate()` (stop+start), no
inventada aca.

**Sin bit de estado persistido a nivel de `PluginBinding` -- misma
simplificacion deliberada que `DolosTPlugin` (M11 fase 1), documentada
otra vez porque es la razon por la que este modulo NO tiene un
`restore_deployed_state()` propio (a diferencia de
`HoneytokenPlugin`/`CanarytokenPlugin`, que si reconcilian contra su
config local): el estado real vive unicamente en Docker
(`opencanary_client.container_status()`), asi que la reconciliacion
para `rotate()`/`retire()`/`check_activity()` se hace igual que
DOLOS-T -- forzando `plugin.state = PluginLifecycleState.DEPLOYED` en
la ruta web antes de invocar, en vez de una consulta redundante aca
adentro."""

from __future__ import annotations

import time
from typing import Any, Optional

from ..i18n import lazy_gettext
from .base import DeceptionPlugin, EventType, PluginEvent, PluginLifecycleState
from .opencanary_client import (
    container_name,
    deploy_container,
    fetch_logs,
    restart_container,
    stop_and_remove_container,
)
from .registry import PluginDescription


class OpenCanaryPlugin(DeceptionPlugin):
    """Adapta un contenedor OpenCanary (self-hosted, Docker) a la
    interfaz `DeceptionPlugin` de M2. Ver el docstring del modulo para
    el diseno completo."""

    plugin_description = PluginDescription(
        kind="opencanary",
        display_name=lazy_gettext("OpenCanary (Thinkst)"),
        description=lazy_gettext(
            "Honeypot multi-servicio real sobre Docker (SSH, FTP, HTTP, Telnet, MySQL...) -- "
            "detecta intentos de conexion/login con el contenido literal tecleado por el atacante."
        ),
        surface="Red / host (multi-servicio)",
    )

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")
        services = self.config.get("services", {})
        network_mode = self.config.get("network_mode", "bridge")
        node_id = self.config.get("node_id") or self.plugin_id

        deploy_container(
            name=self._container_name(),
            node_id=node_id,
            services=services,
            network_mode=network_mode,
        )
        self.config["node_id"] = node_id
        self.config["last_checked_at"] = time.time()

        enabled = [name for name, options in services.items() if options.get("enabled")]
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "deploy",
                "detail": f"OpenCanary desplegado con {len(enabled)} servicio(s): {', '.join(enabled) or 'ninguno'}.",
                "services": enabled,
                "network_mode": network_mode,
            },
            resource_id=f"opencanary:{self.plugin_id}",
        )
        self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")
        restart_container(name=self._container_name())
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "rotate",
                "detail": "OpenCanary reiniciado: node_id y claves SSH host renovadas (aproximacion stop+start, sin rotacion nativa mas fina).",
            },
            resource_id=f"opencanary:{self.plugin_id}",
        )
        # rotate() no cambia el estado del ciclo de vida: sigue DEPLOYED.

    def retire(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")
        stop_and_remove_container(name=self._container_name())
        self._publish(
            EventType.INTERACTION,
            {"kind": "retire", "detail": "OpenCanary retirado (contenedor detenido y eliminado)."},
            resource_id=f"opencanary:{self.plugin_id}",
        )
        self.config.pop("last_checked_at", None)
        self.state = PluginLifecycleState.RETIRED

    def check_activity(self, *, since: Optional[float] = None) -> list[PluginEvent]:
        """Consulta `container.logs(since=...)` (polling, ver docstring
        de `opencanary_client`) y publica un evento por hit. No forma
        parte del contrato de `DeceptionPlugin` -- pensado para llamarse
        desde una accion manual del operador, igual que
        `CanarytokenPlugin.check_hits()`/`DolosTPlugin.check_activity()`.
        El cursor se persiste como el momento de esta consulta (no el
        timestamp del hit mas reciente -- ver docstring del modulo
        cliente sobre por que)."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="check_activity")
        cursor = since if since is not None else self.config.get("last_checked_at")
        hits = fetch_logs(name=self._container_name(), since=cursor)

        ttp_id = self.config.get("ttp_id")
        event_type = EventType.TTP_OBSERVED if ttp_id else EventType.INTERACTION
        events: list[PluginEvent] = []
        for hit in hits:
            payload: dict[str, Any] = {
                "kind": "trigger",
                "detail": f"OpenCanary: interaccion (logtype {hit.logtype}) desde {hit.src_host or 'origen desconocido'}.",
                "logtype": hit.logtype,
                "local_time": hit.local_time,
                "node_id": hit.node_id,
            }
            if hit.src_host:
                payload["source_ip"] = hit.src_host
            if hit.src_port:
                payload["source_port"] = hit.src_port
            if hit.logdata:
                payload["logdata"] = hit.logdata
            if ttp_id:
                payload["ttp_id"] = ttp_id
            events.append(self._publish(event_type, payload, resource_id=f"opencanary:{self.plugin_id}"))

        self.config["last_checked_at"] = time.time()
        return events

    # -- Helpers internos -----------------------------------------------

    def _container_name(self) -> str:
        return container_name(self.plugin_id)
