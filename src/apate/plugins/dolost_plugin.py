"""Adaptador de plugin para DOLOS-T (M8c) - documento de diseno,
seccion 4.5; contrato exacto en docs/plugin-event-contract.md.

Llama directo a las funciones Python reales de DOLOS-T (paquete
`DOLOST`, dependencia editable local -- ver pyproject.toml), sin
ninguna capa HTTP intermedia: `deploy_collector()`/`deploy_decoy()`/
`clean_decoy()` de `DOLOST.blueprints.api` (las mismas funciones que
usan sus propios endpoints HTTP, reutilizadas tal cual, no reimplementadas)
y `DockerManager` para el resto del ciclo de vida. La emision de
eventos usa `DOLOST.services.events.get_structured_events()` (M8a).

Verificado contra el codigo real de DOLOS-T (no asumido, ver M8c en
docs/roadmap.md): `deploy_collector()`/`deploy_decoy(decoy)`/
`clean_decoy(decoy)` son funciones Python planas en
`blueprints/api.py`, no vistas Flask -- no dependen de un request HTTP
activo, se pueden llamar directo.
"""

from __future__ import annotations

from typing import Any

from DOLOST.blueprints.api import clean_decoy, deploy_collector, deploy_decoy
from DOLOST.services.docker_manager import DockerManager
from DOLOST.services.events import get_structured_events

from ..i18n import lazy_gettext
from .base import DeceptionPlugin, EventType, PluginEvent, PluginLifecycleState
from .registry import PluginDescription

_docker_manager = DockerManager.get_instance()


class DolosTPlugin(DeceptionPlugin):
    """Adapta DOLOS-T (superficie red/host) a la interfaz DeceptionPlugin
    de M2. `config` acepta `decoys`: una lista de dicts con la misma
    forma que ya usa DOLOS-T internamente (`Hostname`, `Description`,
    `IP`, `Subnet`, `Gateway`, `DeceptionNetwork`, `ServicePorts`,
    `Service`, `DecoyFiles` -- ver `blueprints/api.py::deploy_decoy`).
    Una lista vacia (o ausente) despliega solo el collector, sin decoys."""

    plugin_description = PluginDescription(
        kind="dolost",
        display_name=lazy_gettext("Decoys de red"),
        description=lazy_gettext(
            "Despliega un collector y decoys de red/host reales sobre Docker -- "
            "senuelos con IP, puertos de servicio y contenido propio configurables."
        ),
        surface="Red / host",
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # get_structured_events() (M8a) no es una cola que se drena:
        # relee el snapshot completo de los logs "observable_*" en cada
        # llamada -- sin este set, check_activity() re-publicaria el
        # mismo evento en cada poll. No hay un id unico por evento (ver
        # docs/plugin-event-contract.md), asi que se deduplica por la
        # tupla de sus propios campos.
        self._seen_signatures: set[tuple] = set()

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")

        decoys = self.config.get("decoys", [])
        deploy_collector()
        for decoy in decoys:
            deploy_decoy(decoy)

        self._publish(
            EventType.INTERACTION,
            {
                "kind": "deploy",
                "detail": f"DOLOS-T: collector + {len(decoys)} decoy(s) desplegados.",
                "decoy_count": len(decoys),
            },
        )
        self.state = PluginLifecycleState.DEPLOYED

    def restore_deployed_state(self) -> None:
        """Rehidrata el estado solo si todos los decoys siguen existiendo.

        Se usa al construir un motor efímero sin adaptador cacheado, como el
        puente externo. Consultar Docker es deliberadamente bajo demanda: el
        sondeo periódico entrega sus instancias ya reconciliadas y no paga
        esta consulta en cada ciclo.
        """

        expected = {
            f"/DolosT-{decoy['Hostname']}"
            for decoy in self.config.get("decoys", [])
            if decoy.get("Hostname")
        }
        if not expected:
            return
        containers = _docker_manager.get_containers(all=True)
        names = {name for container in containers for name in container.get("Names", [])}
        if expected.issubset(names):
            self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        """DOLOS-T no tiene un concepto nativo de "rotar" un decoy --
        `blueprints/api.py` solo expone start/stop/deploy/undeploy, no
        una operacion de rotacion (no se inventa una: se aproxima con
        stop+start de cada decoy configurado, que al menos renueva el
        contenedor en ejecucion). Documentado como aproximacion, no
        como una funcionalidad real de DOLOS-T que se este reutilizando."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")

        decoys = self.config.get("decoys", [])
        for decoy in decoys:
            hostname = f"DolosT-{decoy['Hostname']}"
            _docker_manager.stop(container_id=hostname)
            _docker_manager.start(container_id=hostname)

        self._publish(
            EventType.INTERACTION,
            {
                "kind": "rotate",
                "detail": f"DOLOS-T: {len(decoys)} decoy(s) reiniciados (sin rotacion nativa en DOLOS-T).",
                "decoy_count": len(decoys),
            },
        )
        # rotate() no cambia el estado del ciclo de vida: sigue DEPLOYED.

    def retire(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")

        decoys = self.config.get("decoys", [])
        for decoy in decoys:
            clean_decoy(decoy)
        _docker_manager.clean_container("Collector")
        _docker_manager.clean_networks()

        self._publish(
            EventType.INTERACTION,
            {
                "kind": "retire",
                "detail": f"DOLOS-T: collector y {len(decoys)} decoy(s) retirados.",
                "decoy_count": len(decoys),
            },
        )
        self.state = PluginLifecycleState.RETIRED

    def check_activity(self) -> list[PluginEvent]:
        """Traduce la actividad estructurada de DOLOS-T (M8a,
        `get_structured_events()`) a `PluginEvent` sobre el bus. No
        forma parte del contrato de `DeceptionPlugin` -- especifico de
        este adaptador, pensado para llamarse desde un loop de polling
        externo, igual que `HoneytokenPlugin.check_access()` (M7) o
        `RuleEngine.check_closure()` (M3)."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="check_activity")

        published: list[PluginEvent] = []
        for raw_event in get_structured_events():
            if not self._event_belongs_to_binding(raw_event):
                continue
            signature = (
                raw_event.get("kind"),
                raw_event.get("detail"),
                raw_event.get("decoy"),
                raw_event.get("timestamp"),
            )
            if signature in self._seen_signatures:
                continue
            self._seen_signatures.add(signature)

            event_type = EventType.TTP_OBSERVED if raw_event.get("ttp_id") else EventType.INTERACTION
            payload = {key: value for key, value in raw_event.items() if value is not None}
            resource_id = self._resource_id_for_event(raw_event)
            published.append(self._publish(event_type, payload, resource_id=resource_id))
        return published

    def _resource_id_for_event(self, raw_event: dict[str, Any]) -> str | None:
        """Resuelve el hostname canónico solo desde el inventario del binding."""

        observed = str(raw_event.get("decoy", ""))
        normalized = observed.casefold()
        if normalized.startswith("dolost-"):
            normalized = normalized[len("dolost-") :]
        for decoy in self.config.get("decoys", []):
            hostname = str(decoy.get("Hostname", ""))
            if hostname and hostname.casefold() == normalized:
                return f"decoy:{hostname}"
        return None

    def _event_belongs_to_binding(self, raw_event: dict[str, Any]) -> bool:
        """Evita atribuir el mismo decoy a varias operaciones.

        Los bindings históricos sin decoys conservan el comportamiento
        previo. Cuando hay inventario explícito, el observable debe indicar
        uno de esos hostnames, con o sin el prefijo de contenedor ``DolosT-``.
        """

        configured = {
            str(decoy.get("Hostname", "")).casefold()
            for decoy in self.config.get("decoys", [])
            if decoy.get("Hostname")
        }
        if not configured:
            return True
        observed = str(raw_event.get("decoy", "")).casefold()
        if observed.startswith("dolost-"):
            observed = observed[len("dolost-") :]
        return observed in configured
