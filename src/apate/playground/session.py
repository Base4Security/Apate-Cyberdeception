"""Sesion de modo Playground (M5) - documento de diseno, seccion 6.5.

Ata una Operacion a un EventBus dedicado, el RuleEngine (M3), el
TelemetryCollector (M4) y el puente de eventos (PlaygroundEventBridge)
en un unico objeto, para que las vistas de atacante/defensor de M4b
tengan un unico punto del que leer sin conocer cada modulo por
separado. No orquesta Docker: eso es lifecycle.py. Una sesion se crea
una vez que el stack ya esta arriba (o incluso antes, si se quiere
empezar a recibir eventos sinteticos de prueba).

Comparte el mismo Nucleo de Operacion y el mismo Motor de decision que
el modo de produccion (seccion 6.5 del diseno): la unica diferencia es
que las reglas se cargan contra un bus propio de la sesion en vez del
bus de una operacion real, y no hay plugins DOLOS-T/BUDA reales
registrados en el motor todavia (M8).

**Gap real encontrado en la verificacion manual pendiente desde M5
(ver docs/roadmap.md), cerrado aca:** `PlaygroundEventBridge.
fetch_and_ingest_elastic()` (la via para ssh_honeypot/frontend/backend/
mysql -- la mayoria documentada de las fuentes del puente, ver
events.py) nunca se llamaba desde ningun lado de la app real -- solo
`ingest_attacker_output()` (el contenedor atacante) estaba conectado a
una sesion. Confirmado con un grep de todo el codigo: la unica
referencia a `fetch_and_ingest_elastic`/`fetch_recent_hits` fuera de su
propio modulo eran los tests con mocks. Sin este metodo, la vista de
defensor nunca iba a mostrar telemetria real de los cuatro servicios
indexados por Filebeat, sin importar que tan bien tradujera el puente
esos datos. `fetch_elastic_events()`, nuevo, cierra el gap -- guarda
la marca de tiempo del ultimo fetch (`_last_elastic_fetch`, arranca en
el momento de crear la sesion) para no re-ingerir los mismos
documentos en cada llamada, ya que `TelemetryCollector.handle_event()`
no deduplica (cada evento publicado se persiste tal cual, ver
telemetry/collector.py) -- sin esa marca, refrescar la vista de
defensor varias veces habria inflado eventos/TTPs/disparos de reglas
con los mismos documentos repetidos."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..core.models import Operation
from ..plugins.base import EventBus, PluginEvent
from ..plugins.operation import build_operation_plugins
from ..rules.engine import RuleEngine
from ..rules.models import Rule
from ..rules.repository import SQLiteRuleDecisionRepository
from ..telemetry.collector import TelemetryCollector
from .config import PlaygroundConfig
from .elastic import DEFAULT_ELASTIC_URL
from .events import PlaygroundEventBridge
from .lifecycle import run_attacker_script as _run_attacker_script


@dataclass
class PlaygroundSession:
    """Una ejecucion en curso del modo Playground para una Operacion
    puntual. La sesión y el stack viven solo en memoria porque son
    desechables (sección 6.1 del diseño), pero las decisiones que el
    motor toma durante ella pueden persistirse en SQLite."""

    operation: Operation
    bus: EventBus
    engine: RuleEngine
    telemetry: TelemetryCollector
    bridge: PlaygroundEventBridge
    _last_elastic_fetch: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def create(
        cls,
        *,
        operation: Operation,
        rules: list[Rule],
        telemetry: TelemetryCollector,
        decision_repository: SQLiteRuleDecisionRepository | None = None,
        operation_executor=None,
    ) -> "PlaygroundSession":
        """Arma una sesion nueva: un EventBus propio de la operacion,
        con el RuleEngine (cargado con las mismas reglas del motor de
        decision) y el TelemetryCollector central (M4) suscriptos, mas
        el puente de eventos listo para recibir logs del stack."""

        bus = EventBus()
        telemetry.attach(bus)
        engine = RuleEngine(
            operation=operation,
            plugins=build_operation_plugins(operation, bus),
            bus=bus,
            rules=rules,
            decision_repository=decision_repository,
            operation_executor=operation_executor,
        )
        bridge = PlaygroundEventBridge(bus=bus, operation_id=operation.id)
        return cls(operation=operation, bus=bus, engine=engine, telemetry=telemetry, bridge=bridge)

    def run_attacker_script(self, config: PlaygroundConfig) -> list[PluginEvent]:
        """Ejecuta attack_scripts/main_attacker.py dentro de
        attacker-tools (ver lifecycle.run_attacker_script -- interactivo,
        sin argumentos por linea de comandos) y traduce su salida
        estandar a eventos sobre el bus de esta sesion: es la unica
        forma de alimentar la vista de atacante, ya que ese contenedor
        no tiene logging propio ni entrada en Filebeat (ver events.py)."""

        result = _run_attacker_script(config)
        return self.bridge.ingest_attacker_output(result.stdout)

    def fetch_elastic_events(self, *, elastic_url: str = DEFAULT_ELASTIC_URL) -> list[PluginEvent]:
        """Consulta Elasticsearch por hits nuevos desde el ultimo fetch
        de esta sesion (ssh_honeypot/frontend/backend/mysql, ver
        events.py) y los traduce/publica sobre el bus de la sesion --
        es la via real de telemetria del defensor, ver docstring del
        modulo. Avanza `_last_elastic_fetch` al terminar, haya o no
        hits nuevos, para que la siguiente llamada no vuelva a
        consultar la misma ventana ya cubierta."""

        events = self.bridge.fetch_and_ingest_elastic(elastic_url=elastic_url, since=self._last_elastic_fetch)
        self._last_elastic_fetch = datetime.now(timezone.utc)
        return events
