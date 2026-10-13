"""Puente de telemetria externo configurable (primera de una tanda de
tres tareas para ampliar el ecosistema de herramientas que APATE puede
orquestar -- ver docs/roadmap.md).

**Confirmado antes de disenar nada, investigando el codigo real (M5,
verificado contra Docker/Elasticsearch reales, no una suposicion):**
APATE ya tiene DOS formas de integrar una herramienta externa, no una.
Un `DeceptionPlugin` completo (`apate.plugins`, APATE controla el ciclo
de vida: `deploy()`/`rotate()`/`retire()`) o un puente de telemetria
que SOLO ingiere eventos, sin desplegar ni controlar nada --
`apate.playground.events.PlaygroundEventBridge` es ese segundo modelo,
ya funcionando: consulta Elasticsearch (`apate.playground.elastic.
fetch_recent_hits()`) y traduce hits a `PluginEvent` sin desplegar
absolutamente nada. Este modulo generaliza ese segundo modelo para que
una fuente Elasticsearch externa (T-Pot, cualquier stack con su propio
ELK) tambien pueda alimentar una Operacion real -- hoy el puente
existente esta atado al indice `playground-logs-*` y al mapeo
`mitre.*` exacto que resuelve Filebeat en el stack vendorizado.

**Que se comparte de verdad con el puente del Playground, y que no
(decision explicita, con el argumento pedido):**

- **El cliente HTTP de Elasticsearch SI se comparte, generalizado
  minimamente** (`apate.playground.elastic.fetch_recent_hits()`, ahora
  con un parametro `timestamp_field` -- ver su docstring para el
  argumento completo de por que no se relocalizo a un modulo "neutral"
  en vez de solo parametrizarse). Es codigo sin ningun acoplamiento a
  Playground mas alla de sus valores por default; duplicarlo no se
  justificaba.
- **La traduccion NO se comparte -- es un modulo nuevo, a proposito.**
  `PlaygroundEventBridge._map_elastic_hit()` es un mapeo FIJO,
  hardcodeado al documento exacto que indexa Filebeat en el stack
  vendorizado (`event_type`, `message`, `source_ip`, `username`,
  `command`, `fake`, `mitre.technique_id/tactic/technique_name`). Una
  fuente externa (T-Pot u otra) no tiene por que llamar a sus campos
  igual -- generalizar ESE mapeo especifico lo habria roto (o forzado a
  volverse una capa de compatibilidad rara) sin necesidad: la tarea
  pedia explicitamente un mapeo CONFIGURABLE, asi que la traduccion de
  este modulo (`ExternalTelemetryBridge.ingest_hit()`) es data-driven
  desde cero (`ExternalTelemetrySource.field_mapping`), no una
  generalizacion del mapeo fijo existente.
- **El parseo de la salida de attacker-tools (banners MITRE) no aplica
  aca en absoluto** -- es especifico del contenedor atacante del
  Playground, sin equivalente en una fuente Elasticsearch generica.

**Por que no es un `DeceptionPlugin` (decision arquitectonica, no un
detalle de implementacion):** un puente de telemetria no despliega ni
controla nada -- no hay ningun recurso real que `deploy()`/`rotate()`/
`retire()` pudieran administrar de forma honesta. Forzarlo en
`PluginRegistry`/`PluginBinding` habria significado inventar semantica
sin sentido real (¿que seria "rotar" una fuente de telemetria de solo
lectura?) solo para reusar infraestructura -- exactamente la distincion
de dos modelos que esta tarea pide preservar. Por eso vive en
`Operation.telemetry_bridges: list[ExternalTelemetrySource]`, una lista
aparte de `Operation.plugins` (ver docstring de `ExternalTelemetrySource`
en `apate.core.models`).

**Mapeo declarativo, no un motor de transformacion.**
`ExternalTelemetrySource.field_mapping` es `dict[str, str]`: clave de
payload reconocida por el resto de APATE (`ttp_id`/`detail`/
`source_ip`/`credential`/`hash`/`domain`/`url`/`kind`, ver
docs/plugin-event-contract.md seccion 3.3) -> ruta con puntos del campo
real en el documento fuente. `ingest_hit()` resuelve cada ruta contra
el `_source` del hit (`_get_dotted()`, misma tecnica que ya usaba
`PlaygroundEventBridge` para el mapeo `mitre.*`, reimplementada aca en
vez de importada -- son ~10 lineas, no vale la pena una dependencia
cruzada por eso) y copia el valor tal cual bajo esa clave. Sin
funciones, sin expresiones, sin ningun tipo de logica condicional mas
alla de "si el campo esta presente, se copia" -- exactamente lo que
pidio la tarea. `event_type` se decide con la unica regla semantica que
ya es inherente al contrato de `PluginEvent` (seccion 3.2): si el
mapeo produjo un `ttp_id`, es `TTP_OBSERVED`; si no, `INTERACTION`.

**Seguridad -- seccion 3.4 del contrato, aplicada de verdad, no solo
citada.** El contenido de una fuente externa que APATE no controla
puede terminar persistido en telemetria y renderizado en la UI (los
templates ya renderizan `payload` con autoescape de Jinja, nunca
`|safe` -- confirmado revisando `apate/web/templates/`, no asumido; el
riesgo real que faltaba cubrir era el LARGO, no la inyeccion). Cada
valor mapeado pasa por `apate.plugins.base.sanitize_payload_text()`
antes de entrar al payload -- trunca texto largo, deja pasar cualquier
otro tipo tal cual. **Descuido real encontrado en el puente EXISTENTE
del Playground durante esta investigacion, corregido en el mismo
commit:** `PlaygroundEventBridge._map_elastic_hit()` copiaba `message`/
`command` (contenido potencialmente escrito por un atacante en una
sesion SSH real contra el honeypot) sin ningun limite de longitud --
ahora usa el mismo helper."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from ..core.models import ExternalTelemetrySource
from ..i18n import gettext as _
from ..plugins.base import EventBus, EventType, PluginEvent, sanitize_payload_text
from ..playground.elastic import DEFAULT_ELASTIC_URL, fetch_recent_hits
from ..playground.exceptions import PlaygroundError
from .exceptions import ExternalTelemetryError


def _get_dotted(source: dict[str, Any], dotted_key: str) -> Optional[Any]:
    """Busca un campo que puede llegar como objeto anidado
    (`{"mitre": {"technique_id": ...}}`) o como clave plana con el
    punto literal (`"mitre.technique_id"`) -- misma tecnica que
    `apate.playground.events._get_dotted()`, reimplementada aca (no
    importada) para no crear una dependencia cruzada por ~10 lineas
    sin estado."""

    if dotted_key in source:
        return source[dotted_key]
    node: Any = source
    for part in dotted_key.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


class ExternalTelemetryBridge:
    """Traduce hits de Elasticsearch de una fuente externa a
    `PluginEvent` segun el mapeo declarativo de `source`, y los publica
    en el `EventBus` de la operacion -- mismo bus que consumen
    `RuleEngine`/`TelemetryCollector` para cualquier otro emisor. No
    despliega ni controla la fuente: solo lee. Ver docstring del
    modulo para el diseno completo."""

    def __init__(self, *, source: ExternalTelemetrySource, bus: EventBus, operation_id: str) -> None:
        self.source = source
        self.bus = bus
        self.operation_id = operation_id

    def ingest_hit(self, hit: dict[str, Any]) -> Optional[PluginEvent]:
        """Traduce un hit segun `source.field_mapping`. Devuelve `None`
        sin publicar nada -- nunca lanza -- si el hit no tiene la forma
        esperada (`'_source'` valido) o si el mapeo no resolvio NINGUN
        campo (publicar un evento sin ningun dato mapeado no aportaria
        nada, y ocultaria en silencio un mapeo mal configurado si se
        contara como "exito")."""

        raw = hit.get("_source") if isinstance(hit, dict) else None
        if not isinstance(raw, dict):
            return None

        payload: dict[str, Any] = {}
        for payload_key, source_path in self.source.field_mapping.items():
            value = _get_dotted(raw, source_path)
            if value is not None:
                payload[payload_key] = sanitize_payload_text(value)
        if not payload:
            return None

        payload.setdefault("source", self.source.name)
        event_type = EventType.TTP_OBSERVED if "ttp_id" in payload else EventType.INTERACTION
        from ..ledger.repository import digest
        event = PluginEvent(
            event_type=event_type,
            plugin_id=self.source.id,
            surface=self.source.surface,
            operation_id=self.operation_id,
            payload=payload,
            provenance={"raw": hit, "external_id": str(hit["_id"]) if hit.get("_id") is not None else None,
                "generation": None, "origin_time": _get_dotted(raw, self.source.timestamp_field),
                "transformation": "external-field-mapping-v1", "mapping_sha256": digest(self.source.field_mapping)},
        )
        self.bus.publish(event)
        return event

    def ingest_hits(self, hits) -> list[PluginEvent]:
        events = []
        for hit in hits:
            event = self.ingest_hit(hit)
            if event is not None:
                events.append(event)
        return events

    def fetch_and_ingest(self, *, since: datetime, size: int = 500) -> list[PluginEvent]:
        """Consulta Elasticsearch (`fetch_recent_hits()`, compartido
        con el Playground -- ver docstring del modulo) y traduce los
        hits obtenidos. `ExternalTelemetryError` envuelve cualquier
        falla de red/consulta real, para que quien use este puente no
        tenga que conocer `apate.playground.exceptions`."""

        try:
            hits = fetch_recent_hits(
                elastic_url=self.source.elastic_url or DEFAULT_ELASTIC_URL,
                index=self.source.index,
                since=since,
                size=size,
                timestamp_field=self.source.timestamp_field,
            )
        except PlaygroundError as exc:
            raise ExternalTelemetryError(
                _(
                    "No se pudo consultar la fuente de telemetria '%(source)s': %(error)s",
                    source=self.source.name,
                    error=exc,
                )
            ) from exc
        return self.ingest_hits(hits)
