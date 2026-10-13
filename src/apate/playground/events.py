"""Puente de eventos del modo Playground (M5) hacia el EventBus de M2 -
documento de diseno, seccion 6.2.

Traduce la salida del stack Cyber Deception Playground a PluginEvent
normalizados (interaction/ttp_observed), para que el RuleEngine (M3) y
el TelemetryCollector (M4) los procesen exactamente igual que a los de
cualquier plugin real. El modo Playground no es un plugin
(deploy()/rotate()/retire()): es un modo de ejecucion que alimenta el
mismo bus con datos de un entorno aislado en lugar de con datos de
produccion (seccion 6.5 del diseno).

Verificado contra el repositorio real (ver docs/analisis-repos-existentes.md,
actualizado tras poder clonarlo) -- ya no es una suposicion:

- **ssh_honeypot, frontend, backend y mysql** escriben todos a un unico
  indice Elasticsearch `playground-logs-*` via Filebeat, que ademas
  enriquece los eventos que matchean una regla de `filebeat.yml` con
  `mitre.tactic`/`mitre.technique_id`/`mitre.technique_name` ya
  resueltos (ej. la regla HONEYTOKEN_ACCESS agrega T1190). Por eso este
  puente consulta Elasticsearch (`GET playground-logs-*/_search`, ver
  elastic.py) en vez de parsear un archivo de log por contenedor: es
  mas robusto (un unico punto de lectura para los cuatro servicios) y
  evita tener que inferir la TTP nosotros mismos, ya que Filebeat ya la
  resolvio. El honeypot SSH en particular escribe JSON-lines a
  `ssh_connections.json` (montado en el host, indexado por Filebeat)
  con los campos `timestamp`, `source_ip`, `username`, `event_type`
  (`ssh_connection`/`command_execution`), `command` y `fake` -- estos
  son los campos que ingest_elastic_hit() reconoce cuando llegan en un
  documento del indice unificado.
- **attacker-tools** es la unica excepcion: no corre nada
  automaticamente (`command: /bin/bash`, shell interactiva) y no tiene
  entrada en Filebeat, asi que sus acciones no llegan a Elasticsearch.
  Sus eventos se obtienen ejecutando `attack_scripts/main_attacker.py`
  via `docker exec -i` (ver lifecycle.run_attacker_script -- el script
  es interactivo, sin flag ni variable de entorno para saltar sus
  confirmaciones, asi que hay que alimentarle stdin) y parseando su
  salida estandar. Esa salida es texto plano pensado para un operador
  humano, no JSON: lo unico con un formato fijo y confirmado contra el
  repo real es el banner que imprime `print_mitre_header()` en cada
  fase (ver `_MITRE_BANNER_RE` mas abajo) --

  ```
  ============================================================
    MITRE ATT&CK  |  T1595.003
    Tactic        |  Reconnaissance
    Technique     |  Active Scanning
  ============================================================
  ```

  -- que se traduce a un evento `ttp_observed`. El resto de la salida
  (texto descriptivo de cada fase) no se traduce a eventos en este
  hito: no tiene una forma estructurada confirmada, y adivinarla otra
  vez es exactamente el error que ya se corrigio una vez en este mismo
  puente (ver docs/roadmap.md).

Deliberadamente NO se usa eval() ni exec() sobre contenido de log: es
el mismo error de seguridad encontrado en DOLOS-T
(docs/analisis-repos-existentes.md, services/activity.py, eval() sobre
contenido de log que el atacante controla parcialmente) que este
puente existe en parte para no repetir. Todo documento/bloque que no
tenga la forma esperada se descarta de forma explicita (regex sobre
texto, nunca eval()) en vez de interpretarse como codigo.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from enum import Enum
from typing import Any, Iterable, Optional

from ..plugins.base import EventBus, EventType, PluginEvent, sanitize_payload_text
from .elastic import DEFAULT_ELASTIC_URL, ELASTIC_INDEX, fetch_recent_hits

logger = logging.getLogger(__name__)

# plugin_id que llevan todos los eventos que salen de este puente: el
# RuleEngine y el TelemetryCollector no distinguen entre un plugin real
# y el Playground, asi que necesitan un identificador estable para
# poder referenciarlo desde una regla si hiciera falta.
PLAYGROUND_PLUGIN_ID = "playground"


class PlaygroundSource(str, Enum):
    """Origen de un evento traducido por el puente. ELASTIC cubre todo
    lo que Filebeat indexa (ssh_honeypot, frontend, backend, mysql);
    ATTACKER es la unica excepcion, porque attacker-tools no tiene
    logging ni entrada en Filebeat (ver docstring del modulo)."""

    ELASTIC = "elastic"
    ATTACKER = "attacker"


_SOURCE_SURFACE = {
    PlaygroundSource.ELASTIC: "network",
    PlaygroundSource.ATTACKER: "network",
}


def _get_dotted(source: dict[str, Any], dotted_key: str) -> Optional[Any]:
    """Busca un campo que puede llegar como objeto anidado
    ({"mitre": {"technique_id": ...}}, la forma habitual en que un
    documento JSON representa un nombre de campo con puntos) o, si
    Filebeat/Logstash lo serializara distinto, como clave plana con el
    punto literal ("mitre.technique_id"). Se prueban ambas formas
    porque no se tuvo a la vista un documento real de Elasticsearch,
    solo la definicion de los campos en filebeat.yml."""

    if dotted_key in source:
        return source[dotted_key]
    node: Any = source
    for part in dotted_key.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _map_elastic_hit(source: dict[str, Any]) -> tuple[EventType, dict[str, Any]]:
    """Traduce el _source de un documento del indice unificado
    playground-logs-* (ssh_honeypot, frontend, backend o mysql -- el
    mapeo es el mismo sin importar cual de los cuatro lo origino,
    porque Filebeat ya resuelve la TTP antes de indexarlo) a un
    PluginEvent."""

    kind = source.get("event_type", "observed")
    payload: dict[str, Any] = {"kind": kind}

    # sanitize_payload_text() (apate.plugins.base, seccion 3.4 del
    # contrato) trunca texto largo -- descuido real encontrado al
    # investigar para el puente de telemetria externo configurable
    # (ver apate.telemetry.external_bridge): 'message'/'command' pueden
    # venir de una sesion SSH real contra el honeypot, contenido que
    # APATE no controla, y no tenian ningun limite de longitud antes de
    # esto.
    message = source.get("message")
    if message:
        payload["detail"] = sanitize_payload_text(message)
    else:
        payload["detail"] = f"Evento observado en Elasticsearch ({ELASTIC_INDEX}): {kind}"

    source_ip = source.get("source_ip")
    if source_ip:
        payload["source_ip"] = sanitize_payload_text(source_ip)

    # El honeypot SSH reporta 'username' (no un par usuario:contrasena);
    # se promueve igual a la clave 'credential' que ya reconoce la
    # extraccion de IoCs de M4 (ver apate/telemetry/models.py,
    # _IOC_PAYLOAD_KEYS), porque un username usado contra el honeypot ya
    # es en si mismo un indicador.
    username = source.get("username")
    if username:
        payload["credential"] = sanitize_payload_text(username)

    command = source.get("command")
    if command:
        payload["command"] = sanitize_payload_text(command)

    if "fake" in source:
        payload["fake"] = source["fake"]

    technique_id = _get_dotted(source, "mitre.technique_id")
    if technique_id:
        payload["ttp_id"] = technique_id
        tactic = _get_dotted(source, "mitre.tactic")
        technique_name = _get_dotted(source, "mitre.technique_name")
        if tactic:
            payload["mitre_tactic"] = tactic
        if technique_name:
            payload["mitre_technique_name"] = technique_name
        return EventType.TTP_OBSERVED, payload

    return EventType.INTERACTION, payload


# Banner que imprime print_mitre_header() en cada una de las 8 fases de
# main_attacker.py (components/base_attacker.py) -- el unico fragmento
# de la salida estandar de attacker-tools con una forma fija confirmada
# contra el repo real. Tres lineas consecutivas, en este orden, cada
# una "<label que puede tener espacios de relleno> | <valor>"; la linea
# 'Technique' es opcional por las dudas de que alguna fase no la
# incluya, pero 'MITRE ATT&CK' y 'Tactic' son las que definen un match.
_MITRE_LINE_RE = re.compile(r"^\s*MITRE ATT&CK\s*\|\s*(?P<technique_id>\S+)\s*$")
_TACTIC_LINE_RE = re.compile(r"^\s*Tactic\s*\|\s*(?P<tactic>.+?)\s*$")
_TECHNIQUE_LINE_RE = re.compile(r"^\s*Technique\s*\|\s*(?P<technique_name>.+?)\s*$")


def _extract_mitre_banners(stdout: str) -> list[dict[str, Optional[str]]]:
    """Escanea la salida estandar completa de attacker-tools buscando
    bloques 'MITRE ATT&CK | <id>' / 'Tactic | <tactic>' / opcionalmente
    'Technique | <nombre>' en lineas consecutivas (ver docstring del
    modulo). No depende de las lineas de '=' que delimitan el banner
    -- son puramente decorativas y no aportan datos -- asi que un
    cambio de ancho del banner no rompe el parseo."""

    lines = stdout.splitlines()
    banners: list[dict[str, Optional[str]]] = []
    i = 0
    while i < len(lines):
        match = _MITRE_LINE_RE.match(lines[i])
        if match is None:
            i += 1
            continue
        tactic = None
        technique_name = None
        if i + 1 < len(lines):
            tactic_match = _TACTIC_LINE_RE.match(lines[i + 1])
            if tactic_match is not None:
                tactic = tactic_match.group("tactic")
        if i + 2 < len(lines):
            technique_match = _TECHNIQUE_LINE_RE.match(lines[i + 2])
            if technique_match is not None:
                technique_name = technique_match.group("technique_name")
        banners.append({"ttp_id": match.group("technique_id"), "tactic": tactic, "technique_name": technique_name})
        i += 3
    return banners


class PlaygroundEventBridge:
    """Traduce documentos de Elasticsearch y salida del contenedor
    atacante a PluginEvent, y los publica en el EventBus de la
    operacion (mismo bus que consumen RuleEngine y TelemetryCollector).
    Cada evento publicado lleva en su payload la clave 'source' (uno de
    PlaygroundSource) para que la vista de atacante de M4b pueda
    filtrar sin depender de heuristicas sobre el contenido."""

    def __init__(
        self, *, bus: EventBus, operation_id: str, plugin_id: str = PLAYGROUND_PLUGIN_ID
    ) -> None:
        self.bus = bus
        self.operation_id = operation_id
        self.plugin_id = plugin_id
        self._attacker_pending_banner: Optional[dict[str, Optional[str]]] = None

    # -- Elasticsearch (ssh_honeypot, frontend, backend, mysql) ---------

    def ingest_elastic_hit(self, hit: dict[str, Any]) -> Optional[PluginEvent]:
        """Traduce un hit de la API de busqueda de Elasticsearch (siempre
        con '_source', que es la forma real de la respuesta de
        _search). Devuelve None sin publicar nada -- nunca levanta una
        excepcion -- si el hit no tiene esa forma: un documento
        inesperado no debe tirar abajo el resto del puente."""

        source = hit.get("_source") if isinstance(hit, dict) else None
        if not isinstance(source, dict):
            logger.warning("Hit de Elasticsearch descartado: no tiene un '_source' valido: %r", hit)
            return None
        event_type, payload = _map_elastic_hit(source)
        return self._publish(PlaygroundSource.ELASTIC, event_type, payload)

    def ingest_elastic_hits(self, hits: Iterable[dict[str, Any]]) -> list[PluginEvent]:
        """Procesa varios hits en orden (por ejemplo, hits.hits de la
        respuesta de _search); los que se descartan (ver
        ingest_elastic_hit) simplemente no aparecen en el resultado."""

        events = []
        for hit in hits:
            event = self.ingest_elastic_hit(hit)
            if event is not None:
                events.append(event)
        return events

    def fetch_and_ingest_elastic(
        self, *, elastic_url: str = DEFAULT_ELASTIC_URL, since: datetime, size: int = 500
    ) -> list[PluginEvent]:
        """Consulta Elasticsearch (`GET playground-logs-*/_search`,
        filtrando por timestamp reciente -- ver elastic.fetch_recent_hits)
        y traduce los hits obtenidos. Separado internamente en
        fetch_recent_hits() + ingest_elastic_hits() para que la
        traduccion se pueda seguir probando con hits de fixture, sin
        red real (ver tests/test_playground_events.py); esta funcion
        es la unica que hace la llamada de red."""

        hits = fetch_recent_hits(elastic_url=elastic_url, index=ELASTIC_INDEX, since=since, size=size)
        return self.ingest_elastic_hits(hits)

    # -- Contenedor atacante (docker exec + stdout, sin Filebeat) -------

    def ingest_attacker_output(self, stdout: str) -> list[PluginEvent]:
        """Escanea la salida estandar completa de run_attacker_script()
        buscando banners MITRE ATT&CK (ver _extract_mitre_banners) y
        publica un evento ttp_observed por cada uno encontrado, en
        orden. Si no aparece ningun banner (stdout vacio, o attacker-
        tools no llego a esa parte del script) devuelve una lista
        vacia -- nunca levanta una excepcion."""

        return [self._publish_attacker_banner(banner) for banner in _extract_mitre_banners(stdout)]

    def ingest_attacker_output_line(self, line: str) -> list[PluginEvent]:
        """Consume una línea del atacante sin esperar el stdout completo.

        El banner puede omitir ``Technique``. Por eso se retiene el bloque
        hasta su siguiente línea: si es ``Technique`` se publica completo; si
        no lo es, se publica sin ese campo y la línea se vuelve a procesar.
        """

        line = line.rstrip("\r\n")
        pending = self._attacker_pending_banner
        if pending is not None:
            if pending["tactic"] is None:
                tactic_match = _TACTIC_LINE_RE.match(line)
                if tactic_match is not None:
                    pending["tactic"] = tactic_match.group("tactic")
                    return []
                self._attacker_pending_banner = None
            else:
                technique_match = _TECHNIQUE_LINE_RE.match(line)
                self._attacker_pending_banner = None
                if technique_match is not None:
                    pending["technique_name"] = technique_match.group("technique_name")
                    return [self._publish_attacker_banner(pending)]
                return [self._publish_attacker_banner(pending), *self.ingest_attacker_output_line(line)]

        mitre_match = _MITRE_LINE_RE.match(line)
        if mitre_match is not None:
            self._attacker_pending_banner = {
                "ttp_id": mitre_match.group("technique_id"),
                "tactic": None,
                "technique_name": None,
            }
        return []

    def finish_attacker_output_stream(self) -> list[PluginEvent]:
        """Publica el último banner válido si el stream terminó sin Technique."""

        pending = self._attacker_pending_banner
        self._attacker_pending_banner = None
        if pending is not None and pending["tactic"] is not None:
            return [self._publish_attacker_banner(pending)]
        return []

    def _publish_attacker_banner(self, banner: dict[str, Optional[str]]) -> PluginEvent:
        payload: dict[str, Any] = {
            "kind": "mitre_technique",
            "ttp_id": banner["ttp_id"],
            "detail": f"Tecnica MITRE observada en la salida de attacker-tools: {banner['ttp_id']}",
        }
        if banner["tactic"]:
            payload["mitre_tactic"] = banner["tactic"]
        if banner["technique_name"]:
            payload["mitre_technique_name"] = banner["technique_name"]
        return self._publish(PlaygroundSource.ATTACKER, EventType.TTP_OBSERVED, payload)

    # -- Comun ------------------------------------------------------------

    def _publish(self, source: PlaygroundSource, event_type: EventType, payload: dict[str, Any]) -> PluginEvent:
        payload.setdefault("source", source.value)
        event = PluginEvent(
            event_type=event_type,
            plugin_id=self.plugin_id,
            surface=_SOURCE_SURFACE[source],
            operation_id=self.operation_id,
            payload=payload,
        )
        self.bus.publish(event)
        return event
