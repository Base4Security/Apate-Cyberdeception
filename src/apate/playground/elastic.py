"""Cliente minimo de Elasticsearch para el puente de eventos del modo
Playground (M5) - ver events.py.

Usa unicamente `urllib.request` (biblioteca estandar) para no agregar
una dependencia nueva solo para esto, en linea con la filosofia
minimalista del proyecto (docs/diseno.md, seccion 1; `requests` ya
esta planificado recien para M8c). No es un cliente de Elasticsearch
general: solo lo suficiente para `GET playground-logs-*/_search`
filtrando por timestamp reciente, que es lo que necesita el puente de
eventos (ver docs/analisis-repos-existentes.md, verificado contra el
repo real).

**Corregido tras la verificacion manual pendiente desde M5 (ver
docs/roadmap.md), ejecutando de verdad contra Elasticsearch real:** el
filtro de rango usaba el campo `timestamp` -- confirmado con documentos
reales que ese campo **no existe en la inmensa mayoria del indice**
(los logs de consultas de MySQL, ~99.8% del volumen real medido, no
tienen ningun campo `timestamp` propio, solo `@timestamp`, el que
agrega Filebeat siempre en la ingesta) -- un filtro de rango sobre un
campo ausente no matchea esos documentos, asi que `fetch_recent_hits()`
devolvia una fraccion minima de lo que realmente habia (confirmado:
134 hits contra `timestamp` vs. 10000+ contra `@timestamp` sobre el
mismo dataset real). `@timestamp` esta presente en el 100% de los
documentos (es el que agrega Filebeat en la ingesta, no depende de que
la aplicacion origen lo incluya) -- se usa ese en el filtro y el sort
en vez de `timestamp`."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any

from ..i18n import gettext as _
from .exceptions import PlaygroundCommandError

# Indice unificado que Filebeat escribe para ssh_honeypot, frontend,
# backend y mysql (ver events.py).
ELASTIC_INDEX = "playground-logs-*"

# Puerto por defecto de Elasticsearch: no se tuvo a la vista el mapeo
# de puertos exacto del docker-compose real, asi que se usa el default
# convencional de Elasticsearch, ajustable via el parametro
# `elastic_url`.
DEFAULT_ELASTIC_URL = "http://localhost:9200"


def fetch_recent_hits(
    *,
    elastic_url: str = DEFAULT_ELASTIC_URL,
    index: str = ELASTIC_INDEX,
    since: datetime,
    size: int = 500,
    timeout: float = 10.0,
    timestamp_field: str = "@timestamp",
) -> list[dict[str, Any]]:
    """Ejecuta `GET <index>/_search` filtrando por `timestamp_field >=
    since`, ordenado ascendente, y devuelve la lista de hits crudos
    (cada uno con '_source'). No interpreta el contenido de cada hit --
    eso es responsabilidad de quien traduce (`PlaygroundEventBridge.
    ingest_elastic_hits()` para el Playground, `apate.telemetry.
    external_bridge.ExternalTelemetryBridge` para una fuente externa
    configurable).

    `timestamp_field` (default `"@timestamp"`, el que agrega Filebeat
    en la ingesta del Playground, ver docstring del modulo) es lo unico
    que hizo falta parametrizar para que esta funcion sirva tal cual
    como cliente compartido: un indice externo (T-Pot, cualquier otro
    stack con su propio ELK) no tiene por que llamar a su campo de
    timestamp igual que el Playground. Se evaluo mover esta funcion a
    un modulo neutral (`apate.telemetry`) para una separacion de capas
    "correcta" -- se descarto: es una funcion de ~20 lineas sin ningun
    otro acoplamiento a Playground mas alla de sus DOS valores por
    default (`elastic_url`/`index`, ya parametros desde M5), y
    relocalizarla habria significado inventar una traduccion de
    excepciones entre `PlaygroundCommandError` (que
    `tests/test_playground_elastic.py`/`tests/test_web_playground.py`
    ya esperan tal cual, no se puede cambiar sin romper el modo
    Playground verificado) y una excepcion neutral, por un beneficio de
    layering marginal. `apate.telemetry.external_bridge` importa esta
    funcion directo de aca (documentado ahi) en vez de duplicarla."""

    query = {
        "query": {"range": {timestamp_field: {"gte": since.isoformat()}}},
        "sort": [{timestamp_field: "asc"}],
        "size": size,
    }
    url = f"{elastic_url.rstrip('/')}/{index}/_search"
    request = urllib.request.Request(
        url,
        data=json.dumps(query).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError) as exc:
        raise PlaygroundCommandError(
            _("No se pudo consultar Elasticsearch en '%(url)s': %(error)s", url=url, error=exc)
        ) from exc
    return body.get("hits", {}).get("hits", [])
