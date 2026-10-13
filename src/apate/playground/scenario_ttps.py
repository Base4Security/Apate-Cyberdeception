"""Cobertura de TTPs del escenario fijo del Playground (M14g) - ver
docs/roadmap.md seccion M14g.

La investigacion de M14g confirmo que el escenario simulado del Cyber
Deception Playground ("Andesfinance") es literalmente fijo: ni el
contenido del honeypot SSH, ni los datos falsos de frontend/backend, ni
las 8 fases del contenedor atacante varian segun que `Operation` de
APATE este vinculada -- el unico parametro real que ya varia es
`DECEPTION_LEVEL`. Reescribir ese contenido no se considero justificado
para una demo de BlackHat Arsenal (ver el reporte de investigacion en
la conversacion que cerro M14g). El alcance chico que si se construyo
ac'a: cruzar `Scenario.related_ttps` (M1) contra los TTPs reales que
ese escenario fijo efectivamente PUEDE producir -- informacion honesta
para el operador ("esto sí lo vas a poder observar en esta corrida",
"esto no, aunque lo esperes"), sin tocar el repo del Playground.

Dataset propio en `apate/data/playground_scenario_ttps.json` -- mismo
patron de carga que `apate.attack.catalog`/`apate.engage.catalog` (JSON
versionado, cargado una sola vez al importar este modulo), pero a
diferencia de esos dos, NO sale de una fuente publica: es un inventario
propio de dos archivos del repo real del Playground
(`attacker/attack_scripts/components/base_attacker.py::MITRE_TTPS` y
`filebeat/filebeat.yml`), ver el campo `_meta` del dataset para el
detalle completo. Capa de solo lectura, sin ningun side effect -- no
toca Docker, Elasticsearch, ni el checkout de `APATE_PLAYGROUND_PATH`
en si; funciona incluso sin ningun checkout configurado."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "playground_scenario_ttps.json"


@dataclass(frozen=True)
class ScenarioTTP:
    """Una tecnica que el escenario fijo del Playground puede producir
    de verdad en esta corrida -- `origin` distingue si sale del
    diccionario `MITRE_TTPS` del contenedor atacante, de una regla de
    Filebeat, o de ambos (las dos tablas son independientes, sin fuente
    de verdad compartida, asi que el solapamiento es coincidencia de
    contenido, no de mecanismo)."""

    id: str
    name: str
    origin: str
    attacker_phase: Optional[str]
    filebeat_rule: Optional[str]


def _load() -> list[ScenarioTTP]:
    data = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    return [
        ScenarioTTP(
            id=entry["id"],
            name=entry["name"],
            origin=entry["origin"],
            attacker_phase=entry.get("attacker_phase"),
            filebeat_rule=entry.get("filebeat_rule"),
        )
        for entry in data["ttps"]
    ]


# Cargado una sola vez al importar el modulo -- mismo criterio que
# apate.attack.catalog/apate.engage.catalog.
_SCENARIO_TTPS = _load()


def list_producible_ttps() -> list[ScenarioTTP]:
    """Las 9 tecnicas que el escenario fijo puede producir hoy. Copia
    de la lista cacheada, mismo criterio que `apate.attack.catalog`."""

    return list(_SCENARIO_TTPS)


@dataclass(frozen=True)
class ScenarioTTPCoverage:
    """Resultado de cruzar `Scenario.related_ttps` contra el dataset de
    (1) -- `producible` son las `ScenarioTTP` reales que coinciden,
    `not_producible` son los ids de `related_ttps` que no tienen
    ninguna chance de observarse en esta corrida (ni el atacante ni
    Filebeat las producen), en el orden original."""

    producible: list[ScenarioTTP]
    not_producible: list[str]


def match_scenario_ttps(related_ttps: list[str]) -> ScenarioTTPCoverage:
    """Cruza una lista de TTPs esperadas (`Scenario.related_ttps`)
    contra lo que el escenario fijo del Playground puede producir de
    verdad. No valida ids contra ningun otro catalogo (`apate.attack` u
    otro) -- un id que no este en `related_ttps` en primer lugar
    simplemente no se evalua; un id de `related_ttps` que no resuelva
    contra el dataset de (1) cae en `not_producible` tal cual, sin
    intentar adivinar si es un id invalido o uno valido que el
    escenario fijo no cubre -- esa distincion no le aporta nada al
    operador, en los dos casos el resultado practico es el mismo: no lo
    va a ver en esta corrida."""

    by_id = {ttp.id: ttp for ttp in _SCENARIO_TTPS}
    producible: list[ScenarioTTP] = []
    not_producible: list[str] = []
    for ttp_id in related_ttps:
        match = by_id.get(ttp_id)
        if match is not None:
            producible.append(match)
        else:
            not_producible.append(ttp_id)
    return ScenarioTTPCoverage(producible=producible, not_producible=not_producible)
