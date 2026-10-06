"""Catalogo de MITRE Engage (M12a) - ver docs/analisis-engage-integral.md.

Dataset propio en `apate/data/mitre_engage_matrix.json`, mismo patron
que `apate.attack.catalog` (dataset de MITRE ATT&CK, M12j): los datos
externos viven en un archivo de datos versionado, no hardcodeados en
codigo Python. IDs/nombres/descripciones de Goals/Approaches/
Activities tomados literal del dataset publico oficial de
github.com/mitre/engage (Apache-2.0); la relacion many-to-many
Approach->Activity y Goal->Approach no viene en un archivo de
relaciones separado en ese repo (no existe uno publico) -- se completo
cruzando contra la matriz visual real (engage.mitre.org/matrix/, v1.0).
Ver el campo `_meta` del propio JSON para la metodologia completa.

5 Goals (Prepare/Understand = `strategic`, Expose/Affect/Elicit =
`engagement`), 9 Approaches (cada uno con `goal_id`), 31 Activities (23
`engagement` + 8 `strategic`, cada una con `approach_ids: list[str]`
porque una misma actividad puede pertenecer a mas de un Approach --
ej. "Lures" esta en Detect/Direct/Disrupt).

Catalogo de solo lectura: igual que `apate.attack.catalog`, estos
dataclasses no tienen to_dict()/from_dict() -- no se persisten ni se
serializan a JSON de operacion, se cargan una vez desde el archivo de
datos (al importar este modulo, no en cada request) y se consultan en
memoria."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_engage_matrix.json"


@dataclass(frozen=True)
class Goal:
    """Un Goal de MITRE Engage -- el nivel mas alto de la matriz.
    `kind` distingue los dos Goals `strategic` (Prepare/Understand, el
    "antes"/"despues" de una operacion) de los tres `engagement`
    (Expose/Affect/Elicit, lo que pasa durante ella)."""

    id: str
    name: str
    kind: str
    description: str


@dataclass(frozen=True)
class Approach:
    """Un Approach de MITRE Engage, agrupado bajo un Goal (`goal_id`)."""

    id: str
    name: str
    goal_id: str
    description: str


@dataclass(frozen=True)
class Activity:
    """Una Activity de MITRE Engage. `approach_ids` es una lista, no un
    campo unico, porque una misma actividad puede pertenecer a mas de
    un Approach (ver docstring del modulo, ejemplo "Lures")."""

    id: str
    name: str
    kind: str
    approach_ids: list[str]
    description: str


def _load() -> tuple[list[Goal], list[Approach], list[Activity]]:
    data = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    goals = [
        Goal(id=entry["id"], name=entry["name"], kind=entry["kind"], description=entry.get("description", ""))
        for entry in data["goals"]
    ]
    approaches = [
        Approach(
            id=entry["id"],
            name=entry["name"],
            goal_id=entry["goal_id"],
            description=entry.get("description", ""),
        )
        for entry in data["approaches"]
    ]
    activities = [
        Activity(
            id=entry["id"],
            name=entry["name"],
            kind=entry["kind"],
            approach_ids=list(entry.get("approach_ids", [])),
            description=entry.get("description", ""),
        )
        for entry in data["activities"]
    ]
    return goals, approaches, activities


# Cargado una sola vez al importar el modulo -- mismo criterio que
# apate.attack.catalog ("no en cada request").
_GOALS, _APPROACHES, _ACTIVITIES = _load()


def list_goals() -> list[Goal]:
    """Los 5 Goals del catalogo. Copia de la lista cacheada -- quien la
    reciba no puede mutar el catalogo compartido."""

    return list(_GOALS)


def list_approaches(goal_id: Optional[str] = None) -> list[Approach]:
    """Todos los Approaches, o solo los de `goal_id` (ej. "EGO0001")
    si se pasa. Copia de la lista cacheada, mismo criterio que
    `list_goals()`."""

    if goal_id is None:
        return list(_APPROACHES)
    return [approach for approach in _APPROACHES if approach.goal_id == goal_id]


def list_activities(approach_id: Optional[str] = None, kind: Optional[str] = None) -> list[Activity]:
    """Todas las Activities, filtradas por `approach_id` (una activity
    matchea si `approach_id` esta en su `approach_ids`) y/o por `kind`
    ("engagement"/"strategic") -- ambos filtros son independientes y se
    aplican juntos si se pasan los dos. Copia de la lista cacheada."""

    activities = _ACTIVITIES
    if approach_id is not None:
        activities = [activity for activity in activities if approach_id in activity.approach_ids]
    if kind is not None:
        activities = [activity for activity in activities if activity.kind == kind]
    return list(activities)


def get_activity(activity_id: str) -> Optional[Activity]:
    """La Activity con ese id (ej. "EAC0005"), o `None` si no existe en
    el catalogo -- nunca lanza."""

    for activity in _ACTIVITIES:
        if activity.id == activity_id:
            return activity
    return None
