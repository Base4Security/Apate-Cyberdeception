"""Motor determinista de sugerencia de actividades de Engage -- dos
fuentes de señal, dos funciones hermanas, mismo criterio de "asistir,
nunca decidir" (seccion 8 del documento de diseño) para las dos.

**`suggest_activities()` (M12d) - TTP -> actividad puntual.** Dataset
propio en `apate/data/engage_ttp_suggestions.json`, mismo patron de
carga que `apate.attack.catalog`/`apate.engage.catalog`: se carga una
sola vez al importar este modulo. Sale de `attack_mapping.json`
(dataset oficial de `mitre/engage`, Apache-2.0) muestreado tecnica por
tecnica y generalizado a nivel de **tactica** de ATT&CK -- ver el
campo `_meta` del propio archivo para la metodologia completa, incluida
la lista exacta de tecnicas muestreadas por tactica.

Cuatro tacticas (`initial-access`, `impact`, `exfiltration`,
`resource-development`) quedan sin ninguna actividad sugerida a
proposito -- el dataset oficial de MITRE no tiene entradas para ellas
en las tecnicas muestreadas, consistente con que Engage modela
vulnerabilidades que se revelan durante la interaccion del adversario
con el entorno de engagement, no tacticas de pre-compromiso o de
impacto/salida macro. No se inventan sugerencias para esas tacticas
-- `suggest_activities()` simplemente no les aporta nada.

**`suggest_activities_for_objectives()` -- StrategicObjective (paso 2
de la metodologia) -> Approach completo, no actividad puntual.**
Dataset propio en `apate/data/engage_objective_suggestions.json`.
**A diferencia del dataset de arriba, este NO sale de ninguna fuente
oficial** -- no existe ningun dataset publico que relacione
`StrategicObjective` (taxonomia de cinco categorias del paper Pacheco
& Staino, no de MITRE Engage) contra Goals/Approaches de Engage. Es un
juicio interpretativo de APATE sobre las descripciones textuales
reales de cada Approach -- ver el campo `_meta` de ese archivo para el
razonamiento completo, caso por caso, incluidos los dos casos
ambiguos (`attribution`/`controls_validation`) y por que se descarto
la alternativa considerada en cada uno. Resuelve a nivel de Approach
(no de Activity individual) a proposito: bajar a nivel de actividad
puntual sin ninguna fuente que lo respalde sumaria precision falsa
sobre un juicio ya interpretativo.

Asistencia de planificacion en tiempo de diseño, nunca aplicada
automaticamente -- el motor de reglas (M3) sigue siendo el unico que
decide en tiempo de ejecucion (seccion 8 del documento de diseño)."""

from __future__ import annotations

import json
from pathlib import Path

from ..attack import list_techniques
from .catalog import Activity, get_activity, list_activities

_TTP_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "engage_ttp_suggestions.json"
_OBJECTIVE_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "engage_objective_suggestions.json"


def _load_tactic_activity_map() -> dict[str, list[str]]:
    data = json.loads(_TTP_DATA_PATH.read_text(encoding="utf-8"))
    return {tactic: list(activity_ids) for tactic, activity_ids in data["tactic_activity_map"].items()}


def _load_objective_approach_map() -> dict[str, list[str]]:
    data = json.loads(_OBJECTIVE_DATA_PATH.read_text(encoding="utf-8"))
    return {objective: list(approach_ids) for objective, approach_ids in data["objective_approach_map"].items()}


# Cargados una sola vez al importar el modulo -- mismo criterio que
# apate.attack.catalog/apate.engage.catalog.
_TACTIC_ACTIVITY_MAP = _load_tactic_activity_map()
_OBJECTIVE_APPROACH_MAP = _load_objective_approach_map()


def suggest_activities(ttps: list[str]) -> list[Activity]:
    """Sugiere actividades de Engage relevantes a partir de una lista
    de IDs de tecnica de ATT&CK (ej. `AdversaryProfile.expected_ttps`).

    Resuelve cada id a su tactica real via `apate.attack.
    list_techniques()` (catalogo curado de 41 tecnicas, M12j) -- un id
    que no esta en ese catalogo no tiene tactica resoluble y se ignora
    en silencio, no rompe ni asume una tactica por default. Junta los
    `eac_id` mapeados para esas tacticas (deduplicados, en el orden en
    que se encuentran) y devuelve las `Activity` reales
    correspondientes -- nunca strings sueltos ni ids crudos; un
    `eac_id` que no resuelva a ninguna `Activity` del catalogo (no
    deberia pasar, pero no se asume) tambien se ignora en silencio,
    igual que hace `get_activity()` con un id desconocido."""

    technique_by_id = {technique.id: technique for technique in list_techniques()}

    seen_activity_ids: set[str] = set()
    activity_ids: list[str] = []
    for ttp in ttps:
        technique = technique_by_id.get(ttp)
        if technique is None:
            continue
        for activity_id in _TACTIC_ACTIVITY_MAP.get(technique.tactic, []):
            if activity_id not in seen_activity_ids:
                seen_activity_ids.add(activity_id)
                activity_ids.append(activity_id)

    activities = []
    for activity_id in activity_ids:
        activity = get_activity(activity_id)
        if activity is not None:
            activities.append(activity)
    return activities


def suggest_activities_for_objectives(objectives: list[str]) -> list[Activity]:
    """Sugiere actividades de Engage a partir de los objetivos
    estrategicos de la operacion (`StrategicObjective.value`, paso 2 de
    la metodologia -- `StrategicDecisions.objectives`). Funcion hermana
    de `suggest_activities()` (TTPs, paso 1): dos señales distintas,
    conceptualmente independientes, que se combinan en la UI pero se
    calculan por separado aca -- ver el docstring del modulo sobre por
    que esta funcion en particular es un juicio interpretativo de
    APATE, no una extraccion verificada.

    Un objetivo sin entrada en el dataset (no deberia pasar con los
    cinco valores reales de `StrategicObjective`, pero no se asume) se
    ignora en silencio, mismo criterio que un TTP fuera del catalogo en
    `suggest_activities()`. A diferencia de esa funcion, resuelve a
    **Approach** (no a un solo `eac_id` por entrada del dataset) --
    cada Approach mapeado aporta todas sus actividades `kind ==
    "engagement"` reales del catalogo, deduplicadas en el orden en que
    se encuentran."""

    seen_activity_ids: set[str] = set()
    activities: list[Activity] = []
    for objective in objectives:
        for approach_id in _OBJECTIVE_APPROACH_MAP.get(objective, []):
            for activity in list_activities(approach_id=approach_id, kind="engagement"):
                if activity.id not in seen_activity_ids:
                    seen_activity_ids.add(activity.id)
                    activities.append(activity)
    return activities
