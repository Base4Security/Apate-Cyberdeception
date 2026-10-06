"""Heatmap de TTPs (M13a, estilo MITRE ATT&CK Navigator) - extraido de
`apate.web.blueprints.operations` en M14f para que
`apate.web.blueprints.playground` (vista "esperado vs. observado" del
defensor del Playground) lo use tambien, sin duplicar la logica de
clasificacion de status por tecnica -- los dos blueprints tienen que
clasificar cada tecnica exactamente igual sobre el mismo
`OperationReport`, no con una segunda implementacion que pueda
divergir con el tiempo.

Modulo interno de `apate.web` (prefijo `_` en el nombre de archivo,
igual que `_ttp_heatmap()` ya era "privada" del blueprint de
operaciones antes de esta extraccion) -- no pensado para usarse fuera
de los blueprints de esta app. `apate.web.blueprints.operations` sigue
siendo el unico lugar que arma el formulario de perfil de adversario
(M12j), asi que `techniques_by_tactic()` se importa desde ahi con el
mismo nombre de siempre (`_techniques_by_tactic`) via alias en el
import -- este modulo no le agrega ningun uso nuevo, solo lo comparte."""

from __future__ import annotations

from typing import Optional

from ..attack import Technique, list_techniques
from ..reporting import OperationReport


def techniques_by_tactic() -> dict[str, list[Technique]]:
    """Agrupa el catalogo de `apate.attack` por tactica, ordenado
    alfabeticamente por nombre de tactica -- el formulario de perfil de
    adversario (M12j) arma un grupo de checkboxes por tactica en vez de
    una lista plana de 41 tecnicas, y el heatmap (mas abajo) arma sus
    columnas de la misma forma."""

    grouped: dict[str, list[Technique]] = {}
    for technique in list_techniques():
        grouped.setdefault(technique.tactic, []).append(technique)
    return dict(sorted(grouped.items()))


# Status posibles de una celda del heatmap de TTPs (M13a) -> etiqueta en
# espanol, reusada tanto para las TTPs sin celda (fuera del catalogo
# curado, listadas aparte) como -- indirectamente, via las mismas clases
# CSS ttp-cell-<status> -- para la leyenda estatica del template.
TTP_STATUS_LABELS = {
    "matched": "coincidente",
    "not-observed": "esperada, no observada",
    "unexpected": "observada, no esperada",
}


def ttp_heatmap(report: OperationReport) -> dict:
    """Arma las columnas del heatmap de TTPs (M13a, estilo MITRE ATT&CK
    Navigator: columnas por tactica, tecnicas apiladas dentro de cada
    columna) a partir de un `OperationReport` ya generado -- pura capa
    de presentacion sobre `techniques_by_tactic()`, `generate_report()`
    no cambia. Cada tecnica del catalogo curado de 41 (`apate.attack`,
    M12j) se clasifica en un unico status ("matched"/"not-observed"/
    "unexpected"/`None`) segun a que conjunto del informe pertenece.

    Las TTPs del informe que no resuelven a ninguna tecnica del
    catalogo curado (`expected_ttps` nunca se valido contra el
    catalogo desde M12j, y la telemetria observada puede ser
    cualquier cosa) no tienen celda en la grilla -- se listan aparte
    en `uncatalogued` para no perder esa informacion en silencio,
    cubriendo los tres conjuntos (no solo `unexpected_ttps`, aunque
    sea el caso mas probable en la practica).

    Sin gate sobre `operation.status` -- eso es decision de quien
    llama (operations.py::detail() solo la usa para operaciones
    CLOSED; playground.py::defender_view() la usa en cualquier
    estado, M14f)."""

    matched = set(report.matched_ttps)
    not_observed = set(report.ttps_not_observed)
    unexpected = set(report.unexpected_ttps)
    catalog_ids = {technique.id for technique in list_techniques()}

    def _status(ttp_id: str) -> Optional[str]:
        if ttp_id in matched:
            return "matched"
        if ttp_id in not_observed:
            return "not-observed"
        if ttp_id in unexpected:
            return "unexpected"
        return None

    columns = [
        {
            "tactic": tactic,
            "cells": [{"technique": technique, "status": _status(technique.id)} for technique in techniques],
        }
        for tactic, techniques in techniques_by_tactic().items()
    ]

    uncatalogued = []
    for status, ttp_ids in (
        ("matched", matched - catalog_ids),
        ("not-observed", not_observed - catalog_ids),
        ("unexpected", unexpected - catalog_ids),
    ):
        for ttp_id in sorted(ttp_ids):
            uncatalogued.append({"id": ttp_id, "status": status, "label": TTP_STATUS_LABELS[status]})

    return {"columns": columns, "uncatalogued": uncatalogued}
