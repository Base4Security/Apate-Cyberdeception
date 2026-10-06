"""Vista de portafolio (M13g, ver docs/roadmap.md seccion M13g):
cobertura agregada entre TODAS las operaciones -- extension de M13a
(heatmap de TTPs por operacion) a nivel de portafolio, mas actividades
de Engage y plugins por kind agregados entre operaciones. Depende de
M13a, ya completo (reusa `techniques_by_tactic()`/`TTP_STATUS_LABELS`
de `apate.web._ttp_presentation` tal cual, sin tocarlos).

Modulo interno de `apate.web` (mismo patron que `_ttp_presentation.py`,
M14f): la agregacion es sustancial (tres agregaciones distintas) y no
es logica de negocio de ningun paquete `apate.*` -- pura capa de
presentacion sobre lo que `apate.reporting`/`apate.attack`/
`apate.engage`/`apate.plugins` ya exponen, asi que vive en su propio
modulo en vez de crecer mas `apate.web.blueprints.operations` (ya el
archivo mas grande del blueprint).

**Costo -- actualizado en la Fase 7 de integración:** la versión
original (M13g) llamaba `generate_report()` una vez por operación. La
Fase 4 post-BlackHat lo reemplazó por una consulta agrupada de TTPs y
esta fase amplía el contrato a registros normalizados completos con
`TelemetryRepository.list_for_operations()`. Una sola consulta alimenta
el heatmap y las métricas transversales (eventos, IoCs, proveedores y
período), sin consultar estadísticas internas de BUDA.

**Semantica de agregacion del heatmap de TTPs, decision explicita:**
un booleano "coincidio en alguna operacion" hubiera perdido
informacion real de un portafolio -- se optó por un *conteo* por cada
uno de los tres conjuntos (matched/not_observed/unexpected), mas
trabajo de presentacion pero bastante mas util para un operador que
esta mirando el portafolio a proposito. Cada celda se colorea por el
status "dominante" (matched > not_observed > unexpected, la mejor
señal disponible para esa tecnica en todo el portafolio) y muestra el
conteo de ese status junto al nombre; el desglose completo de los tres
conteos queda en el `title` de la celda, igual que M13a ya usaba
`title` para mostrar el id/nombre completo.

**Filtro de que operaciones entran, decision explicita:** una operacion
sin ninguna `AdversaryProfile.expected_ttps` no aporta nada a ningun
conjunto del heatmap agregado (sus matched/not_observed/unexpected
quedan vacios los tres, `generate_report()` sobre ella es una consulta
de telemetria que no iba a sumar nada) pero SI infla el denominador "de
cuantas operaciones" que le da sentido a los conteos -- se excluye del
heatmap agregado (`ttp_operations_count` cuenta solo las que quedan,
`excluded_count` lo dice explicito en vez de perder la diferencia en
silencio). Las actividades de Engage y los plugins por kind, en
cambio, son sumas simples sobre `PluginBinding` -- una operacion sin
plugins ya contribuye cero de forma natural a esos dos, sin necesitar
el mismo filtro."""

from __future__ import annotations

from datetime import datetime, timezone
from collections.abc import Iterable
from typing import Optional

from ..attack import list_techniques
from ..assets import Asset
from ..core.models import Operation, PluginBinding
from ..engage import get_activity, list_activities, list_approaches, list_goals
from ..plugins import PluginRegistry
from ..reporting import compare_ttps, plugin_effect_summaries
from ._operational_metrics import build_portfolio_operational_metrics
from ._asset_coverage import _CRITICALITY_ORDER
from ._ttp_presentation import TTP_STATUS_LABELS, techniques_by_tactic


def _dominant_status(matched: int, not_observed: int, unexpected: int) -> tuple[Optional[str], int]:
    """Prioridad matched > not-observed > unexpected -- la mejor senal
    disponible para esa tecnica en todo el portafolio. `count` es el
    conteo de ese status puntual (no la suma de los tres)."""

    if matched:
        return "matched", matched
    if not_observed:
        return "not-observed", not_observed
    if unexpected:
        return "unexpected", unexpected
    return None, 0


def _portfolio_ttp_heatmap(reports: list, operation_ids: Optional[list[str]] = None) -> dict:
    """Mismo layout que `_ttp_presentation.ttp_heatmap()` (columnas por
    tactica del catalogo curado de 41, tecnicas apiladas dentro de cada
    columna) pero agregado entre `reports` en vez de uno solo -- ver
    docstring del modulo para la semantica de conteo/status dominante."""

    matched_counts: dict[str, int] = {}
    not_observed_counts: dict[str, int] = {}
    unexpected_counts: dict[str, int] = {}
    operation_ids_by_ttp: dict[str, set[str]] = {}
    for index, report in enumerate(reports):
        operation_id = operation_ids[index] if operation_ids else None
        for ttp_id in report.matched_ttps:
            matched_counts[ttp_id] = matched_counts.get(ttp_id, 0) + 1
            if operation_id:
                operation_ids_by_ttp.setdefault(ttp_id, set()).add(operation_id)
        for ttp_id in report.ttps_not_observed:
            not_observed_counts[ttp_id] = not_observed_counts.get(ttp_id, 0) + 1
            if operation_id:
                operation_ids_by_ttp.setdefault(ttp_id, set()).add(operation_id)
        for ttp_id in report.unexpected_ttps:
            unexpected_counts[ttp_id] = unexpected_counts.get(ttp_id, 0) + 1
            if operation_id:
                operation_ids_by_ttp.setdefault(ttp_id, set()).add(operation_id)

    def _cell(technique) -> dict:
        matched = matched_counts.get(technique.id, 0)
        not_observed = not_observed_counts.get(technique.id, 0)
        unexpected = unexpected_counts.get(technique.id, 0)
        status, count = _dominant_status(matched, not_observed, unexpected)
        return {
            "technique": technique,
            "status": status,
            "count": count,
            "matched_count": matched,
            "not_observed_count": not_observed,
            "unexpected_count": unexpected,
            "operation_ids": sorted(operation_ids_by_ttp.get(technique.id, ())),
        }

    columns = [
        {"tactic": tactic, "cells": [_cell(technique) for technique in techniques]}
        for tactic, techniques in techniques_by_tactic().items()
    ]

    catalog_ids = {technique.id for technique in list_techniques()}
    all_ttp_ids = set(matched_counts) | set(not_observed_counts) | set(unexpected_counts)
    uncatalogued = []
    for ttp_id in sorted(all_ttp_ids - catalog_ids):
        matched = matched_counts.get(ttp_id, 0)
        not_observed = not_observed_counts.get(ttp_id, 0)
        unexpected = unexpected_counts.get(ttp_id, 0)
        status, count = _dominant_status(matched, not_observed, unexpected)
        uncatalogued.append({"id": ttp_id, "status": status, "count": count, "label": TTP_STATUS_LABELS[status]})

    return {"columns": columns, "uncatalogued": uncatalogued}


def _portfolio_engage_coverage(operations: list[Operation]) -> list[dict]:
    """Cuantas operaciones *distintas* planificaron cada actividad de
    Engage "engagement" (Expose/Affect/Elicit) en al menos un
    `PluginBinding` -- mismo agrupado Goal -> Approach que ya usa el
    selector de "Vincular plugin" (M12c,
    `operations.py::_engagement_activities_by_goal()`), pero contando
    operaciones en vez de armar checkboxes; no reusa esa funcion
    directamente porque el resultado que necesita el portafolio es
    otro (conteo, no estructura de formulario). Cuenta OPERACIONES, no
    bindings sueltos -- que una misma actividad este planificada dos
    veces dentro de la misma operacion no debe pesar el doble que
    estar planificada una vez en dos operaciones distintas.

    **Tercer item del backlog de Engage post-M12 (ver docs/roadmap.md):
    `measured_count`, mismo denominador que `operation_count`** --
    cuantas de esas operaciones tienen ademas al menos un binding con
    esa actividad *medido* (`DeceptionEffect.is_measured`, via
    `PluginEffectSummary` de la Fase 2 post-BlackHat). Cobertura de
    *medicion*, no de exito: `measured_outcome` es texto libre a
    proposito (decision explicita de la Fase 2 -- importa la nota
    humana de que se observo, no un booleano), asi que no hay forma
    honesta de calcular un "% de efectividad" por actividad sin
    fabricar una metrica que el modelo de datos no sostiene. Los
    textos reales quedan aparte, en `_portfolio_measured_effect_notes()`,
    para que el operador los lea el mismo en vez de que el sistema
    decida por el que "funciona"."""

    operation_ids_by_activity: dict[str, set[str]] = {}
    measured_operation_ids_by_activity: dict[str, set[str]] = {}
    for operation in operations:
        summaries = plugin_effect_summaries(operation)
        for binding, summary in zip(operation.plugins, summaries):
            for activity_id in binding.effect.engage_activity_ids:
                operation_ids_by_activity.setdefault(activity_id, set()).add(operation.id)
                if summary.is_measured:
                    measured_operation_ids_by_activity.setdefault(activity_id, set()).add(operation.id)

    result = []
    for goal in list_goals():
        if goal.kind != "engagement":
            continue
        approaches = []
        for approach in list_approaches(goal_id=goal.id):
            activities = [
                {
                    "activity": activity,
                    "operation_count": len(operation_ids_by_activity.get(activity.id, ())),
                    "measured_count": len(measured_operation_ids_by_activity.get(activity.id, ())),
                }
                for activity in list_activities(approach_id=approach.id, kind="engagement")
            ]
            if activities:
                approaches.append({"approach": approach, "activities": activities})
        if approaches:
            result.append({"goal": goal, "approaches": approaches})
    return result


def _portfolio_measured_effect_notes(operations: list[Operation]) -> list[dict]:
    """Los textos reales de `DeceptionEffect.measured_outcome` (Fase 2
    post-BlackHat) de bindings que ademas declaran alguna actividad de
    Engage -- la alternativa honesta a una metrica de "% de
    efectividad" que el modelo de datos no sostiene (ver docstring de
    `_portfolio_engage_coverage()`). Una fila por binding medido (no
    una por actividad -- un binding con mas de una actividad no repite
    el mismo texto varias veces), con las actividades como lista para
    que el template las muestre juntas. Ordenadas por fecha de
    medicion mas reciente primero -- la nota mas nueva es, en general,
    la mas relevante para un operador que entra a mirar el portafolio."""

    notes = []
    for operation in operations:
        summaries = plugin_effect_summaries(operation)
        for binding, summary in zip(operation.plugins, summaries):
            if not summary.is_measured or not binding.effect.engage_activity_ids:
                continue
            notes.append(
                {
                    "operation_id": operation.id,
                    "operation_name": operation.name,
                    "plugin_id": binding.plugin_id,
                    "activities": [get_activity(aid) for aid in binding.effect.engage_activity_ids],
                    "measured_outcome": summary.measured_outcome,
                    "measured_at": summary.measured_at,
                    "measured_by": summary.measured_by,
                }
            )

    notes.sort(key=lambda note: note["measured_at"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return notes


def _resolve_portfolio_plugin_kind(binding: PluginBinding) -> Optional[str]:
    """kind real del binding para el conteo agregado de portafolio
    (M13g) -- **deliberadamente no reusa**
    `operations.py::_plugin_kind()` (M12h): esa funcion esta acotada a
    proposito a `"dolost"`/`"buda"` (los dos unicos kinds con panel de
    mecanica especifica), mapeando `"mock"`/`"honeytoken"` explicitos a
    `None` aunque sean kinds validos -- el portafolio, en cambio,
    quiere contar los cuatro por igual ("cuantos honeytoken/mock hay
    desplegados" es justo la pregunta que este agregado responde).
    `binding.plugin_kind` explicito manda si es uno de los kinds
    registrados en `PluginRegistry`; sin kind explicito, cae al mismo
    heuristico de prefijo legacy que `_plugin_kind()` (los unicos dos
    kinds que esa convencion informal pre-M12h llego a cubrir) -- sin
    ese prefijo tampoco, queda "sin clasificar" en vez de inventarle un
    kind."""

    valid_kinds = PluginRegistry.list_kinds()
    if binding.plugin_kind in valid_kinds:
        return binding.plugin_kind
    if binding.plugin_kind is not None:
        return None
    plugin_id = binding.plugin_id.lower()
    if plugin_id.startswith("dolost"):
        return "dolost"
    if plugin_id.startswith("buda"):
        return "buda"
    return None


def _portfolio_plugin_kind_counts(operations: list[Operation]) -> dict:
    """Conteo de `PluginBinding` por kind entre TODAS las operaciones,
    con el nombre legible de `PluginRegistry.list_descriptions()`
    (M13i) en vez del kind crudo. Muestra los cuatro kinds registrados
    siempre, incluso en cero -- un portafolio tiene sentido que muestre
    tambien lo que *no* se esta usando, mismo criterio que el heatmap
    de TTPs muestra celdas neutras para tecnicas sin relacion. Bindings
    que no resuelven a ningun kind (ver `_resolve_portfolio_plugin_kind`)
    se cuentan aparte, en `unclassified_count`, en vez de perderse en
    silencio."""

    counts: dict[Optional[str], int] = {}
    for operation in operations:
        for binding in operation.plugins:
            kind = _resolve_portfolio_plugin_kind(binding)
            counts[kind] = counts.get(kind, 0) + 1

    kinds = [
        {
            "kind": description.kind,
            "display_name": description.display_name,
            "surface": description.surface,
            "count": counts.get(description.kind, 0),
        }
        for description in PluginRegistry.list_descriptions()
    ]
    return {"kinds": kinds, "unclassified_count": counts.get(None, 0)}


def _portfolio_asset_coverage(operations: list[Operation], inventory_assets: Iterable[Asset]) -> dict:
    """Agrega cobertura explícita de activos entre operaciones.

    Las dos preguntas no se mezclan: ``covered`` contesta si alguna
    capacidad declara proteger al activo y ``targeted_uncovered`` si el
    activo entró en al menos un plan pero ninguna capacidad lo protege.
    ``not_targeted`` conserva el caso distinto de fichas que no entraron
    en ningún plan. Cada conjunto de identificadores elimina bindings
    repetidos de una misma operación antes de contar.

    Las referencias sin ficha se devuelven por separado. No participan de
    los hallazgos de inventario ni reciben criticidad inventada, pero siguen
    siendo visibles para que el operador pueda resolverlas.
    """

    assets = list(inventory_assets)
    asset_by_identifier = {asset.identifier: asset for asset in assets}
    target_operation_ids: dict[str, set[str]] = {}
    covered_operation_ids: dict[str, set[str]] = {}

    for operation in operations:
        for reference in dict.fromkeys(operation.adversary_profile.target_assets):
            target_operation_ids.setdefault(reference, set()).add(operation.id)
        for binding in operation.plugins:
            for reference in dict.fromkeys(binding.protected_asset_ids):
                covered_operation_ids.setdefault(reference, set()).add(operation.id)

    def _entry(asset: Asset) -> dict:
        return {
            "asset": asset,
            "target_operation_ids": sorted(target_operation_ids.get(asset.identifier, ())),
            "covered_operation_ids": sorted(covered_operation_ids.get(asset.identifier, ())),
        }

    def _sort_key(entry: dict) -> tuple[int, str]:
        asset = entry["asset"]
        return (_CRITICALITY_ORDER.get(asset.criticality, 4), asset.name.lower())

    entries = [_entry(asset) for asset in assets]
    covered = sorted((entry for entry in entries if entry["covered_operation_ids"]), key=_sort_key)
    targeted_uncovered = sorted(
        (entry for entry in entries if entry["target_operation_ids"] and not entry["covered_operation_ids"]),
        key=_sort_key,
    )
    not_targeted = sorted((entry for entry in entries if not entry["target_operation_ids"]), key=_sort_key)

    unresolved_references = []
    for reference in sorted((set(target_operation_ids) | set(covered_operation_ids)) - set(asset_by_identifier), key=str.lower):
        unresolved_references.append(
            {
                "reference": reference,
                "target_operation_ids": sorted(target_operation_ids.get(reference, ())),
                "covered_operation_ids": sorted(covered_operation_ids.get(reference, ())),
            }
        )

    return {
        "inventory_count": len(assets),
        "covered": covered,
        "targeted_uncovered": targeted_uncovered,
        "not_targeted": not_targeted,
        "unresolved_references": unresolved_references,
    }


def build_portfolio(
    operations: list[Operation],
    telemetry,
    inventory_assets: Iterable[Asset] = (),
    *,
    records_by_operation: Optional[dict[str, list]] = None,
) -> dict:
    """Arma todo lo que la vista de portafolio necesita a partir de
    TODAS las operaciones del repositorio -- ver docstring del modulo
    para el filtro de que operaciones entran al heatmap de TTPs
    (`ttp_operations_count`/`excluded_count`) y por que Engage/plugins
    no necesitan el mismo filtro.

    Fase 7 de integración: una única consulta de registros completos
    alimenta tanto el heatmap como los conteos operacionales. Así se
    incorporan eventos/IoCs/período sin volver a N consultas. La cobertura
    de activos se calcula en la misma pasada de modelo, sin consultas de
    telemetría ni informes adicionales por operación."""

    operation_ids = [operation.id for operation in operations]
    if records_by_operation is None:
        records_by_operation = telemetry.list_events_by_operation(operation_ids)
    ttp_operations = [op for op in operations if op.adversary_profile.expected_ttps]
    observed_by_operation = {
        operation_id: sorted({record.ttp_id for record in records if record.ttp_id})
        for operation_id, records in records_by_operation.items()
    }
    comparisons = [
        compare_ttps(op.adversary_profile.expected_ttps, observed_by_operation.get(op.id, []))
        for op in ttp_operations
    ]

    return {
        "considered_count": len(operations),
        "ttp_operations_count": len(ttp_operations),
        "excluded_count": len(operations) - len(ttp_operations),
        "ttp_heatmap": _portfolio_ttp_heatmap(comparisons, [op.id for op in ttp_operations]),
        "operation_names": {op.id: op.name for op in operations},
        "engage_coverage": _portfolio_engage_coverage(operations),
        "measured_effect_notes": _portfolio_measured_effect_notes(operations),
        "plugin_kind_counts": _portfolio_plugin_kind_counts(operations),
        "asset_coverage": _portfolio_asset_coverage(operations, inventory_assets),
        "operational_metrics": build_portfolio_operational_metrics(
            operations,
            records_by_operation,
            telemetry_source=type(telemetry.repository).__name__,
        ),
    }
