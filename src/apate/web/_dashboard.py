"""KPIs agregados sobre operaciones (M13d, `operations.list_operations()`)
- extraido de `apate.web.blueprints.operations` para que la landing de
`create_app()` (`GET /`) lo use tambien, mismo criterio que
`_ttp_presentation.py`/`_portfolio.py`: decision explicita entre
importar cruzando el prefijo `_` de `operations.py` o extraer a un
modulo neutral -- se eligio extraer, para que ningun blueprint "sea
dueno" de una funcion que ahora usan dos consumidores. `operations.py`
sigue importando esto con el mismo nombre de siempre (`_dashboard_kpis`)
via alias, cero cambio de comportamiento.

Modulo interno de `apate.web` (prefijo `_`), no pensado para usarse
fuera de esta app."""

from __future__ import annotations

from ..core import Operation, OperationStatus


def dashboard_kpis(operations: list[Operation]) -> dict:
    """KPIs agregados para el landing de Operaciones (M13d) y para la
    landing raiz (`GET /`) -- pura agregacion sobre datos ya cargados
    por `list_operations()`, sin tocar `apate.core.models` ni pagar el
    costo de generar un `OperationReport` (M6) por operacion en cada
    carga de la pagina: "cobertura de TTPs agregada" se calcula sobre
    `AdversaryProfile.expected_ttps` (lo planificado, ya en memoria),
    no contra telemetria observada -- decision explicita de M13d,
    documentada en docs/roadmap.md, no un atajo sin pensar.

    Vacio (`operations == []`) da conteos en cero y listas vacias, sin
    excepciones -- quien llama decide si mostrar o no las tarjetas de
    KPI en ese caso (no tiene sentido mostrarlas con nada adentro)."""

    active_count = sum(1 for op in operations if op.status == OperationStatus.ACTIVE)
    compromised_count = sum(1 for op in operations if op.status == OperationStatus.COMPROMISED)

    ttp_coverage = {ttp for op in operations for ttp in op.adversary_profile.expected_ttps}

    upcoming_closures = sorted(
        (
            op
            for op in operations
            if op.status != OperationStatus.CLOSED and op.closure_criteria.end_date is not None
        ),
        key=lambda op: op.closure_criteria.end_date,
    )[:5]

    return {
        "active_count": active_count,
        "compromised_count": compromised_count,
        "ttp_coverage_count": len(ttp_coverage),
        "upcoming_closures": upcoming_closures,
    }
