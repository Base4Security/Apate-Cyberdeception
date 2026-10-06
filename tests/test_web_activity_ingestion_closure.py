"""E7 de docs/improvements.md: el cierre automático por vencimiento nunca
se ejecutaba.

`RuleEngine.check_closure()` no tenía ningún invocador en código de
producción -- sus únicas apariciones fuera de la definición eran
docstrings -- y `Operation.is_past_due()` solo se llamaba desde ahí. El
formulario expone `end_date`, el dashboard lista "próximos cierres" y
`ClosureCriteria` lo valida, pero la operación no se cerraba nunca. Es el
mismo patrón que la verificación manual de M5 encontró en
`fetch_and_ingest_elastic()`.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from apate.core.models import (
    AdversaryProfile,
    ClosureCriteria,
    Environment,
    Narrative,
    Operation,
    OperationStatus,
    RulesOfEngagement,
)
from apate.web._activity_ingestion import ActivityIngestionService

_REGLA_DE_CIERRE = """rules:
  - name: Cerrar al vencer
    when:
      closure_due: true
    then:
      - action: transition
        to: closed
"""


def _operacion(*, end_date, status=OperationStatus.ACTIVE, nombre="Op"):
    operacion = Operation(
        name=nombre,
        adversary_profile=AdversaryProfile(name="a"),
        roe=RulesOfEngagement(environment=Environment.ISOLATED),
        narrative=Narrative(name="n"),
        closure_criteria=ClosureCriteria(end_date=end_date),
    )
    if status == OperationStatus.ACTIVE:
        operacion.mark_active()
    elif status == OperationStatus.CLOSED:
        operacion.mark_active()
        operacion.close()
    return operacion


def _ayer():
    return datetime.now(timezone.utc) - timedelta(days=1)


def _manana():
    return datetime.now(timezone.utc) + timedelta(days=1)


@pytest.fixture
def servicio(app):
    Path(app.config["APATE_RULES_PATH"]).write_text(_REGLA_DE_CIERRE, encoding="utf-8")
    return ActivityIngestionService(app, enabled=True, interval_seconds=0.1)


def _recargar(app, operacion):
    return app.config["OPERATION_REPOSITORY"].get(operacion.id)


# -- La regresión --------------------------------------------------------


def test_an_expired_operation_is_closed_by_the_heartbeat(app, servicio):
    operacion = _operacion(end_date=_ayer())
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()

    assert _recargar(app, operacion).status == OperationStatus.CLOSED


def test_the_closure_is_persisted_not_only_in_memory(app, servicio):
    operacion = _operacion(end_date=_ayer())
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()

    recargada = _recargar(app, operacion)
    assert recargada.closed_at is not None


def test_the_closure_leaves_an_auditable_firing(app, servicio):
    operacion = _operacion(end_date=_ayer())
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()
        disparos = app.config["RULE_DECISION_REPOSITORY"].list_firings_for_operation(operacion.id)

    assert [d.rule_name for d in disparos] == ["Cerrar al vencer"]


# -- Lo que no debe cerrar ----------------------------------------------


def test_an_operation_still_in_time_is_untouched(app, servicio):
    operacion = _operacion(end_date=_manana())
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()

    assert _recargar(app, operacion).status == OperationStatus.ACTIVE


def test_an_operation_without_end_date_is_untouched(app, servicio):
    operacion = _operacion(end_date=None)
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()

    assert _recargar(app, operacion).status == OperationStatus.ACTIVE


def test_without_a_closure_rule_end_date_stays_informative(app):
    """No se cambia la semántica del motor: cierra solo si el operador
    escribió una regla `closure_due`, que es el mecanismo explícito que el
    editor de reglas ya ofrece."""

    Path(app.config["APATE_RULES_PATH"]).write_text("rules: []\n", encoding="utf-8")
    servicio = ActivityIngestionService(app, enabled=True, interval_seconds=0.1)
    operacion = _operacion(end_date=_ayer())
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()

    assert _recargar(app, operacion).status == OperationStatus.ACTIVE


def test_closures_are_skipped_when_rules_are_disabled(app):
    Path(app.config["APATE_RULES_PATH"]).write_text(_REGLA_DE_CIERRE, encoding="utf-8")
    servicio = ActivityIngestionService(app, enabled=True, rules_enabled=False)
    operacion = _operacion(end_date=_ayer())
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()

    assert _recargar(app, operacion).status == OperationStatus.ACTIVE


def test_an_already_closed_operation_is_not_reprocessed(app, servicio):
    operacion = _operacion(end_date=_ayer(), status=OperationStatus.CLOSED)
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()
        disparos = app.config["RULE_DECISION_REPOSITORY"].list_firings_for_operation(operacion.id)

    assert disparos == []


# -- Cobertura e aislamiento --------------------------------------------


def test_closure_does_not_depend_on_having_buda_or_dolost_bindings(app, servicio):
    """El sondeo de actividad solo mira bindings BUDA/DOLOS-T; el
    vencimiento no depende de ninguna capacidad."""

    operacion = _operacion(end_date=_ayer(), nombre="Sin capacidades")
    assert operacion.plugins == []
    app.config["OPERATION_REPOSITORY"].save(operacion)

    with app.app_context():
        servicio.poll_once()

    assert _recargar(app, operacion).status == OperationStatus.CLOSED


def test_one_broken_operation_does_not_stop_the_others(app, servicio, monkeypatch):
    rota = _operacion(end_date=_ayer(), nombre="Rota")
    sana = _operacion(end_date=_ayer(), nombre="Sana")
    for operacion in (rota, sana):
        app.config["OPERATION_REPOSITORY"].save(operacion)

    original = ActivityIngestionService._check_closures

    import apate.web._activity_ingestion as modulo

    real_build = modulo.build_operation_plugins

    def build_con_falla(operation, bus, **kwargs):
        if operation.id == rota.id:
            raise RuntimeError("binding imposible")
        return real_build(operation, bus, **kwargs)

    monkeypatch.setattr(modulo, "build_operation_plugins", build_con_falla)

    with app.app_context():
        original(servicio)

    assert _recargar(app, sana).status == OperationStatus.CLOSED
    assert _recargar(app, rota).status == OperationStatus.ACTIVE
