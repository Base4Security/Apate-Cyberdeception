"""Tests para los KPIs agregados del landing de Operaciones (M13d) --
ver docs/roadmap.md seccion M13d.

Dos niveles: unitario sobre `_dashboard_kpis()`/`_recent_rule_firings()`
y su repositorio SQLite, e integración sobre `GET /operations/` real."""

from datetime import date, timedelta, timezone, datetime
from unittest.mock import patch

from apate.core import AdversaryProfile, ClosureCriteria, Narrative, Operation, OperationStatus, RulesOfEngagement
from apate.rules import SQLiteRuleDecisionRepository
from apate.rules.models import Action, ActionKind, RuleFiring
from apate.web.blueprints.operations import _dashboard_kpis, _recent_rule_firings
from apate.web._operation_center import build_operation_list_attention

_RULE_YAML = """
rules:
  - name: "Escaneo -> activar"
    when:
      event_type: interaction
      payload:
        kind: scan
    then:
      - action: transition
        to: active
"""


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba M13d",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _end_date(days_from_now: int):
    return datetime.combine(date.today() + timedelta(days=days_from_now), datetime.min.time(), tzinfo=timezone.utc)


def _make_checkout(tmp_path):
    checkout = tmp_path / "cyberdeception-playground"
    checkout.mkdir()
    (checkout / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return checkout


# -- _dashboard_kpis(): conteos ----------------------------------------------


def test_dashboard_kpis_counts_active_and_compromised():
    active = _make_operation(name="A")
    active.mark_active()
    compromised = _make_operation(name="B")
    compromised.mark_active()
    compromised.mark_compromised()
    planning = _make_operation(name="C")

    kpis = _dashboard_kpis([active, compromised, planning])

    assert kpis["active_count"] == 1
    assert kpis["compromised_count"] == 1


def test_dashboard_kpis_ttp_coverage_counts_distinct_ttps_across_operations():
    op1 = _make_operation(adversary_profile=AdversaryProfile(name="A", expected_ttps=["T1046", "T1078"]))
    op2 = _make_operation(adversary_profile=AdversaryProfile(name="B", expected_ttps=["T1078", "T1003"]))

    kpis = _dashboard_kpis([op1, op2])

    # T1078 aparece en las dos operaciones -- cuenta una sola vez.
    assert kpis["ttp_coverage_count"] == 3


def test_dashboard_kpis_upcoming_closures_excludes_closed_and_undated_sorted_by_soonest():
    soon = _make_operation(name="Cierra pronto", closure_criteria=ClosureCriteria(end_date=_end_date(2)))
    later = _make_operation(name="Cierra despues", closure_criteria=ClosureCriteria(end_date=_end_date(10)))
    no_date = _make_operation(name="Sin fecha")
    closed = _make_operation(name="Ya cerrada", closure_criteria=ClosureCriteria(end_date=_end_date(1)))
    closed.mark_active()
    closed.close()

    kpis = _dashboard_kpis([later, no_date, soon, closed])

    assert [op.name for op in kpis["upcoming_closures"]] == ["Cierra pronto", "Cierra despues"]


def test_dashboard_kpis_upcoming_closures_capped_at_five():
    operations = [
        _make_operation(name=f"Op {i}", closure_criteria=ClosureCriteria(end_date=_end_date(i)))
        for i in range(7)
    ]

    kpis = _dashboard_kpis(operations)

    assert len(kpis["upcoming_closures"]) == 5
    assert [op.name for op in kpis["upcoming_closures"]] == ["Op 0", "Op 1", "Op 2", "Op 3", "Op 4"]


def test_dashboard_kpis_empty_operations_list_does_not_crash():
    kpis = _dashboard_kpis([])

    assert kpis["active_count"] == 0
    assert kpis["compromised_count"] == 0
    assert kpis["ttp_coverage_count"] == 0
    assert kpis["upcoming_closures"] == []


# -- _recent_rule_firings(): decisiones persistidas -------------------------


def test_recent_rule_firings_empty_without_decisions(tmp_path):
    assert _recent_rule_firings([], SQLiteRuleDecisionRepository(tmp_path / "decisions.db")) == []


def test_recent_rule_firings_combines_and_sorts_persisted_decisions(tmp_path):
    old_firing = RuleFiring(
        rule_name="regla vieja",
        actions=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE)],
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    new_firing = RuleFiring(
        rule_name="regla nueva",
        actions=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE)],
        timestamp=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    op_a = _make_operation(name="Operacion A")
    op_b = _make_operation(name="Operacion B")
    repository = SQLiteRuleDecisionRepository(tmp_path / "decisions.db")
    repository.append_firing(op_a.id, old_firing)
    repository.append_firing(op_b.id, new_firing)

    result = _recent_rule_firings([op_a, op_b], repository)

    assert [item["firing"].rule_name for item in result] == ["regla nueva", "regla vieja"]
    assert result[0]["operation_name"] == "Operacion B"


def test_recent_rule_firings_respects_limit(tmp_path):
    firings = [
        RuleFiring(
            rule_name=f"regla {i}",
            actions=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE)],
            timestamp=datetime(2026, 1, i + 1, tzinfo=timezone.utc),
        )
        for i in range(7)
    ]
    operation = _make_operation(name="Operacion A")
    repository = SQLiteRuleDecisionRepository(tmp_path / "decisions.db")
    for firing in firings:
        repository.append_firing(operation.id, firing)

    result = _recent_rule_firings([operation], repository, limit=3)

    assert len(result) == 3
    assert result[0]["firing"].rule_name == "regla 6"


# -- Integracion: GET /operations/ -------------------------------------------


def test_operations_list_shows_kpi_cards_with_correct_values(client, app):
    repo = app.config["OPERATION_REPOSITORY"]

    active = _make_operation(
        name="Activa",
        adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1046"]),
        closure_criteria=ClosureCriteria(end_date=_end_date(3)),
    )
    active.mark_active()
    repo.save(active)

    compromised = _make_operation(
        name="Comprometida", adversary_profile=AdversaryProfile(name="APT2", expected_ttps=["T1078"])
    )
    compromised.mark_active()
    compromised.mark_compromised()
    repo.save(compromised)

    response = client.get("/operations/")
    text = response.data.decode()

    assert response.status_code == 200
    assert 'class="card kpi-card"' in text
    assert "Activa" in text and "Comprometida" in text
    # 2 TTPs distintas (T1046, T1078), 1 activa, 1 comprometida, 1 cierre planificado.
    assert '<dd class="kpi-value">1</dd>' in text  # activas
    assert '<dd class="kpi-value">2</dd>' in text  # cobertura de TTPs


def test_operations_list_without_any_operation_shows_no_kpi_cards(client):
    response = client.get("/operations/")
    text = response.data.decode()

    assert response.status_code == 200
    assert "Plantilla: inici&aacute; el wizard con una operaci&oacute;n de ejemplo ya poblada." in text
    assert "En blanco: inici&aacute; el wizard sin valores precargados." in text
    assert 'class="card kpi-card"' not in text


def test_operations_list_shows_no_playground_sessions_message_when_none_active(client, app):
    repo = app.config["OPERATION_REPOSITORY"]
    repo.save(_make_operation())

    response = client.get("/operations/")

    assert response.status_code == 200
    assert b"Todav" in response.data and b"decisiones persistidas" in response.data


def test_operation_attention_summary_is_nominal_and_closed_operations_do_not_alert():
    planning = _make_operation()
    closed = _make_operation()
    closed.mark_active()
    closed.close()

    planning_summary = build_operation_list_attention(planning, event_count=0)
    closed_summary = build_operation_list_attention(closed, event_count=0)

    assert planning_summary["count"] > 0
    assert planning_summary["items"][0]["label"] == "Diseño"
    assert closed_summary == {"count": 0, "items": [], "label": "Cerrada"}


def test_operations_list_exposes_attention_without_opening_each_detail(client, app):
    operation = _make_operation(name="Necesita preparación")
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get("/operations/").get_data(as_text=True)

    assert "Requieren atenci&oacute;n" in text
    assert 'class="operation-attention-summary"' in text
    assert "Perfil" in text
    assert "no es un score" in text


def test_operations_list_shows_real_rule_firing_from_an_active_playground_session(client, app, tmp_path):
    repo = app.config["OPERATION_REPOSITORY"]
    operation = _make_operation(name="Operacion con Playground activo")
    repo.save(operation)

    client.post("/rules/", data={"rules_text": _RULE_YAML})
    app.config["APATE_PLAYGROUND_PATH"] = _make_checkout(tmp_path)

    with patch("apate.web.blueprints.playground.start_stack"):
        client.post(f"/playground/{operation.id}/start", data={"level": "basic"})

    session = app.config["PLAYGROUND_SESSIONS"][operation.id]
    session.bridge.ingest_elastic_hit({"_source": {"event_type": "scan", "source_ip": "203.0.113.5"}})

    response = client.get("/operations/")
    text = response.data.decode()

    assert response.status_code == 200
    assert "Operacion con Playground activo" in text
    assert "Escaneo -&gt; activar" in text or "Escaneo -> activar" in text
    assert "Sin sesiones de Playground activas" not in text
