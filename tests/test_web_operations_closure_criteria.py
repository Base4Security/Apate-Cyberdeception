"""Integración web de `ClosureCriteria` y sus Gating Criteria (M12f)."""

from apate.core import OperationStatus, PluginBinding
from apate.plugins import EventBus, EventType, PluginEvent
from apate.rules import RuleEngine


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M12f",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_new_operation_form_includes_end_date_input(client):
    response = client.get("/operations/new")

    assert response.status_code == 200
    assert b'name="end_date"' in response.data
    assert b'type="date"' in response.data


def test_creating_operation_with_end_date_sets_closure_criteria(client):
    operation_id = _create_operation(client, end_date="2026-12-31")

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b"2026-12-31" in response.data


def test_creating_operation_without_end_date_leaves_closure_criteria_empty(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    text = response.data.decode()
    assert "Fecha de cierre planificada" in text


def test_add_trigger_condition_from_web_persists_and_renders(client, app):
    operation_id = _create_operation(client)
    repo = app.config["OPERATION_REPOSITORY"]
    operation = repo.get(operation_id)
    operation.bind_plugin(PluginBinding(plugin_id="honeypot-1", plugin_kind="mock", surface="network"))
    repo.save(operation)

    response = client.post(
        f"/operations/{operation_id}/closure-criteria/trigger-conditions",
        data={
            "event_type": "ttp_observed",
            "plugin_id": "honeypot-1",
            "payload_key": "ttp_id",
            "payload_value": "T1499",
        },
        follow_redirects=True,
    )

    operation = repo.get(operation_id)
    condition = operation.closure_criteria.trigger_conditions[0]
    assert response.status_code == 200
    assert condition.event_type == EventType.TTP_OBSERVED
    assert condition.plugin_id == "honeypot-1"
    assert condition.payload == {"ttp_id": "T1499"}
    assert "TTP observada" in response.get_data(as_text=True)
    assert "ttp_id=T1499" in response.get_data(as_text=True)
    assert '<option value="honeypot-1">' in response.get_data(as_text=True)


def test_add_trigger_condition_rejects_missing_or_unknown_event_type(client, app):
    operation_id = _create_operation(client)

    for invalid_value in ("", "evento_inexistente"):
        response = client.post(
            f"/operations/{operation_id}/closure-criteria/trigger-conditions",
            data={"event_type": invalid_value},
            follow_redirects=True,
        )
        assert "Seleccioná un tipo de evento válido" in response.get_data(as_text=True)

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.closure_criteria.trigger_conditions == []


def test_delete_trigger_condition_by_index(client, app):
    operation_id = _create_operation(client)
    endpoint = f"/operations/{operation_id}/closure-criteria/trigger-conditions"
    client.post(endpoint, data={"event_type": "interaction"})
    client.post(endpoint, data={"event_type": "ttp_observed"})

    response = client.post(f"{endpoint}/0/delete", follow_redirects=True)

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert response.status_code == 200
    assert "Gating Criteria eliminada" in response.get_data(as_text=True)
    assert [item.event_type for item in operation.closure_criteria.trigger_conditions] == [
        EventType.TTP_OBSERVED
    ]


def test_condition_loaded_from_web_closes_operation_through_real_bus_and_engine(client, app):
    operation_id = _create_operation(client)
    client.post(
        f"/operations/{operation_id}/closure-criteria/trigger-conditions",
        data={"event_type": "ttp_observed", "payload_key": "ttp_id", "payload_value": "T1499"},
    )
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    operation.mark_active()
    bus = EventBus()
    RuleEngine(operation=operation, plugins={}, bus=bus, rules=[])

    bus.publish(
        PluginEvent(
            event_type=EventType.TTP_OBSERVED,
            plugin_id="sensor-real",
            surface="network",
            operation_id=operation.id,
            payload={"ttp_id": "T1499"},
        )
    )

    assert operation.status == OperationStatus.CLOSED
