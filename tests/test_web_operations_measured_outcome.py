"""Tests de integracion web para Fase 2 post-BlackHat (ver
docs/roadmap.md): cerrar el lazo entre lo planificado
(DeceptionEffect.success_metric, M10) y lo efectivamente medido.
Mismo patron que tests/test_web_operations_m10.py (helper
_create_operation posteando al formulario real, sin mockear nada)."""

from apate.plugins.base import EventType, PluginEvent


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba Fase 2",
        adversary_name="APT ficticio",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def _bind_plugin(client, operation_id, **overrides):
    form = dict(plugin_id="honeytoken-1", surface="data", success_metric="Alerta en menos de 5 minutos")
    form.update(overrides)
    response = client.post(f"/operations/{operation_id}/plugins", data=form, follow_redirects=False)
    assert response.status_code == 302


def test_record_measured_outcome_persists_with_session_operator(client, app):
    operation_id = _create_operation(client)
    _bind_plugin(client, operation_id)
    client.post("/operator", data={"operator": "Federico"})

    response = client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "Alerta disparada a los 3 minutos"},
        follow_redirects=False,
    )
    assert response.status_code == 302

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    effect = operation.plugins[0].effect
    assert effect.measured_outcome == "Alerta disparada a los 3 minutos"
    assert effect.measured_by == "Federico"
    assert effect.measured_at is not None


def test_record_measured_outcome_without_session_operator_uses_sin_especificar(client, app):
    operation_id = _create_operation(client)
    _bind_plugin(client, operation_id)

    client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "Se observo el acceso"},
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].effect.measured_by == "sin especificar"


def test_record_measured_outcome_rejects_empty_value(client, app):
    operation_id = _create_operation(client)
    _bind_plugin(client, operation_id)

    response = client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "   "},
        follow_redirects=True,
    )

    assert b"no puede estar vac" in response.data
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].effect.measured_outcome == ""


def test_record_measured_outcome_can_be_updated(client, app):
    operation_id = _create_operation(client)
    _bind_plugin(client, operation_id)

    client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "primera medicion"},
    )
    client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "medicion actualizada"},
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].effect.measured_outcome == "medicion actualizada"


def test_record_measured_outcome_404_for_unknown_plugin_id(client):
    operation_id = _create_operation(client)

    response = client.post(f"/operations/{operation_id}/plugins/no-existe/effect/measure", data={"measured_outcome": "x"})

    assert response.status_code == 404


def test_record_measured_outcome_does_not_create_operator_action_entry(client, app):
    # Decision de diseno documentada: es una edicion de campo del
    # dominio (como success_metric en si), no una accion de sistema
    # contra un plugin/decoy real -- no debe aparecer en el log de
    # auditoria de la Fase 1.
    operation_id = _create_operation(client)
    _bind_plugin(client, operation_id)

    client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "se observo"},
    )

    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation_id)
    assert actions == []


def test_detail_page_shows_registrar_before_measuring_and_actualizar_after(client):
    operation_id = _create_operation(client)
    _bind_plugin(client, operation_id)

    before = client.get(f"/operations/{operation_id}")
    assert b"Registrar" in before.data
    assert b"Actualizar" not in before.data

    client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "se observo el acceso"},
    )

    after = client.get(f"/operations/{operation_id}")
    assert b"se observo el acceso" in after.data or b"se observ\xc3\xb3 el acceso" in after.data
    assert b"Actualizar" in after.data


def test_measured_outcome_links_only_its_plugin_evidence(client, app):
    operation_id = _create_operation(client)
    _bind_plugin(client, operation_id)
    collector = app.config["TELEMETRY_COLLECTOR"]
    event = PluginEvent(event_type=EventType.INTERACTION, operation_id=operation_id, plugin_id="honeytoken-1", surface="data", payload={"kind": "access"})
    alien = PluginEvent(event_type=EventType.INTERACTION, operation_id=operation_id, plugin_id="other", surface="data", payload={"kind": "access"})
    collector.handle_event(event)
    collector.handle_event(alien)
    records = collector.list_events(operation_id)
    own_id, alien_id = records[0].id, records[1].id

    rejected = client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "acceso observado", "evidence_event_ids": alien_id},
    )
    assert rejected.status_code == 400

    accepted = client.post(
        f"/operations/{operation_id}/plugins/honeytoken-1/effect/measure",
        data={"measured_outcome": "acceso observado", "evidence_event_ids": own_id},
    )
    assert accepted.status_code == 302
    assert app.config["OPERATION_REPOSITORY"].get(operation_id).plugins[0].effect.evidence_event_ids == [own_id]
    page = client.get(f"/operations/{operation_id}")
    assert f"event_id={own_id}".encode() in page.data
