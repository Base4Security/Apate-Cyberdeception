"""Tests de integracion web para Fase 3 post-BlackHat (ver
docs/roadmap.md): "perfil de adversario vivo" -- incorporar TTPs
observadas-no-esperadas (telemetria) a AdversaryProfile.expected_ttps
de una operacion en curso, con aceptacion explicita del operador.

Mismo patron que tests/test_reporting_generator.py para generar
telemetria real (EventBus + MockHoneypotPlugin.simulate_access(), sin
mockear nada) y tests/test_web_operations_tabs.py para las
aserciones de redirect-con-fragmento."""

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.plugins import EventBus, MockHoneypotPlugin


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba Fase 3",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _save(app, operation: Operation) -> Operation:
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def _observe_ttp(app, operation: Operation, ttp_id: str) -> None:
    bus = EventBus()
    app.config["TELEMETRY_COLLECTOR"].attach(bus)
    mock = MockHoneypotPlugin(plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus)
    mock.deploy()
    mock.simulate_access(ttp_id=ttp_id)


# -- Vista de detalle: seccion de sugerencias --------------------------------


def test_planning_operation_shows_no_live_profile_section(client, app):
    operation = _make_operation()
    _save(app, operation)

    response = client.get(f"/operations/{operation.id}")

    assert b"perfil de adversario vivo" not in response.data.lower()


def test_active_operation_without_unexpected_ttps_shows_empty_state(client, app):
    operation = _make_operation()
    operation.mark_active()
    _save(app, operation)

    response = client.get(f"/operations/{operation.id}")

    assert b"perfil de adversario vivo" in response.data.lower()
    assert b'Sin <abbr title="T&aacute;cticas, t&eacute;cnicas y procedimientos">TTP</abbr>s observadas fuera del perfil todav&iacute;a' in response.data


def test_active_operation_shows_suggested_ttp_with_technique_name(client, app):
    operation = _make_operation(adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1046"]))
    operation.mark_active()
    _save(app, operation)
    _observe_ttp(app, operation, "T1595.002")  # no esperada

    response = client.get(f"/operations/{operation.id}")

    assert b'value="T1595.002"' in response.data
    assert b"T1595.002" in response.data


def test_compromised_operation_also_shows_suggestions(client, app):
    operation = _make_operation()
    operation.mark_active()
    operation.mark_compromised()
    _save(app, operation)
    _observe_ttp(app, operation, "T1595.002")

    response = client.get(f"/operations/{operation.id}")

    assert b'value="T1595.002"' in response.data


def test_closed_operation_does_not_show_live_profile_section(client, app):
    operation = _make_operation()
    operation.mark_active()
    operation.close()
    _save(app, operation)

    response = client.get(f"/operations/{operation.id}")

    assert b"perfil de adversario vivo" not in response.data.lower()


# -- POST /adversary-profile/incorporate-ttps --------------------------------


def test_incorporate_suggested_ttps_adds_to_profile(client, app):
    operation = _make_operation(adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1046"]))
    operation.mark_active()
    _save(app, operation)
    _observe_ttp(app, operation, "T1595.002")

    response = client.post(
        f"/operations/{operation.id}/adversary-profile/incorporate-ttps",
        data={"incorporate_ttps": ["T1595.002"]},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{operation.id}#tab-profile")

    reloaded = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert reloaded.adversary_profile.expected_ttps == ["T1046", "T1595.002"]


def test_incorporate_multiple_ttps_dedupes_against_existing_profile(client, app):
    operation = _make_operation(adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1046"]))
    operation.mark_active()
    _save(app, operation)

    client.post(
        f"/operations/{operation.id}/adversary-profile/incorporate-ttps",
        data={"incorporate_ttps": ["T1046", "T1595.002"]},
    )

    reloaded = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert reloaded.adversary_profile.expected_ttps == ["T1046", "T1595.002"]


def test_incorporate_suggested_ttps_rejected_for_planning_operation(client, app):
    operation = _make_operation()
    _save(app, operation)

    response = client.post(
        f"/operations/{operation.id}/adversary-profile/incorporate-ttps",
        data={"incorporate_ttps": ["T1595.002"]},
        follow_redirects=True,
    )

    assert "activa o comprometida".encode() in response.data
    reloaded = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert reloaded.adversary_profile.expected_ttps == ["T1046"]


def test_incorporate_suggested_ttps_rejected_for_closed_operation(client, app):
    operation = _make_operation()
    operation.mark_active()
    operation.close()
    _save(app, operation)

    response = client.post(
        f"/operations/{operation.id}/adversary-profile/incorporate-ttps",
        data={"incorporate_ttps": ["T1595.002"]},
        follow_redirects=True,
    )

    assert "activa o comprometida".encode() in response.data
    reloaded = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert reloaded.adversary_profile.expected_ttps == ["T1046"]


def test_incorporate_suggested_ttps_without_selection_flashes_error(client, app):
    operation = _make_operation()
    operation.mark_active()
    _save(app, operation)

    response = client.post(
        f"/operations/{operation.id}/adversary-profile/incorporate-ttps",
        data={},
        follow_redirects=True,
    )

    assert "ninguna TTP".encode() in response.data
    reloaded = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert reloaded.adversary_profile.expected_ttps == ["T1046"]


def test_incorporate_suggested_ttps_404_for_unknown_operation(client):
    response = client.post(
        "/operations/no-existe/adversary-profile/incorporate-ttps",
        data={"incorporate_ttps": ["T1595.002"]},
    )
    assert response.status_code == 404


def test_incorporate_suggested_ttps_does_not_create_operator_action_entry(client, app):
    # Decision de diseno documentada (misma que measured_outcome en la
    # Fase 2): es una edicion de campo del dominio, no una accion de
    # sistema contra un plugin/decoy real -- no debe aparecer en el
    # log de auditoria de la Fase 1.
    operation = _make_operation()
    operation.mark_active()
    _save(app, operation)

    client.post(
        f"/operations/{operation.id}/adversary-profile/incorporate-ttps",
        data={"incorporate_ttps": ["T1595.002"]},
    )

    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert actions == []
