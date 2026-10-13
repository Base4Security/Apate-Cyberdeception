"""Panel "Canarytokens (Thinkst)" en el detalle de operación --
segunda de la tanda de tareas para ampliar el ecosistema de
herramientas orquestables. Ver docstring de
`apate.plugins.canarytoken_plugin` para el diseño completo."""

from __future__ import annotations

import json
from unittest.mock import patch

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.plugins.canarytoken_client import CanarytokenCreated, CanarytokenHit
from apate.plugins.exceptions import CanarytokenAPIError


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación con Canarytokens"),
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def _unconfigured_binding(plugin_id="canarytoken-1"):
    return PluginBinding(plugin_id=plugin_id, plugin_kind="canarytoken", surface="data")


def _configured_binding(plugin_id="canarytoken-1", **config_overrides):
    config = {"base_url": "http://localhost:8082/root", "token_type": "dns", "memo": "m", "email": "soc@example.com"}
    config.update(config_overrides)
    return PluginBinding(plugin_id=plugin_id, plugin_kind="canarytoken", surface="data", config=config)


def _deployed_binding(plugin_id="canarytoken-1"):
    return _configured_binding(plugin_id, token="tok-1", auth_token="secret-auth-abc123", token_url="http://x/y", hostname="tok-1.local")


_CREATED = CanarytokenCreated(token="tok-1", auth_token="secret-auth-abc123", token_url="http://x/y", hostname="tok-1.local")


# -- Panel: presente, estados, nunca expone auth_token -----------------------


def test_panel_shows_unconfigured_state(client, app):
    operation = _operation()
    operation.plugins.append(_unconfigured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "Canarytokens (Thinkst)" in text
    assert "sin configurar" in text


def test_panel_shows_configured_but_not_deployed_state(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "preparado" in text
    assert "Crear token" in text


def test_panel_shows_deployed_state_with_token_but_never_auth_token(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    assert "desplegado" in text
    assert "tok-1" in text
    assert "tok-1.local" in text
    assert "secret-auth-abc123" not in text
    assert "auth_token" not in text.lower() or "el secreto de administraci" in text.lower()


def test_panel_absent_when_no_canarytoken_binding(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    # Se comprueba la ausencia del PANEL, no del nombre: desde que el
    # selector de tipo muestra cada capacidad por su nombre de funcion,
    # "Canarytokens (Thinkst)" aparece siempre como opcion, haya binding o no.
    assert "Migas &middot; Canarytokens (Thinkst)" not in text


# -- Configurar (POST) --------------------------------------------------------


def test_configure_seeds_config(client, app):
    operation = _operation()
    operation.plugins.append(_unconfigured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/configure",
        data={"base_url": "http://x/root", "token_type": "dns", "memo": "nota", "email": "a@b.com", "ttp_id": "T1590.002"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["base_url"] == "http://x/root"
    assert binding.config["token_type"] == "dns"
    assert binding.config["memo"] == "nota"
    assert binding.config["email"] == "a@b.com"
    assert binding.config["ttp_id"] == "T1590.002"


def test_configure_requires_all_fields_with_clear_message(client, app):
    operation = _operation()
    operation.plugins.append(_unconfigured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/configure",
        data={"base_url": "", "token_type": "", "memo": "", "email": ""},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert "URL base" in response.data.decode()


def test_configure_blocked_while_deployed(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/configure",
        data={"base_url": "http://y", "token_type": "dns", "memo": "m2", "email": "b@b.com"},
        follow_redirects=True,
    )

    assert b"flash-error" in response.data
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["base_url"] == "http://localhost:8082/root"  # sin cambios


# -- Deploy -------------------------------------------------------------------


def test_deploy_creates_token_and_persists_identity(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        response = client.post(
            f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/deploy", follow_redirects=False
        )

    assert response.status_code == 302
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["token"] == "tok-1"
    assert binding.config["auth_token"] == "secret-auth-abc123"
    raw = (app.config["APATE_DATA_DIR"] / "operations" / f"{operation.id}.json").read_text(encoding="utf-8")
    assert "secret-auth-abc123" not in raw


def test_deploy_flashes_error_on_api_failure_without_partial_state(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.canarytoken_plugin.create_token", side_effect=CanarytokenAPIError("no se pudo crear")):
        response = client.post(
            f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/deploy", follow_redirects=True
        )

    assert b"flash-error" in response.data
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert "token" not in binding.config


def test_deploy_flashes_error_when_not_configured(client, app):
    operation = _operation()
    operation.plugins.append(_unconfigured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/deploy", follow_redirects=True
    )

    assert b"flash-error" in response.data


def test_deploy_wrong_kind_returns_400(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(f"/operations/{operation.id}/plugins/mock-1/canarytoken/deploy")

    assert response.status_code == 400


# -- Rotate ---------------------------------------------------------------


def test_rotate_flashes_success_without_state_change(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/rotate", follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" not in response.data
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["token"] == "tok-1"  # sin cambios: no hay rotación real


def test_rotate_before_deploy_flashes_error(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/rotate", follow_redirects=True
    )

    assert b"flash-error" in response.data


# -- Retire -----------------------------------------------------------------


def test_retire_deletes_and_clears_config(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.canarytoken_plugin.delete_token") as mock_delete:
        response = client.post(
            f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/retire", follow_redirects=False
        )

    assert response.status_code == 302
    mock_delete.assert_called_once()
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert "token" not in binding.config
    assert "auth_token" not in binding.config
    # La configuración de creación sobrevive (se puede volver a desplegar).
    assert binding.config["base_url"] == "http://localhost:8082/root"


def test_retire_api_failure_keeps_identity(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.canarytoken_plugin.delete_token", side_effect=CanarytokenAPIError("fallo")):
        response = client.post(
            f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/retire", follow_redirects=True
        )

    assert b"flash-error" in response.data
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["token"] == "tok-1"


# -- Check hits ---------------------------------------------------------------


def test_check_hits_publishes_to_telemetry_and_persists_cursor(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    hit = CanarytokenHit(time_of_hit=200.0, source_ip="203.0.113.5", input_channel="DNS", token_type="dns", is_tor_relay=False, useragent="")
    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[hit]):
        response = client.post(
            f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/check-hits", follow_redirects=False
        )

    assert response.status_code == 302
    events = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert len(events) == 1
    assert events[0].payload["source_ip"] == "203.0.113.5"
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["last_hit_time"] == 200.0


def test_check_hits_second_call_does_not_duplicate_already_seen_hit(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    hit = CanarytokenHit(time_of_hit=200.0, source_ip="203.0.113.5", input_channel="DNS", token_type="dns", is_tor_relay=False, useragent="")
    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[hit]):
        client.post(f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/check-hits")
        client.post(f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/check-hits")

    events = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert len(events) == 1


def test_check_hits_never_persists_or_shows_auth_token_in_response(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[]):
        response = client.post(
            f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/check-hits", follow_redirects=True
        )

    assert "secret-auth-abc123" not in response.data.decode()


def test_auth_token_heredado_en_claro_se_migra_al_siguiente_guardado(client, app):
    operation = _operation()
    operation.plugins.append(_deployed_binding())
    repository = app.config["OPERATION_REPOSITORY"]
    repository.save(operation)
    path = app.config["APATE_DATA_DIR"] / "operations" / f"{operation.id}.json"
    legacy = json.loads(path.read_text(encoding="utf-8"))
    legacy["plugins"][0]["config"]["auth_token"] = "secret-auth-abc123"
    path.write_text(json.dumps(legacy), encoding="utf-8")

    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[]):
        response = client.post(
            f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/check-hits",
            follow_redirects=True,
        )

    raw = path.read_text(encoding="utf-8")
    assert response.status_code == 200
    assert "secret-auth-abc123" not in response.get_data(as_text=True)
    assert "apate-fernet:v1:" not in response.get_data(as_text=True)
    assert "secret-auth-abc123" not in raw
    assert "apate-fernet:v1:" in raw


def test_check_hits_before_deploy_flashes_error(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(
        f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/check-hits", follow_redirects=True
    )

    assert b"flash-error" in response.data


# -- "Vincular capacidad": seeding inline (mismo patrón que dolost/buda/honeytoken) --


def _create_operation(client):
    form = dict(
        name="Operación de prueba",
        adversary_name="APT ficticio",
        adversary_motivation="espionaje",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046"],
        target_assets="ERP",
        environment="isolated",
        narrative_name="Narrativa base",
        narrative_description="desc",
    )
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_add_plugin_binding_seeds_canarytoken_config_inline(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "canarytoken-1",
            "plugin_kind": "canarytoken",
            "surface": "data",
            "canarytoken_base_url": "http://x/root",
            "canarytoken_token_type": "aws_keys",
            "canarytoken_memo": "Miga en el escritorio",
            "canarytoken_email": "soc@example.com",
            "canarytoken_ttp_id": "T1590.002",
        },
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    binding = operation.plugins[0]
    assert binding.config["base_url"] == "http://x/root"
    assert binding.config["token_type"] == "aws_keys"
    assert binding.config["email"] == "soc@example.com"
    assert binding.config["ttp_id"] == "T1590.002"


def test_add_plugin_binding_without_canarytoken_fields_creates_unconfigured_binding(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "canarytoken-1", "plugin_kind": "canarytoken", "surface": "data"},
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].config == {}


# -- Auditoría (Fase 1 post-BlackHat) -----------------------------------------


def test_deploy_logs_operator_action(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.canarytoken_plugin.create_token", return_value=_CREATED):
        client.post(f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/deploy")

    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert any(a.action == "canarytoken_deploy" and a.outcome == "success" for a in actions)


# -- Correlación gratuita con la infraestructura existente -------------------


def test_hit_with_ttp_id_shows_up_in_existing_ttp_report(client, app):
    from apate.reporting import generate_report

    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1590.002"]))
    operation.plugins.append(_deployed_binding())
    operation.plugins[0].config["ttp_id"] = "T1590.002"
    app.config["OPERATION_REPOSITORY"].save(operation)

    hit = CanarytokenHit(time_of_hit=1.0, source_ip="203.0.113.9", input_channel="DNS", token_type="dns", is_tor_relay=False, useragent="")
    with patch("apate.plugins.canarytoken_plugin.fetch_hits", return_value=[hit]):
        client.post(f"/operations/{operation.id}/plugins/canarytoken-1/canarytoken/check-hits")

    saved = app.config["OPERATION_REPOSITORY"].get(operation.id)
    report = generate_report(saved, app.config["TELEMETRY_COLLECTOR"])
    assert "T1590.002" in report.matched_ttps
