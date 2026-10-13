"""Panel "OpenCanary (Thinkst)" en el detalle de operación -- tercera y
última de la tanda de tareas para ampliar el ecosistema de herramientas
orquestables. Ver docstring de `apate.plugins.opencanary_plugin` para
el diseño completo."""

from __future__ import annotations

from unittest.mock import patch

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.plugins.exceptions import OpenCanaryError
from apate.plugins.opencanary_client import OpenCanaryHit


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación con OpenCanary"),
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def _unconfigured_binding(plugin_id="opencanary-1"):
    return PluginBinding(plugin_id=plugin_id, plugin_kind="opencanary", surface="network")


def _configured_binding(plugin_id="opencanary-1", **config_overrides):
    config = {"services": {"ssh": {"enabled": True, "port": 2222}}, "network_mode": "bridge"}
    config.update(config_overrides)
    return PluginBinding(plugin_id=plugin_id, plugin_kind="opencanary", surface="network", config=config)


_NOT_DEPLOYED_STATUS = {"docker_available": True, "status": "no desplegado", "up": False}
_RUNNING_STATUS = {"docker_available": True, "status": "running", "up": True}
_DOCKER_UNAVAILABLE_STATUS = {"docker_available": False, "status": None, "up": None}

_STATUS_PATCH = "apate.web.blueprints.operations._opencanary_container_status"


# -- Panel: presente, estados, nunca rompe sin Docker -----------------------


def test_panel_shows_unconfigured_state(client, app):
    operation = _operation()
    operation.plugins.append(_unconfigured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(_STATUS_PATCH, return_value=_NOT_DEPLOYED_STATUS):
        text = client.get(f"/operations/{operation.id}").data.decode()

    assert "OpenCanary (Thinkst)" in text
    assert "ninguno configurado" in text


def test_panel_shows_configured_but_not_deployed_state(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(_STATUS_PATCH, return_value=_NOT_DEPLOYED_STATUS):
        text = client.get(f"/operations/{operation.id}").data.decode()

    assert "ssh:2222" in text
    assert "Desplegar</button>" in text


def test_panel_shows_running_container_offers_lifecycle_actions(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(_STATUS_PATCH, return_value=_RUNNING_STATUS):
        text = client.get(f"/operations/{operation.id}").data.decode()

    assert "running" in text
    assert "Consultar actividad" in text
    assert "dot-up" in text


def test_panel_docker_unavailable_shows_unknown_not_down(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(_STATUS_PATCH, return_value=_DOCKER_UNAVAILABLE_STATUS):
        text = client.get(f"/operations/{operation.id}").data.decode()

    assert "Docker no disponible" in text
    assert "dot-unknown" in text
    assert "dot-down" not in text


def test_panel_absent_when_no_opencanary_binding(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    text = client.get(f"/operations/{operation.id}").data.decode()

    # Se comprueba la ausencia del PANEL, no del nombre: desde que el
    # selector de tipo muestra cada capacidad por su nombre de funcion,
    # "OpenCanary (Thinkst)" aparece siempre como opcion, haya binding o no.
    assert "Decoys &middot; OpenCanary (Thinkst)" not in text


# -- Configurar (POST) --------------------------------------------------------


def test_configure_seeds_config(client, app):
    operation = _operation()
    operation.plugins.append(_unconfigured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(_STATUS_PATCH, return_value=_NOT_DEPLOYED_STATUS):
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/configure",
            data={"services": "ssh:2222\nftp:2121", "network_mode": "bridge", "ttp_id": "T1110.001"},
            follow_redirects=False,
        )

    assert response.status_code == 302
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["services"] == {
        "ssh": {"enabled": True, "port": 2222},
        "ftp": {"enabled": True, "port": 2121},
    }
    assert binding.config["network_mode"] == "bridge"
    assert binding.config["ttp_id"] == "T1110.001"


def test_configure_invalid_network_mode_falls_back_to_bridge(client, app):
    operation = _operation()
    operation.plugins.append(_unconfigured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(_STATUS_PATCH, return_value=_NOT_DEPLOYED_STATUS):
        client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/configure",
            data={"services": "ssh:22", "network_mode": "not-a-real-mode"},
        )

    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["network_mode"] == "bridge"


def test_configure_blocked_while_deployed(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(_STATUS_PATCH, return_value=_RUNNING_STATUS):
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/configure",
            data={"services": "ssh:9999"},
            follow_redirects=True,
        )

    assert b"flash-error" in response.data
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["services"] == {"ssh": {"enabled": True, "port": 2222}}  # sin cambios


# -- Deploy -------------------------------------------------------------------


def test_deploy_calls_plugin_and_persists_node_id(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="container-id"):
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/deploy", follow_redirects=False
        )

    assert response.status_code == 302
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["node_id"] == "opencanary-1"
    assert "last_checked_at" in binding.config


def test_deploy_flashes_error_on_docker_failure(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(
        "apate.plugins.opencanary_plugin.deploy_container", side_effect=OpenCanaryError("puerto ya ocupado")
    ):
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/deploy", follow_redirects=True
        )

    assert b"flash-error" in response.data
    assert "puerto ya ocupado" in response.data.decode()


def test_deploy_wrong_kind_returns_400(client, app):
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.post(f"/operations/{operation.id}/plugins/mock-1/opencanary/deploy")

    assert response.status_code == 400


# -- Rotate -------------------------------------------------------------------


def test_rotate_calls_restart_container(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.opencanary_plugin.restart_container") as mock_restart:
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/rotate", follow_redirects=True
        )

    assert response.status_code == 200
    assert b"flash-error" not in response.data
    mock_restart.assert_called_once_with(name="OpenCanary-opencanary-1")


def test_rotate_docker_failure_flashes_error(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.opencanary_plugin.restart_container", side_effect=OpenCanaryError("no responde")):
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/rotate", follow_redirects=True
        )

    assert b"flash-error" in response.data


# -- Retire -----------------------------------------------------------------


def test_retire_calls_stop_and_remove_and_clears_cursor(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding(last_checked_at=123.0))
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.opencanary_plugin.stop_and_remove_container") as mock_stop:
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/retire", follow_redirects=False
        )

    assert response.status_code == 302
    mock_stop.assert_called_once_with(name="OpenCanary-opencanary-1")
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert "last_checked_at" not in binding.config
    # La configuración de servicios sobrevive (se puede volver a desplegar).
    assert binding.config["services"] == {"ssh": {"enabled": True, "port": 2222}}


def test_retire_docker_failure_flashes_error(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch(
        "apate.plugins.opencanary_plugin.stop_and_remove_container", side_effect=OpenCanaryError("fallo")
    ):
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/retire", follow_redirects=True
        )

    assert b"flash-error" in response.data


# -- Check activity ------------------------------------------------------------


def test_check_activity_publishes_to_telemetry_and_persists_cursor(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    hit = OpenCanaryHit(
        logtype=4002,
        local_time="2024-01-01",
        src_host="203.0.113.5",
        src_port=51390,
        dst_host=None,
        dst_port=2222,
        node_id="opencanary-1",
        logdata={"USERNAME": "fakeuser"},
    )
    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[hit]), patch(
        "apate.plugins.opencanary_plugin.time"
    ) as mock_time:
        mock_time.time.return_value = 999.0
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/check-activity", follow_redirects=False
        )

    assert response.status_code == 302
    events = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert len(events) == 1
    assert events[0].payload["source_ip"] == "203.0.113.5"
    binding = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0]
    assert binding.config["last_checked_at"] == 999.0


def test_check_activity_docker_failure_flashes_error(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.opencanary_plugin.fetch_logs", side_effect=OpenCanaryError("no se pudo leer")):
        response = client.post(
            f"/operations/{operation.id}/plugins/opencanary-1/opencanary/check-activity", follow_redirects=True
        )

    assert b"flash-error" in response.data


def test_check_activity_never_shows_raw_logdata_secrets_unsanitized(client, app):
    """No hay ningún secreto propio de APATE en logdata (a diferencia de
    Canarytokens) -- este test confirma que el contenido SÍ se muestra
    (es la interacción observada, el propósito del honeypot), truncado
    si hace falta, no oculto."""

    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    hit = OpenCanaryHit(
        logtype=4002,
        local_time="2024-01-01",
        src_host="203.0.113.5",
        src_port=1,
        dst_host=None,
        dst_port=2222,
        node_id="opencanary-1",
        logdata={"USERNAME": "attacker123"},
    )
    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[hit]):
        client.post(f"/operations/{operation.id}/plugins/opencanary-1/opencanary/check-activity")

    events = app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    assert events[0].payload["logdata"]["USERNAME"] == "attacker123"


# -- "Vincular capacidad": seeding inline (mismo patrón que dolost/buda/canarytoken) --


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


def test_add_plugin_binding_seeds_opencanary_config_inline(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "opencanary-1",
            "plugin_kind": "opencanary",
            "surface": "network",
            "opencanary_services": "ssh:2222",
            "opencanary_network_mode": "host",
            "opencanary_ttp_id": "T1110.001",
        },
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    binding = operation.plugins[0]
    assert binding.config["services"] == {"ssh": {"enabled": True, "port": 2222}}
    assert binding.config["network_mode"] == "host"
    assert binding.config["ttp_id"] == "T1110.001"


def test_add_plugin_binding_without_opencanary_fields_creates_unconfigured_binding(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/plugins",
        data={"plugin_id": "opencanary-1", "plugin_kind": "opencanary", "surface": "network"},
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].config == {}


# -- Auditoría (Fase 1 post-BlackHat) -----------------------------------------


def test_deploy_logs_operator_action(client, app):
    operation = _operation()
    operation.plugins.append(_configured_binding())
    app.config["OPERATION_REPOSITORY"].save(operation)

    with patch("apate.plugins.opencanary_plugin.deploy_container", return_value="x"):
        client.post(f"/operations/{operation.id}/plugins/opencanary-1/opencanary/deploy")

    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert any(a.action == "opencanary_deploy" and a.outcome == "success" for a in actions)


# -- Correlación gratuita con la infraestructura existente -------------------


def test_hit_with_ttp_id_shows_up_in_existing_ttp_report(client, app):
    from apate.reporting import generate_report

    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1110.001"]))
    operation.plugins.append(_configured_binding(ttp_id="T1110.001"))
    app.config["OPERATION_REPOSITORY"].save(operation)

    hit = OpenCanaryHit(
        logtype=4002,
        local_time="x",
        src_host="203.0.113.9",
        src_port=1,
        dst_host=None,
        dst_port=22,
        node_id="opencanary-1",
        logdata={},
    )
    with patch("apate.plugins.opencanary_plugin.fetch_logs", return_value=[hit]):
        client.post(f"/operations/{operation.id}/plugins/opencanary-1/opencanary/check-activity")

    saved = app.config["OPERATION_REPOSITORY"].get(operation.id)
    report = generate_report(saved, app.config["TELEMETRY_COLLECTOR"])
    assert "T1110.001" in report.matched_ttps
