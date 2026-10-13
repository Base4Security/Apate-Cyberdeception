"""Estado en vivo del listado de operaciones (referencia declarada:
CounterCraft, "campaign cards" que muestran que esta corriendo sin
abrir cada campana). Ver docstring de `_bulk_deployment_status()`
(apate.web.blueprints.operations) para el diseno completo: una sola
consulta a Docker/BUDA por lote, nunca durante el render sincronico de
`list_operations()`, y "desconocido" en vez de "abajo" cuando el
proveedor no responde.

Mismo patron de fixtures que `test_web_operations_panels.py`
(`mounted_app`/`mounted_client` con `SQLALCHEMY_DATABASE_URI` real
para ejercitar BUDA de verdad; Docker real no esta disponible en este
entorno, asi que el caso "docker_available=False" se ejercita sin
mockear nada)."""

import datetime

import pytest

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.plugins import dolost_plugin as dolost_plugin_module
from apate.web import create_app
from apate.web.blueprints import operations as operations_module


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-live-status-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operación de prueba",
        adversary_profile=AdversaryProfile(name="APT ficticio", motivation="espionaje", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _make_buda_narrative(app, **overrides) -> int:
    from BUDA.app import db as buda_db
    from BUDA.models import Narrative as BudaNarrative

    defaults = dict(
        title="t",
        objective="o",
        attacker_profile="a",
        deception_activities="d",
        end_date=datetime.date.today(),
        is_running=False,
        percentage_of_similarity=100,
    )
    defaults.update(overrides)
    with app.app_context():
        narrative = BudaNarrative(**defaults)
        buda_db.session.add(narrative)
        buda_db.session.commit()
        return narrative.id


# -- _bulk_deployment_status(): Docker ----------------------------------------


def test_docker_unavailable_marks_decoys_unknown_not_down(mounted_app):
    # Docker real no esta disponible en este entorno -- degradacion sin
    # mockear nada, mismo caso que ya cubre test_web_operations_panels.py
    # para el panel de una sola operacion.
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))

    with mounted_app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=True)

    assert status[op.id]["docker_available"] is False
    assert status[op.id]["decoys"] == {"up": 0, "down": 0, "unknown": 1}


def test_docker_available_decoy_up(mounted_app, monkeypatch):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager,
        "get_containers",
        lambda all=True: [{"Names": ["/DolosT-ssh1"], "Status": "Up 2 minutes"}],
    )

    with mounted_app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=True)

    assert status[op.id]["docker_available"] is True
    assert status[op.id]["decoys"] == {"up": 1, "down": 0, "unknown": 0}


def test_docker_available_but_decoy_container_missing_is_down_not_unknown(mounted_app, monkeypatch):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    monkeypatch.setattr(dolost_plugin_module._docker_manager, "get_containers", lambda all=True: [])

    with mounted_app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=True)

    assert status[op.id]["docker_available"] is True
    assert status[op.id]["decoys"] == {"up": 0, "down": 1, "unknown": 0}


def test_docker_not_queried_when_external_tools_not_mounted(mounted_app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager,
        "get_containers",
        lambda all=True: calls.append(True) or [],
    )
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))

    with mounted_app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=False)

    assert calls == []
    assert status[op.id]["docker_available"] is False
    assert status[op.id]["decoys"]["unknown"] == 1


def test_multiple_operations_share_a_single_docker_call(mounted_app, monkeypatch):
    calls = []
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager,
        "get_containers",
        lambda all=True: calls.append(True) or [{"Names": ["/DolosT-ssh1"], "Status": "Up 1 minute"}],
    )
    op1 = _make_operation(name="Op 1")
    op1.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    op2 = _make_operation(name="Op 2")
    op2.bind_plugin(PluginBinding(plugin_id="dolost-2", surface="network", config={"decoys": [{"Hostname": "ssh2"}]}))

    with mounted_app.app_context():
        operations_module._bulk_deployment_status([op1, op2], external_tools_mounted=True)

    assert len(calls) == 1, "un decoy por operacion no deberia pagar una consulta a Docker por operacion"


# -- _bulk_deployment_status(): BUDA -------------------------------------------


def test_buda_narrative_running(mounted_app):
    narrative_id = _make_buda_narrative(mounted_app, is_running=True)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))

    with mounted_app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=True)

    assert status[op.id]["buda_available"] is True
    assert status[op.id]["narratives"] == {"running": 1, "configured": 1}


def test_buda_narrative_not_running(mounted_app):
    narrative_id = _make_buda_narrative(mounted_app, is_running=False)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))

    with mounted_app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=True)

    assert status[op.id]["narratives"] == {"running": 0, "configured": 1}


def test_buda_binding_without_narrative_id_not_counted():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={}))

    app = create_app({"TESTING": True, "APATE_MOUNT_EXTERNAL_TOOLS": False})
    with app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=False)

    assert status[op.id]["narratives"] == {"running": 0, "configured": 0}
    assert status[op.id]["has_any_capability"] is False


def test_buda_not_mounted_marks_narrative_unknown_but_still_counts_configured():
    # Sin APATE_MOUNT_EXTERNAL_TOOLS, no hay forma de saber si esta
    # corriendo -- pero "configurada" es un dato local (config del
    # binding), no depende de BUDA para saberse.
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": 42}))

    app = create_app({"TESTING": True, "APATE_MOUNT_EXTERNAL_TOOLS": False})
    with app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=False)

    assert status[op.id]["buda_available"] is False
    assert status[op.id]["narratives"] == {"running": 0, "configured": 1}
    assert status[op.id]["has_any_capability"] is True


# -- _bulk_deployment_status(): honeytokens ------------------------------------


def test_honeytoken_deployed_counts(mounted_app, tmp_path):
    directory = tmp_path / "honeytokens"
    directory.mkdir()
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            plugin_kind="honeytoken",
            surface="data",
            config={"directory": str(directory), "filenames": ["creds.txt"]},
        )
    )

    with mounted_app.app_context():
        # deploy() real para crear el archivo -- misma via que ya usan
        # los tests de HoneytokenPlugin, no se fabrica el estado a mano.
        from apate.plugins import EventBus, HoneytokenPlugin

        plugin = HoneytokenPlugin.from_binding(op.plugins[0], operation_id=op.id, bus=EventBus())
        plugin.deploy()

        status = operations_module._bulk_deployment_status([op], external_tools_mounted=True)

    assert status[op.id]["honeytokens"] == {"deployed": 1, "configured": 1}
    assert status[op.id]["has_any_capability"] is True


def test_operation_without_any_capability_configured():
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))

    app = create_app({"TESTING": True, "APATE_MOUNT_EXTERNAL_TOOLS": False})
    with app.app_context():
        status = operations_module._bulk_deployment_status([op], external_tools_mounted=False)

    assert status[op.id]["has_any_capability"] is False
    assert status[op.id]["decoys"] == {"up": 0, "down": 0, "unknown": 0}
    assert status[op.id]["narratives"] == {"running": 0, "configured": 0}
    assert status[op.id]["honeytokens"] == {"deployed": 0, "configured": 0}


# -- Ruta /operations/deployment-status ----------------------------------------


def test_deployment_status_route_returns_json_for_known_ids(client, app):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(op)

    response = client.get(f"/operations/deployment-status?ids={op.id}")

    assert response.status_code == 200
    data = response.get_json()
    assert list(data.keys()) == [op.id]


def test_deployment_status_route_ignores_unknown_ids(client, app):
    op = _make_operation()
    app.config["OPERATION_REPOSITORY"].save(op)

    response = client.get(f"/operations/deployment-status?ids={op.id},no-existe")

    assert response.status_code == 200
    assert list(response.get_json().keys()) == [op.id]


def test_deployment_status_route_empty_ids_returns_empty_object(client):
    response = client.get("/operations/deployment-status?ids=")

    assert response.status_code == 200
    assert response.get_json() == {}


def test_deployment_status_route_no_ids_param_returns_empty_object(client):
    response = client.get("/operations/deployment-status")

    assert response.status_code == 200
    assert response.get_json() == {}


# -- operations/list.html: seccion "Estado en vivo" ----------------------------


def _create_operation(client, **overrides):
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
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_live_status_section_present(client):
    _create_operation(client)

    text = client.get("/operations/").data.decode()

    assert 'id="operations-live-status-title"' in text
    assert "operations.deployment_status" not in text  # nunca se filtra el nombre interno de la vista


def test_only_active_and_compromised_operations_get_live_cards(client, app):
    planning_id = _create_operation(client, name="Planning")
    active_id = _create_operation(client, name="Active")
    compromised_id = _create_operation(client, name="Compromised")
    closed_id = _create_operation(client, name="Closed")

    repo = app.config["OPERATION_REPOSITORY"]
    active = repo.get(active_id)
    active.mark_active()
    repo.save(active)
    compromised = repo.get(compromised_id)
    compromised.mark_active()
    compromised.mark_compromised()
    repo.save(compromised)
    closed = repo.get(closed_id)
    closed.mark_active()
    closed.close()
    repo.save(closed)

    text = client.get("/operations/").data.decode()

    assert f'data-operation-id="{active_id}"' in text
    assert f'data-operation-id="{compromised_id}"' in text
    assert f'data-operation-id="{planning_id}"' not in text
    assert f'data-operation-id="{closed_id}"' not in text


def test_empty_state_when_no_live_operations(client):
    _create_operation(client)  # queda en PLANNING

    text = client.get("/operations/").data.decode()

    assert "Ninguna operaci" in text
    assert 'id="operations-live-cards"' not in text


def test_fetch_markers_present_when_live_operations_exist(client, app):
    operation_id = _create_operation(client)
    op = app.config["OPERATION_REPOSITORY"].get(operation_id)
    op.mark_active()
    app.config["OPERATION_REPOSITORY"].save(op)

    text = client.get("/operations/").data.decode()

    assert 'id="operations-live-cards"' in text
    assert f'data-operation-id="{operation_id}"' in text
    assert "/operations/deployment-status" in text
    assert "AbortController" in text


def test_existing_search_filter_sort_markup_untouched(client, app):
    """No-regresion: el buscador/filtro/orden de la tabla completa
    (post-BlackHat, ya andaba bien) sigue presente tal cual."""

    _create_operation(client)

    text = client.get("/operations/").data.decode()

    assert 'id="operations-search"' in text
    assert 'id="operations-status-filter"' in text
    assert 'id="operations-table"' in text
    assert 'data-sort-key="name"' in text
