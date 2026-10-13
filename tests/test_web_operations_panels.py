"""Tests de integracion para los paneles "Decoys"/"Narrativa de
comportamiento simulado" (adaptadores de DOLOS-T/BUDA, renombrados a
funcion-first tras M14 -- ver docs/roadmap.md) anidados bajo
/operations/<id> (fase de construccion de la UI oscura unificada, sobre
la clasificacion "operacion" vs. "mecanica especifica" ya acordada).

Se mockean las mismas funciones que ya mockean test_plugins_dolost.py/
test_plugins_buda.py (deploy_collector/deploy_decoy/clean_decoy,
DockerManager, start_narrative/stop_narrative) -- sin Docker ni WinRM
reales. La base de BUDA es un sqlite temporal real (igual que
test_web_external.py): las consultas de Narrative/UserProfile del
panel BUDA no se mockean, se ejercitan contra filas reales."""

import datetime
from pathlib import Path

import pytest

from apate.core import AdversaryProfile, Narrative, Operation, OperationStatus, PluginBinding, RulesOfEngagement
from apate.plugins.exceptions import CanarytokenAPIError, OpenCanaryError
from apate.plugins import buda_plugin as buda_plugin_module
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
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-panels-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba",
        adversary_profile=AdversaryProfile(name="APT ficticio", motivation="espionaje", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _save(app, operation: Operation) -> Operation:
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


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


@pytest.fixture
def dolost_calls(monkeypatch):
    calls = {
        "deploy_collector": [],
        "deploy_decoy": [],
        "clean_decoy": [],
        "web_deploy_decoy": [],
        "web_clean_decoy": [],
        "stop": [],
        "start": [],
        "clean_container": [],
        "clean_networks": [],
    }

    monkeypatch.setattr(dolost_plugin_module, "deploy_collector", lambda: calls["deploy_collector"].append(True))
    monkeypatch.setattr(dolost_plugin_module, "deploy_decoy", lambda decoy: calls["deploy_decoy"].append(decoy))
    monkeypatch.setattr(dolost_plugin_module, "clean_decoy", lambda decoy: calls["clean_decoy"].append(decoy))
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager, "stop", lambda container_id: calls["stop"].append(container_id)
    )
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager, "start", lambda container_id: calls["start"].append(container_id)
    )
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager, "clean_container", lambda name: calls["clean_container"].append(name)
    )
    monkeypatch.setattr(
        dolost_plugin_module._docker_manager, "clean_networks", lambda: calls["clean_networks"].append(True)
    )
    # Rutas de deploy/undeploy individuales llaman directo a las
    # funciones de DOLOST.blueprints.api importadas en operations.py --
    # distintas del deploy()/retire() completo de DolosTPlugin de arriba.
    monkeypatch.setattr(operations_module, "_dolost_deploy_decoy", lambda decoy: calls["web_deploy_decoy"].append(decoy))
    monkeypatch.setattr(operations_module, "_dolost_clean_decoy", lambda decoy: calls["web_clean_decoy"].append(decoy))
    return calls


@pytest.fixture
def buda_calls(monkeypatch):
    calls = {"start_narrative": [], "stop_narrative": []}
    monkeypatch.setattr(
        buda_plugin_module,
        "start_narrative",
        lambda narrative_id: (calls["start_narrative"].append(narrative_id), {"message": "Narrative started"})[1],
    )
    monkeypatch.setattr(
        buda_plugin_module,
        "stop_narrative",
        lambda narrative_id: (calls["stop_narrative"].append(narrative_id), {"message": "Narrative stopped"})[1],
    )
    return calls


# -- Visibilidad de paneles segun _plugin_kind() -----------------------------


def test_dolost_panel_appears_for_dolost_plugin_id(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b'<h3 class="section-heading">Decoys' in response.data
    assert b"Narrativa de comportamiento simulado" not in response.data


def test_buda_panel_appears_for_buda_plugin_id(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b"Narrativa de comportamiento simulado" in response.data
    assert b'<h3 class="section-heading">Decoys' not in response.data


def test_no_panel_for_unrelated_plugin_id(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert b'<h3 class="section-heading">Decoys' not in response.data
    assert b"Narrativa de comportamiento simulado" not in response.data


def test_no_panels_shown_when_external_tools_not_mounted(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    app.config["OPERATION_REPOSITORY"].save(op)

    response = app.test_client().get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b'<h3 class="section-heading">Decoys' not in response.data


# -- Panel "Decoys" (adaptador DOLOS-T) ----------------------------------


def test_dolost_panel_lists_configured_decoys_with_unknown_status(mounted_app, mounted_client):
    # Sin Docker configurado en el entorno de tests, DockerManager.client
    # es None -- _dolost_panel_data() debe degradar con gracia (estado
    # "desconocido"), no romper con un 500.
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="dolost-1",
            surface="network",
            config={"decoys": [{"Hostname": "ssh1", "Service": "ssh", "IP": "1.2.3.4"}]},
        )
    )
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b"ssh1" in response.data
    assert "Docker no est".encode() in response.data


def test_dolost_panel_includes_start_stop_delete_buttons_and_live_stats_widget(mounted_app, mounted_client):
    # M14b: gaps de M14a cerrados -- los tres botones nuevos por decoy
    # (Start/Stop/Borrar de la config) mas el widget de stats en vivo
    # (ContainerStatsManager, antes sin ningun consumidor en apate.web).
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]})
    )
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    assert response.status_code == 200
    assert "dolost/decoys/ssh1/start" in text
    assert "dolost/decoys/ssh1/stop" in text
    assert "dolost/decoys/ssh1/delete" in text
    assert 'data-container="DolosT-ssh1"' in text
    assert "dolost-live-stats" in text
    assert "socket.io" in text  # CDN script, solo cuando hay paneles DOLOS-T


def test_dolost_live_stats_script_absent_without_dolost_panels(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b"socket.io" not in response.data
    assert b"dolost-live-stats" not in response.data


def test_dolost_deploy_route_calls_full_lifecycle(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/deploy", follow_redirects=True)

    assert response.status_code == 200
    assert dolost_calls["deploy_collector"] == [True]
    assert dolost_calls["deploy_decoy"] == [{"Hostname": "ssh1"}]
    assert b"flash-success" in response.data


def test_dolost_rotate_route_forces_state_and_rotates(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/rotate", follow_redirects=True)

    assert response.status_code == 200
    assert dolost_calls["stop"] == ["DolosT-ssh1"]
    assert dolost_calls["start"] == ["DolosT-ssh1"]


def test_dolost_retire_route_forces_state_and_retires(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/retire", follow_redirects=True)

    assert response.status_code == 200
    assert dolost_calls["clean_decoy"] == [{"Hostname": "ssh1"}]
    assert dolost_calls["clean_container"] == ["Collector"]
    assert len(dolost_calls["clean_networks"]) == 1


def test_dolost_add_decoy_persists_into_config(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys",
        data={"Hostname": "ftp1", "Service": "ftp", "IP": "10.0.0.5"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert reloaded.plugins[0].config["decoys"] == [
        {
            "Hostname": "ftp1",
            "Description": "",
            "IP": "10.0.0.5",
            "Subnet": "",
            "Gateway": "",
            "DeceptionNetwork": "",
            "ServicePorts": "",
            "Service": "ftp",
            "DecoyFiles": "",
        }
    ]


def test_dolost_add_decoy_without_hostname_flashes_error_and_does_not_persist(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys", data={}, follow_redirects=True
    )

    assert b"flash-error" in response.data
    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert reloaded.plugins[0].config.get("decoys", []) == []


def test_dolost_deploy_decoy_individual_does_not_call_full_deploy(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/deploy", follow_redirects=True
    )

    assert response.status_code == 200
    assert dolost_calls["web_deploy_decoy"] == [{"Hostname": "ssh1"}]
    assert dolost_calls["deploy_collector"] == []
    assert dolost_calls["deploy_decoy"] == []


def test_dolost_undeploy_decoy_individual(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/undeploy", follow_redirects=True
    )

    assert response.status_code == 200
    assert dolost_calls["web_clean_decoy"] == [{"Hostname": "ssh1"}]
    assert dolost_calls["clean_decoy"] == []


def test_dolost_deploy_decoy_unknown_hostname_404(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": []}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/no-existe/deploy")

    assert response.status_code == 404


# -- M14b: start/stop/delete de un decoy puntual (gaps reales de M14a) ------


def test_dolost_start_decoy_calls_docker_start(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/start", follow_redirects=True
    )

    assert response.status_code == 200
    assert dolost_calls["start"] == ["DolosT-ssh1"]
    assert b"flash-success" in response.data


def test_dolost_stop_decoy_calls_docker_stop(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/stop", follow_redirects=True
    )

    assert response.status_code == 200
    assert dolost_calls["stop"] == ["DolosT-ssh1"]
    assert b"flash-success" in response.data


def test_dolost_start_decoy_unknown_hostname_404(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": []}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/no-existe/start")

    assert response.status_code == 404


def test_dolost_stop_decoy_unknown_hostname_404(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": []}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/no-existe/stop")

    assert response.status_code == 404


def test_dolost_delete_decoy_removes_entry_when_docker_status_unknown(mounted_app, mounted_client):
    # Sin Docker configurado en el entorno de tests (containers is None,
    # mismo escenario que test_dolost_panel_lists_configured_decoys_with_
    # unknown_status) -- no se puede confirmar que el decoy siga
    # desplegado, asi que se permite el borrado (fail-open, ver
    # docstring de dolost_delete_decoy).
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="dolost-1",
            surface="network",
            config={"decoys": [{"Hostname": "ssh1"}, {"Hostname": "ftp1"}]},
        )
    )
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/delete", follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-success" in response.data
    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert [d["Hostname"] for d in reloaded.plugins[0].config["decoys"]] == ["ftp1"]


def test_dolost_delete_decoy_rejected_when_still_deployed(mounted_app, mounted_client, monkeypatch):
    # Caso de seguridad pedido explicitamente (M14b): si el contenedor
    # todavia existe en Docker, se rechaza el borrado de la config en
    # vez de dejarlo huerfano.
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    monkeypatch.setattr(
        dolost_plugin_module._docker_manager,
        "get_containers",
        lambda all=True: [{"Names": ["/DolosT-ssh1"], "Status": "Up 2 minutes"}],
    )

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/delete", follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert "todav".encode() in response.data
    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert [d["Hostname"] for d in reloaded.plugins[0].config["decoys"]] == ["ssh1"]


def test_dolost_delete_decoy_unknown_hostname_404(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": []}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/no-existe/delete")

    assert response.status_code == 404


def test_dolost_route_404_for_unknown_plugin_id(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/deploy")

    assert response.status_code == 404


def test_dolost_route_400_for_mismatched_plugin_kind(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/buda-1/dolost/deploy")

    assert response.status_code == 400


# -- Panel "Narrativa de comportamiento simulado" (adaptador BUDA) ---------


def test_buda_panel_offers_create_and_link_when_no_narrative_configured(mounted_app, mounted_client):
    _make_buda_narrative(mounted_app, title="Existente")
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b"Crear narrativa para esta operaci" in response.data
    assert b"Vincular existente" in response.data


def test_buda_panel_shows_running_state_and_profiles(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(mounted_app)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b"detenida" in response.data
    assert b"Sin perfiles de usuario vinculados" in response.data


def test_buda_panel_never_shows_title_objective_or_attacker_profile(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(
        mounted_app,
        title="SECRETO-TITULO",
        objective="SECRETO-OBJETIVO",
        attacker_profile="SECRETO-PERFIL",
    )
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert b"SECRETO-TITULO" not in response.data
    assert b"SECRETO-OBJETIVO" not in response.data
    assert b"SECRETO-PERFIL" not in response.data


def test_buda_panel_never_shows_winrm_credentials(mounted_app, mounted_client):
    from BUDA.app import db as buda_db
    from BUDA.models import Narrative as BudaNarrative, UserProfile as BudaUserProfile

    narrative_id = _make_buda_narrative(mounted_app)
    with mounted_app.app_context():
        narrative = buda_db.session.get(BudaNarrative, narrative_id)
        profile = BudaUserProfile(
            name="Leonardo",
            role="Developer",
            behavior_pattern="navega y abre archivos",
            winrm_server="10.0.0.9",
            winrm_username="SECRETO-USUARIO",
            winrm_password="SECRETO-PASSWORD",
        )
        profile.narrative = [narrative]
        buda_db.session.add(profile)
        buda_db.session.commit()

    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b"Leonardo" in response.data
    assert b"10.0.0.9" in response.data
    assert b"SECRETO-USUARIO" not in response.data
    assert b"SECRETO-PASSWORD" not in response.data


def test_buda_panel_review_shows_activities_assigned_to_each_profile(mounted_app, mounted_client):
    # M14d: "vista de revision" nativa -- lo que hoy solo se veia en
    # /buda/narrative_review/narratives/review/<id>, sin winrm_username/
    # winrm_password a diferencia del original (ver docstring de
    # _buda_panel_data()).
    from BUDA.app import db as buda_db
    from BUDA.models import Activity as BudaActivity
    from BUDA.models import Narrative as BudaNarrative
    from BUDA.models import UserProfile as BudaUserProfile

    narrative_id = _make_buda_narrative(mounted_app)
    with mounted_app.app_context():
        narrative = buda_db.session.get(BudaNarrative, narrative_id)
        profile = BudaUserProfile(
            name="Leonardo",
            role="Developer",
            behavior_pattern="navega y abre archivos",
            winrm_server="10.0.0.9",
            winrm_username="SECRETO-USUARIO",
            winrm_password="SECRETO-PASSWORD",
        )
        activity = BudaActivity(activity_type="Navegar intranet", details="Abre SharePoint")
        profile.narrative = [narrative]
        profile.activities = [activity]
        buda_db.session.add_all([profile, activity])
        buda_db.session.commit()

    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    assert response.status_code == 200
    assert "Navegar intranet" in text
    assert "SECRETO-USUARIO" not in text
    assert "SECRETO-PASSWORD" not in text


def test_buda_panel_review_profile_without_activities_says_so(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(mounted_app)
    from BUDA.app import db as buda_db
    from BUDA.models import Narrative as BudaNarrative
    from BUDA.models import UserProfile as BudaUserProfile

    with mounted_app.app_context():
        narrative = buda_db.session.get(BudaNarrative, narrative_id)
        profile = BudaUserProfile(
            name="Sin actividades",
            role="Tester",
            behavior_pattern="",
            winrm_server="10.0.0.10",
            winrm_username="u",
            winrm_password="p",
        )
        profile.narrative = [narrative]
        buda_db.session.add(profile)
        buda_db.session.commit()

    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b"Sin actividades asignadas." in response.data


# -- M14d: asignar/desasignar UserProfiles a una narrativa -------------------


def test_buda_update_narrative_profiles_assigns_profiles(mounted_app, mounted_client):
    from BUDA.app import db as buda_db
    from BUDA.models import UserProfile as BudaUserProfile

    narrative_id = _make_buda_narrative(mounted_app)
    with mounted_app.app_context():
        profile = BudaUserProfile(name="alice", role="Analyst", behavior_pattern="", winrm_server="s", winrm_username="u", winrm_password="p")
        buda_db.session.add(profile)
        buda_db.session.commit()
        profile_id = profile.id

    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/profiles",
        data={"user_profile_ids": [str(profile_id)]},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"flash-success" in response.data
    assert b"alice" in response.data

    with mounted_app.app_context():
        from BUDA.models import Narrative as BudaNarrative

        narrative = buda_db.session.get(BudaNarrative, narrative_id)
        assert [p.name for p in narrative.user_profiles] == ["alice"]


def test_buda_update_narrative_profiles_can_unassign_all(mounted_app, mounted_client):
    from BUDA.app import db as buda_db
    from BUDA.models import Narrative as BudaNarrative
    from BUDA.models import UserProfile as BudaUserProfile

    narrative_id = _make_buda_narrative(mounted_app)
    with mounted_app.app_context():
        narrative = buda_db.session.get(BudaNarrative, narrative_id)
        profile = BudaUserProfile(name="alice", role="Analyst", behavior_pattern="", winrm_server="s", winrm_username="u", winrm_password="p")
        profile.narrative = [narrative]
        buda_db.session.add(profile)
        buda_db.session.commit()

    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    # Sin user_profile_ids en el POST -- getlist() devuelve [], la
    # relacion queda vacia (desasignar a todos).
    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/profiles", data={}, follow_redirects=True
    )

    assert response.status_code == 200
    with mounted_app.app_context():
        from BUDA.models import Narrative as BudaNarrative

        assert buda_db.session.get(BudaNarrative, narrative_id).user_profiles == []


def test_buda_update_narrative_profiles_404_when_no_narrative_linked(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/profiles", data={}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data


# -- M14d: borrar una narrativa -----------------------------------------------


def test_buda_delete_narrative_removes_row_and_clears_binding_config(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(mounted_app, is_running=False)

    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/delete", follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-success" in response.data

    with mounted_app.app_context():
        from BUDA.app import db as buda_db
        from BUDA.models import Narrative as BudaNarrative

        assert buda_db.session.get(BudaNarrative, narrative_id) is None

    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert "narrative_id" not in reloaded.plugins[0].config


def test_buda_delete_narrative_rejected_when_running(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(mounted_app, is_running=True)

    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/delete", follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data

    with mounted_app.app_context():
        from BUDA.app import db as buda_db
        from BUDA.models import Narrative as BudaNarrative

        assert buda_db.session.get(BudaNarrative, narrative_id) is not None


def test_buda_delete_narrative_404_when_no_narrative_linked(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/delete", follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data


def test_buda_create_narrative_uses_operation_as_placeholder_source(mounted_app, mounted_client):
    op = _make_operation(
        name="Operacion placeholder",
        adversary_profile=AdversaryProfile(name="APT-9", motivation="sabotaje", skill_level="advanced"),
    )
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/create", follow_redirects=True
    )
    assert response.status_code == 200
    assert b"flash-success" in response.data

    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    narrative_id = reloaded.plugins[0].config["narrative_id"]

    with mounted_app.app_context():
        from BUDA.app import db as buda_db
        from BUDA.models import Narrative as BudaNarrative

        narrative = buda_db.session.get(BudaNarrative, narrative_id)
        assert narrative.title == "Operacion placeholder"
        assert "APT-9" in narrative.attacker_profile
        assert "sabotaje" in narrative.attacker_profile
        assert narrative.is_running is False


def test_buda_link_narrative_sets_config(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(mounted_app)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/link",
        data={"narrative_id": str(narrative_id)},
        follow_redirects=True,
    )

    assert response.status_code == 200
    reloaded = mounted_app.config["OPERATION_REPOSITORY"].get(op.id)
    assert reloaded.plugins[0].config["narrative_id"] == narrative_id


def test_buda_start_calls_plugin_deploy(mounted_app, mounted_client, buda_calls):
    narrative_id = _make_buda_narrative(mounted_app)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/buda-1/buda/start", follow_redirects=True)

    assert response.status_code == 200
    assert buda_calls["start_narrative"] == [narrative_id]
    assert b"flash-success" in response.data


def test_buda_start_refuses_when_already_running(mounted_app, mounted_client, buda_calls):
    narrative_id = _make_buda_narrative(mounted_app, is_running=True)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/buda-1/buda/start", follow_redirects=True)

    assert b"flash-error" in response.data
    assert buda_calls["start_narrative"] == []


def test_buda_stop_calls_plugin_retire(mounted_app, mounted_client, buda_calls):
    narrative_id = _make_buda_narrative(mounted_app, is_running=True)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/buda-1/buda/stop", follow_redirects=True)

    assert response.status_code == 200
    assert buda_calls["stop_narrative"] == [narrative_id]
    assert b"flash-success" in response.data


def test_buda_stop_refuses_when_not_running(mounted_app, mounted_client, buda_calls):
    narrative_id = _make_buda_narrative(mounted_app, is_running=False)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/buda-1/buda/stop", follow_redirects=True)

    assert b"flash-error" in response.data
    assert buda_calls["stop_narrative"] == []


def test_buda_route_404_for_unknown_plugin_id(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/buda-1/buda/start")

    assert response.status_code == 404


def test_buda_route_400_for_mismatched_plugin_kind(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/buda/start")

    assert response.status_code == 400


# -- Fase 1 post-BlackHat: atribucion y auditoria de acciones manuales -------


def test_dolost_deploy_logs_operator_action_with_session_operator(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)
    mounted_client.post("/operator", data={"operator": "Federico"})

    mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/deploy", follow_redirects=True)

    actions = mounted_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(op.id)
    assert len(actions) == 1
    assert actions[0].operator == "Federico"
    assert actions[0].action == "dolost_deploy"
    assert actions[0].outcome == "success"
    assert actions[0].plugin_id == "dolost-1"


def test_manual_action_without_session_operator_logs_as_sin_especificar(mounted_app, mounted_client, buda_calls):
    narrative_id = _make_buda_narrative(mounted_app, is_running=False)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    mounted_client.post(f"/operations/{op.id}/plugins/buda-1/buda/start", follow_redirects=True)

    actions = mounted_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(op.id)
    assert len(actions) == 1
    assert actions[0].operator == "sin especificar"


def test_buda_stop_refusal_logs_error_outcome(mounted_app, mounted_client, buda_calls):
    narrative_id = _make_buda_narrative(mounted_app, is_running=False)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    mounted_client.post(f"/operations/{op.id}/plugins/buda-1/buda/stop", follow_redirects=True)

    actions = mounted_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(op.id)
    assert len(actions) == 1
    assert actions[0].action == "buda_stop"
    assert actions[0].outcome == "error"
    assert actions[0].detail == "La narrativa no está corriendo."


def test_dolost_start_stop_decoy_log_target_hostname(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/start", follow_redirects=True)
    mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/stop", follow_redirects=True)

    actions = mounted_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(op.id)
    assert [a.action for a in actions] == ["dolost_start_decoy", "dolost_stop_decoy"]
    assert all(a.target == "ssh1" for a in actions)


def test_detail_page_renders_operator_action_history(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)
    mounted_client.post("/operator", data={"operator": "Federico"})
    mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/deploy")

    response = mounted_client.get(f"/operations/{op.id}#tab-mechanics")

    assert response.status_code == 200
    assert b"Historial de acciones manuales" in response.data
    assert b"Federico" in response.data
    assert b"dolost_deploy" in response.data


def test_detail_page_shows_empty_state_without_any_operator_action(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert b"Todav&iacute;a no se registr&oacute; ninguna acci&oacute;n manual" in response.data


class _FakeHoneyPlugin:
    def __init__(self, binding: PluginBinding, _operation_id: str, _bus):
        self.binding = binding

    @classmethod
    def from_binding(cls, binding: PluginBinding, operation_id: str, bus):
        return cls(binding, operation_id, bus)

    def configured_paths(self):
        base = Path(self.binding.config["directory"])
        return [base / "a.txt"]

    def deploy(self):  # noqa: ARG002
        pass


class _FailingHoneyPlugin(_FakeHoneyPlugin):
    def configured_paths(self):
        raise RuntimeError("configuración inválida")


class _FakeCanaryPlugin:
    def __init__(self, _binding: PluginBinding, _operation_id: str, _bus):
        self.config = {"token": "tok", "auth_token": "auth"}

    @classmethod
    def from_binding(cls, binding: PluginBinding, operation_id: str, bus):
        return cls(binding, operation_id, bus)

    def deploy(self):  # noqa: ARG002
        pass


class _FailingCanaryPlugin(_FakeCanaryPlugin):
    def deploy(self):  # noqa: ARG002
        raise CanarytokenAPIError("falla API")


class _FakeOpenCanaryPlugin:
    def __init__(self, _binding: PluginBinding, _operation_id: str, _bus):
        self.config = {"node_id": "node", "container_status": "running"}

    @classmethod
    def from_binding(cls, binding: PluginBinding, operation_id: str, bus):
        return cls(binding, operation_id, bus)

    def deploy(self):  # noqa: ARG002
        pass


class _FailingOpenCanaryPlugin(_FakeOpenCanaryPlugin):
    def deploy(self):  # noqa: ARG002
        raise OpenCanaryError("puerto ocupado")


class _FakeDolostPlugin:
    def __init__(self, _binding: PluginBinding, _operation_id: str, _bus):
        self.deployed = False

    @classmethod
    def from_binding(cls, binding: PluginBinding, operation_id: str, bus):
        return cls(binding, operation_id, bus)

    def deploy(self):  # noqa: ARG002
        self.deployed = True


class _FailingDolostPlugin(_FakeDolostPlugin):
    def deploy(self):  # noqa: ARG002
        raise RuntimeError("docker no disponible")


class _FakeBudaPlugin:
    def __init__(self, _binding: PluginBinding, _operation_id: str, _bus):
        pass

    @classmethod
    def from_binding(cls, binding: PluginBinding, operation_id: str, bus):
        return cls(binding, operation_id, bus)

    def deploy(self):  # noqa: ARG002
        pass


def test_deploy_one_binding_dispatcher_success_per_kind(monkeypatch, mounted_app):
    op = _make_operation()
    op_dir = mounted_app.config["APATE_DATA_DIR"] / "op"
    op_dir.mkdir(parents=True, exist_ok=True)
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", config={"directory": str(op_dir)}))
    op.bind_plugin(
        PluginBinding(
            plugin_id="canarytoken-1",
            plugin_kind="canarytoken",
            surface="data",
            config={"base_url": "http://x", "token_type": "aws_keys", "memo": "m", "email": "a@b.com"},
        )
    )
    op.bind_plugin(
        PluginBinding(plugin_id="opencanary-1", plugin_kind="opencanary", surface="network", config={"services": {"ssh": {"enabled": True}}})
    )
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    op.bind_plugin(
        PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity", config={"narrative_id": _make_buda_narrative(mounted_app, is_running=False)})
    )
    _save(mounted_app, op)

    monkeypatch.setattr(operations_module, "HoneytokenPlugin", _FakeHoneyPlugin)
    monkeypatch.setattr(operations_module, "CanarytokenPlugin", _FakeCanaryPlugin)
    monkeypatch.setattr(operations_module, "OpenCanaryPlugin", _FakeOpenCanaryPlugin)
    monkeypatch.setattr(operations_module, "DolosTPlugin", _FakeDolostPlugin)
    monkeypatch.setattr(operations_module, "BudaPlugin", _FakeBudaPlugin)

    with mounted_app.app_context():
        for binding in op.plugins:
            result = operations_module._deploy_one_binding(op, binding, strict=True)
            assert result["outcome"] == "success"


def test_deploy_one_binding_dispatcher_failure_per_kind(monkeypatch, mounted_app):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", config={"directory": "/tmp"}))
    op.bind_plugin(PluginBinding(plugin_id="canarytoken-1", plugin_kind="canarytoken", surface="data"))
    op.bind_plugin(PluginBinding(plugin_id="opencanary-1", plugin_kind="opencanary", surface="network", config={"services": {"ssh": {"enabled": True}}}))
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    op.bind_plugin(
        PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity", config={"narrative_id": _make_buda_narrative(mounted_app, is_running=True)})
    )
    _save(mounted_app, op)

    monkeypatch.setattr(operations_module, "HoneytokenPlugin", _FailingHoneyPlugin)
    monkeypatch.setattr(operations_module, "CanarytokenPlugin", _FailingCanaryPlugin)
    monkeypatch.setattr(operations_module, "OpenCanaryPlugin", _FailingOpenCanaryPlugin)
    monkeypatch.setattr(operations_module, "DolosTPlugin", _FailingDolostPlugin)
    monkeypatch.setattr(operations_module, "BudaPlugin", _FakeBudaPlugin)

    outcomes = []
    with mounted_app.app_context():
        for binding in op.plugins:
            result = operations_module._deploy_one_binding(op, binding, strict=True)
            outcomes.append(result["outcome"])

    assert "failed" in outcomes
    assert outcomes.count("already_deployed") == 1


def test_deploy_all_campaign_route_shows_summary_and_redirect(mounted_app, mounted_client, monkeypatch):
    op = _make_operation()
    op_dir = mounted_app.config["APATE_DATA_DIR"] / "bulk"
    op_dir.mkdir(parents=True, exist_ok=True)
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", config={"directory": str(op_dir)}))
    op.bind_plugin(PluginBinding(plugin_id="canarytoken-1", plugin_kind="canarytoken", surface="data"))
    op.bind_plugin(
        PluginBinding(plugin_id="opencanary-1", plugin_kind="opencanary", surface="network", config={"services": {"ssh": {"enabled": True}}})
    )
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    op.bind_plugin(PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity", config={"narrative_id": _make_buda_narrative(mounted_app, is_running=True)}))
    op.bind_plugin(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    _save(mounted_app, op)

    monkeypatch.setattr(operations_module, "HoneytokenPlugin", _FakeHoneyPlugin)
    monkeypatch.setattr(operations_module, "CanarytokenPlugin", _FakeCanaryPlugin)
    monkeypatch.setattr(operations_module, "OpenCanaryPlugin", _FailingOpenCanaryPlugin)
    monkeypatch.setattr(operations_module, "DolosTPlugin", _FakeDolostPlugin)
    monkeypatch.setattr(operations_module, "BudaPlugin", _FakeBudaPlugin)

    response = mounted_client.post(f"/operations/{op.id}/deploy-all", follow_redirects=True)

    assert response.status_code == 200
    text = response.data.decode()
    assert "Resumen de despliegue de campaña" in text
    assert "2 desplegados" in text
    assert "1 ya estaban desplegados" in text
    assert "2 sin configurar/saltados" in text
    assert "1 fallidos" in text


def test_honeytoken_check_access_is_reachable_from_the_interface(client, app, tmp_path):
    """`HoneytokenPlugin.check_access()` existía desde M7, con tests, y no la
    llamaba nadie: era la única capacidad nativa sin ninguna vía de
    observación, mientras Canarytokens y OpenCanary sí tenían su chequeo.
    Encontrado recorriendo la metodología sobre una instalación limpia.

    El baseline se persiste porque cada request construye una instancia nueva
    y `restore_deployed_state()` vuelve a snapshotear: sin guardarlo, la
    comparación sería contra el instante actual y nunca detectaría nada.
    """

    import os

    from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement

    directorio = tmp_path / "senuelos"
    operation = Operation(
        name="Chequeo de acceso",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
    )
    operation.plugins.append(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            plugin_kind="honeytoken",
            config={"directory": str(directorio), "filenames": ["credenciales.txt"]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    base = f"/operations/{operation.id}/plugins/honeytoken-1/honeytoken"
    client.post(f"{base}/deploy")
    archivo = directorio / "credenciales.txt"
    assert archivo.is_file()

    # El deploy ya deja el punto de referencia persistido (E2 de
    # docs/improvements.md), asi que el primer chequeo ya compara de verdad
    # en vez de limitarse a fijar el baseline -- antes el primer acceso real
    # se perdia en silencio.
    guardado = app.config["OPERATION_REPOSITORY"].get(operation.id).plugins[0].config
    assert guardado["_apate_access_baseline"]

    primero = client.post(f"{base}/check-access", follow_redirects=True).get_data(as_text=True)
    assert "acceso(s) nuevo(s) detectado(s)" in primero

    estado = archivo.stat()
    os.utime(archivo, (estado.st_atime + 120, estado.st_mtime))

    segundo = client.post(f"{base}/check-access", follow_redirects=True).get_data(as_text=True)
    assert "acceso(s) nuevo(s) detectado(s)" in segundo
    assert app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)


def test_manual_honeytoken_rotate_evaluates_rules_and_persists_operation_and_firing(client, app, tmp_path):
    """Una de las siete rutas que antes no guardaba debe persistir ambas cosas.

    El evento ``rotate`` lo publica el plugin real; la regla lo reconoce por
    su binding y transiciona la operación. El assert relee ambos repositorios
    para impedir que quede una decisión SQLite sin su estado de dominio.
    """

    directory = tmp_path / "senuelos-regla"
    operation = Operation(
        name="Rotacion manual con regla",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
    )
    operation.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            plugin_kind="honeytoken",
            config={"directory": str(directory), "filenames": ["credenciales.txt"]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    client.post(
        "/rules/",
        data={
            "rules_text": """
rules:
  - name: \"Rotación manual observada -> activar\"
    when:
      event_type: interaction
      plugin_id: honeytoken-1
      payload:
        kind: rotate
    then:
      - action: transition
        to: active
""",
        },
    )

    base = f"/operations/{operation.id}/plugins/honeytoken-1/honeytoken"
    client.post(f"{base}/deploy")
    response = client.post(f"{base}/rotate", follow_redirects=True)

    assert response.status_code == 200
    persisted = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert persisted.status == OperationStatus.ACTIVE
    firings = app.config["RULE_DECISION_REPOSITORY"].list_firings_for_operation(operation.id)
    assert [firing.rule_name for firing in firings] == ["Rotación manual observada -> activar"]


def test_manual_action_keeps_roe_rejection_in_decision_repository(client, app, tmp_path):
    directory = tmp_path / "senuelos-roe"
    operation = Operation(
        name="Rotacion manual bloqueada",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(forbidden_actions=["transition:active"]),
        narrative=Narrative(name="N"),
    )
    operation.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            plugin_kind="honeytoken",
            config={"directory": str(directory), "filenames": ["credenciales.txt"]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    client.post(
        "/rules/",
        data={
            "rules_text": """
rules:
  - name: \"Rotación bloqueada\"
    when:
      event_type: interaction
      plugin_id: honeytoken-1
      payload:
        kind: rotate
    then:
      - action: transition
        to: active
""",
        },
    )

    base = f"/operations/{operation.id}/plugins/honeytoken-1/honeytoken"
    client.post(f"{base}/deploy")
    client.post(f"{base}/rotate")

    assert app.config["OPERATION_REPOSITORY"].get(operation.id).status == OperationStatus.PLANNING
    rejections = app.config["RULE_DECISION_REPOSITORY"].list_rejections_for_operation(operation.id)
    assert [rejection.rule_name for rejection in rejections] == ["Rotación bloqueada"]


def test_manual_action_keeps_the_reentrant_rule_chain_bounded(client, app, tmp_path):
    directory = tmp_path / "senuelos-cadena"
    operation = Operation(
        name="Rotacion manual con cadena",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
    )
    operation.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            plugin_kind="honeytoken",
            config={"directory": str(directory), "filenames": ["credenciales.txt"]},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    client.post(
        "/rules/",
        data={
            "rules_text": """
rules:
  - name: \"Rotar otra vez\"
    when:
      event_type: interaction
      plugin_id: honeytoken-1
      payload:
        kind: rotate
    then:
      - action: rotate
        plugin_id: honeytoken-1
""",
        },
    )

    base = f"/operations/{operation.id}/plugins/honeytoken-1/honeytoken"
    client.post(f"{base}/deploy")
    response = client.post(f"{base}/rotate")

    assert response.status_code == 302
    rejections = app.config["RULE_DECISION_REPOSITORY"].list_rejections_for_operation(operation.id)
    assert len(rejections) == 1
    assert "Tope de acciones por cadena" in rejections[0].reason
