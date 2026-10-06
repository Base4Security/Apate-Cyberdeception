"""Cobertura del despliegue contextual incorporado en la Fase 4."""

import datetime

import pytest

from apate.core import (
    AdversaryProfile,
    Narrative,
    Operation,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
)
from apate.web import create_app


def _operation() -> Operation:
    return Operation(
        name="Operación contextual",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


def _save(app, operation: Operation) -> None:
    app.config["OPERATION_REPOSITORY"].save(operation)


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'phase4-buda.db'}",
        }
    )


def _buda_binding_with_narrative(app, operation: Operation) -> PluginBinding:
    from BUDA.app import db as buda_db
    from BUDA.models import Narrative as BudaNarrative

    with app.app_context():
        narrative = BudaNarrative(
            title="No debe mostrarse",
            objective="No debe mostrarse",
            attacker_profile="No debe mostrarse",
            deception_activities="Actividad base",
            end_date=datetime.date.today(),
            is_running=False,
            percentage_of_similarity=100,
        )
        buda_db.session.add(narrative)
        buda_db.session.commit()
        narrative_id = narrative.id
    binding = PluginBinding(
        plugin_id="buda-contextual",
        plugin_kind="buda",
        surface="identity",
        config={"narrative_id": narrative_id},
    )
    operation.bind_plugin(binding)
    _save(app, operation)
    return binding


def test_deployment_map_groups_bindings_by_scenario_and_surface(app):
    operation = _operation()
    scenario = Scenario(description="Acceso a finanzas")
    operation.add_scenario(scenario)
    operation.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-finance",
            plugin_kind="honeytoken",
            surface="data",
            scenario_id=scenario.id,
            config={"directory": "C:/deception", "filenames": ["finance.txt"]},
        )
    )
    _save(app, operation)

    response = app.test_client().get(f"/operations/{operation.id}")

    assert response.status_code == 200
    assert b"Mapa de despliegue" in response.data
    assert "Acceso a finanzas".encode() in response.data
    assert b"honeytoken-finance" in response.data
    assert b"Archivos se&ntilde;uelo" in response.data


def test_external_binding_without_mount_links_health_configuration(app):
    operation = _operation()
    operation.bind_plugin(PluginBinding(plugin_id="dolost-offline", plugin_kind="dolost", surface="network"))
    _save(app, operation)

    response = app.test_client().get(f"/operations/{operation.id}")

    assert response.status_code == 200
    assert b"Dependencias externas no disponibles" in response.data
    assert b"/health/configuration/network-host-runtime" in response.data


def test_honeytoken_full_lifecycle_persists_state_and_audit(app, tmp_path):
    operation = _operation()
    binding = PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data")
    operation.bind_plugin(binding)
    _save(app, operation)
    client = app.test_client()
    target = tmp_path / "honeytokens"
    base = f"/operations/{operation.id}/plugins/{binding.plugin_id}/honeytoken"

    configured = client.post(
        f"{base}/configure",
        data={"directory": str(target), "filenames": "finance.csv\nbackup.txt", "ttp_id": "T1552.001"},
    )
    deployed = client.post(f"{base}/deploy")
    before_rotation = (target / "backup.txt").read_text(encoding="utf-8")
    rotated = client.post(f"{base}/rotate")
    after_rotation = (target / "backup.txt").read_text(encoding="utf-8")
    retired = client.post(f"{base}/retire")

    assert all(response.status_code == 302 for response in (configured, deployed, rotated, retired))
    assert before_rotation != after_rotation
    assert not target.exists()
    stored = app.config["OPERATION_REPOSITORY"].get(operation.id)
    assert "_apate_created_directory" not in stored.plugins[0].config
    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert [action.action for action in actions] == [
        "honeytoken_configure",
        "honeytoken_deploy",
        "honeytoken_rotate",
        "honeytoken_retire",
    ]


def test_honeytoken_deploy_refuses_to_overwrite_existing_file(app, tmp_path):
    target = tmp_path / "shared"
    target.mkdir()
    existing = target / "important.txt"
    existing.write_text("real", encoding="utf-8")
    operation = _operation()
    operation.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-safe",
            plugin_kind="honeytoken",
            surface="data",
            config={"directory": str(target), "filenames": [existing.name]},
        )
    )
    _save(app, operation)

    response = app.test_client().post(
        f"/operations/{operation.id}/plugins/honeytoken-safe/honeytoken/deploy",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert existing.read_text(encoding="utf-8") == "real"
    assert b"no sobrescribe archivos existentes" in response.data
    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert actions[-1].outcome == "error"


def test_inline_profile_creation_links_it_without_exposing_credentials(mounted_app):
    operation = _operation()
    binding = _buda_binding_with_narrative(mounted_app, operation)
    client = mounted_app.test_client()
    password = "Secreto-que-no-debe-salir"

    response = client.post(
        f"/operations/{operation.id}/plugins/{binding.plugin_id}/buda/profiles",
        data={
            "name": "Analista",
            "role": "Finanzas",
            "behavior_pattern": "Horario de oficina",
            "winrm_server": "host-01",
            "winrm_username": "usuario-sensible",
            "winrm_password": password,
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Analista" in response.data
    assert b"host-01" in response.data
    assert password.encode() not in response.data
    assert b"usuario-sensible" not in response.data
    actions = mounted_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert actions[-1].action == "buda_create_profile"
    assert password not in actions[-1].detail


def test_inline_activity_creation_and_manual_selection(mounted_app):
    from BUDA.app import db as buda_db
    from BUDA.models import Activity, UserProfile

    operation = _operation()
    binding = _buda_binding_with_narrative(mounted_app, operation)
    client = mounted_app.test_client()
    client.post(
        f"/operations/{operation.id}/plugins/{binding.plugin_id}/buda/profiles",
        data={
            "name": "Operador",
            "role": "Administración",
            "winrm_server": "host-02",
            "winrm_username": "user",
            "winrm_password": "synthetic",
        },
    )
    with mounted_app.app_context():
        profile_id = UserProfile.query.filter_by(name="Operador").one().id

    created = client.post(
        f"/operations/{operation.id}/plugins/{binding.plugin_id}/buda/activities",
        data={"activity_type": "Document Editing", "details": "Plan señuelo", "profile_ids": [str(profile_id)]},
    )
    with mounted_app.app_context():
        created_activity = Activity.query.filter_by(activity_type="Document Editing").one()
        assert [profile.id for profile in created_activity.user_profiles] == [profile_id]
        extra = Activity(activity_type="Browsing", details="Navegación sintética")
        buda_db.session.add(extra)
        buda_db.session.commit()
        extra_id = extra.id

    selected = client.post(
        f"/operations/{operation.id}/plugins/{binding.plugin_id}/buda/profiles/{profile_id}/activities",
        data={"activity_ids": [str(extra_id)]},
    )

    assert created.status_code == 302
    assert selected.status_code == 302
    with mounted_app.app_context():
        profile = buda_db.session.get(UserProfile, profile_id)
        assert [activity.id for activity in profile.activities] == [extra_id]
    actions = mounted_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)
    assert actions[-2].action == "buda_create_activity"
    assert actions[-1].action == "buda_update_profile_activities"


def test_profile_activity_selection_rejects_profile_outside_operation(mounted_app):
    from BUDA.app import db as buda_db
    from BUDA.models import UserProfile

    operation = _operation()
    binding = _buda_binding_with_narrative(mounted_app, operation)
    with mounted_app.app_context():
        outside = UserProfile(
            name="Fuera",
            role="Otro",
            behavior_pattern="",
            winrm_server="host-03",
            winrm_username="user",
            winrm_password="synthetic",
        )
        buda_db.session.add(outside)
        buda_db.session.commit()
        outside_id = outside.id

    response = mounted_app.test_client().post(
        f"/operations/{operation.id}/plugins/{binding.plugin_id}/buda/profiles/{outside_id}/activities"
    )

    assert response.status_code == 404
