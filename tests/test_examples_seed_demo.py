"""Tests para `examples/seed_demo.py` -- seed idempotente de
operaciones de ejemplo para demo (reemplaza `examples/quickstart.py`,
ver docs/roadmap.md).

`examples/` no es un paquete Python (se ejecuta directo con
`python examples/seed_demo.py`, mismo criterio que ya tenia
`quickstart.py`) -- se carga el modulo por ruta de archivo en vez de
agregar un `__init__.py` que cambiaria como se invoca el script.

Mismo patron de fixtures que `test_web_operations_panels.py`
(`mounted_app`/`mounted_client` con `SQLALCHEMY_DATABASE_URI` real):
`_create_buda_narrative_from_operation()`, invocada dentro de
`add_plugin_binding()` para las operaciones de ejemplo con plugin
`buda`, necesita la sesion de SQLAlchemy de BUDA activa
(`mount_buda()`, `APATE_MOUNT_EXTERNAL_TOOLS=True`, el default de
`create_app()`)."""

import importlib.util
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from BUDA.app import db as buda_db
from BUDA.models import Activity as BudaActivity
from BUDA.models import Narrative as BudaNarrative
from BUDA.models import UserProfile as BudaUserProfile
from apate.web import create_app
from apate.web._asset_coverage import build_asset_coverage
from apate.web.blueprints.operations import _canarytoken_panel_data, _opencanary_panel_data
from apate.web._portfolio import build_portfolio

_SEED_DEMO_PATH = Path(__file__).resolve().parent.parent / "examples" / "seed_demo.py"


def _load_seed_demo_module():
    spec = importlib.util.spec_from_file_location("seed_demo", _SEED_DEMO_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


seed_demo = _load_seed_demo_module()


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-seed-demo-test.db'}",
        }
    )


def test_seed_demo_creates_three_example_operations(mounted_app):
    with mounted_app.app_context():
        created = seed_demo.seed_demo_operations(mounted_app)

    assert len(created) == 3
    operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    assert len(operations) == 3
    assert {op.name for op in operations} == {
        spec["operation"]["name"] for spec in seed_demo.list_templates()
    }
    assert {asset.identifier for asset in mounted_app.config["ASSET_REPOSITORY"].list()} == {
        "Segmento de red financiero",
        "Servidores de archivos internos",
        "Buzones de correo de RRHH",
        "Credenciales de acceso remoto",
        "Repositorios de datos financieros",
        "Infraestructura de respaldo",
    }


@pytest.mark.csrf
def test_seed_demo_creates_operations_with_real_csrf_protection(mounted_app):
    """El entrypoint de producción conserva la protección CSRF activa."""

    with mounted_app.app_context():
        created = seed_demo.seed_demo_operations(mounted_app)

    assert len(created) == 3
    assert len(list(mounted_app.config["OPERATION_REPOSITORY"].list())) == 3


def test_seed_demo_can_persist_a_coherent_english_demo_in_a_temp_data_directory(mounted_app):
    mounted_app.config["APATE_LOCALE"] = "en"
    with mounted_app.app_context():
        created = seed_demo.seed_demo_operations(mounted_app, locale="en")
        assert len(created) == 3
        operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
        assets = list(mounted_app.config["ASSET_REPOSITORY"].list())
        assert {operation.name for operation in operations} == {
            spec["operation"]["name"] for spec in seed_demo.list_templates(locale="en")
        }
        assert {asset.identifier for asset in assets} == {
            asset["identifier"] for asset in seed_demo._DEMO_ASSETS_EN
        }
        assert all(profile.winrm_server.endswith(".example.invalid") for profile in BudaUserProfile.query.all())
        assert all(profile.winrm_password == "DEMO_ONLY_NOT_A_REAL_SECRET" for profile in BudaUserProfile.query.all())
        measured = next(
            binding.effect for operation in operations for binding in operation.plugins if binding.effect.measured_outcome
        )
        assert measured.measured_by == "Demo seed"
        assert measured.measured_outcome.startswith("The backup decoy")
        page = mounted_app.test_client().get("/operations/").get_data(as_text=True)
        assert "Operations" in page
        assert "APT28 — Lateral movement to the financial segment" in page


def test_seed_demo_is_idempotent_running_it_twice_does_not_duplicate(mounted_app):
    with mounted_app.app_context():
        first_run = seed_demo.seed_demo_operations(mounted_app)
        second_run = seed_demo.seed_demo_operations(mounted_app)

    assert len(first_run) == 3
    assert second_run == []
    assert len(list(mounted_app.config["OPERATION_REPOSITORY"].list())) == 3


def test_seed_demo_puebla_las_pantallas_vacias_sin_fingir_contexto_forense(mounted_app):
    """El seed usa los flujos web y no inventa un EVTX para BUDA."""

    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)
        seed_demo.seed_demo_operations(mounted_app)

        operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
        assets = list(mounted_app.config["ASSET_REPOSITORY"].list())
        asset_ids = {asset.identifier for asset in assets}
        assert len(assets) == 6
        assert set().union(*(set(operation.adversary_profile.target_assets) for operation in operations)) == asset_ids

        for operation in operations:
            coverage = build_asset_coverage(operation, assets)
            assert coverage["covered"], operation.name
            assert not coverage["unresolved_references"], operation.name

        apt28 = next(operation for operation in operations if operation.name.startswith("APT28"))
        assert len(apt28.scenarios) == 2
        assert any(
            scenario.description == seed_demo._DEMO_SECOND_SCENARIO["description"]
            for scenario in apt28.scenarios
        )

        lazarus = next(operation for operation in operations if operation.name.startswith("Lazarus Group"))
        measured = [
            binding
            for operation in operations
            for binding in operation.plugins
            if binding.effect.measured_outcome
        ]
        assert [binding.plugin_id for binding in measured] == ["dolost-lazarus-exfil"]
        assert measured[0].effect.measured_by == "Seed de demostración"
        assert lazarus.find_plugin_binding("dolost-lazarus-exfil") is measured[0]

        narratives = BudaNarrative.query.order_by(BudaNarrative.id).all()
        profiles = BudaUserProfile.query.order_by(BudaUserProfile.id).all()
        activities = BudaActivity.query.order_by(BudaActivity.id).all()
        assert len(narratives) == len(profiles) == len(activities) == 2
        assert {profile.name for profile in profiles} == {
            profile_data["name"] for profile_data in seed_demo._DEMO_BUDA_PROFILES.values()
        }
        assert all(profile.winrm_server.endswith(".example.invalid") for profile in profiles)
        assert all(len(narrative.user_profiles) == 1 for narrative in narratives)
        assert all(len(activity.user_profiles) == 1 for activity in activities)
        for operation in operations:
            for binding in operation.plugins:
                expected_profile = seed_demo._DEMO_BUDA_PROFILES.get(binding.plugin_id)
                if expected_profile is None:
                    continue
                narrative = buda_db.session.get(BudaNarrative, binding.config["narrative_id"])
                assert [profile.name for profile in narrative.user_profiles] == [expected_profile["name"]]
        # El contexto requiere un EVTX subido y confirmado por la aplicación;
        # el seed no debe fabricar esa evidencia.
        assert list(mounted_app.config["BEHAVIOR_CONTEXT_REPOSITORY"].list()) == []
        assert all(not operation.behavior_context_source_ids for operation in operations)


def test_seed_demo_populates_events_iocs_and_partial_ttps_for_each_operation(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    collector = mounted_app.config["TELEMETRY_COLLECTOR"]
    for operation in list(mounted_app.config["OPERATION_REPOSITORY"].list()):
        observed_ttps = set(collector.list_ttps(operation.id))
        assert collector.list_events(operation.id), operation.name
        assert collector.list_iocs(operation.id), operation.name
        assert observed_ttps, operation.name
        assert set(operation.scenarios[0].related_ttps) - observed_ttps, operation.name


def test_seed_demo_second_run_does_not_duplicate_telemetry(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)
        collector = mounted_app.config["TELEMETRY_COLLECTOR"]
        counts_before = {
            operation.id: len(collector.list_events(operation.id))
            for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
        }
        second_run = seed_demo.seed_demo_operations(mounted_app)

    counts_after = {
        operation.id: len(collector.list_events(operation.id))
        for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
    }
    assert second_run == []
    assert counts_after == counts_before


def test_seed_demo_spreads_impact_telemetry_and_real_rule_decisions_over_time(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    collector = mounted_app.config["TELEMETRY_COLLECTOR"]
    operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    records = [record for operation in operations for record in collector.list_events(operation.id)]
    decisions = mounted_app.config["RULE_DECISION_REPOSITORY"].list_firings_for_operations(
        [operation.id for operation in operations]
    )

    assert len(records) == 2400
    assert max(record.timestamp for record in records) - min(record.timestamp for record in records) >= timedelta(days=19)
    assert {record.ttp_id for record in records if record.ttp_id}
    assert all(record.payload.get("demo_seed") == "impact-v3" for record in records)
    assert len(decisions) == 3
    assert all(firing.rule_name.startswith("Fixture de impacto") for _, firing in decisions)


def test_seed_demo_recent_activity_is_varied_across_operations_and_irregular(mounted_app):
    reference_time = datetime(2026, 8, 29, 12, 45, tzinfo=timezone.utc)
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app, reference_time=reference_time)

    operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    collector = mounted_app.config["TELEMETRY_COLLECTOR"]
    records = sorted(
        (record for operation in operations for record in collector.list_events(operation.id)),
        key=lambda record: record.timestamp,
        reverse=True,
    )
    newest = records[:12]
    newest_details = [record.payload["detail"] for record in newest]
    gaps = [
        int((newest[index].timestamp - newest[index + 1].timestamp).total_seconds())
        for index in range(len(newest) - 1)
    ]

    assert len({record.operation_id for record in newest}) > 1
    assert len(newest_details) == len(set(newest_details))
    assert len(set(gaps)) > 1


def test_seed_demo_is_reproducible_with_a_fixed_reference_time(mounted_app, tmp_path):
    reference_time = datetime(2026, 8, 29, 12, 45, tzinfo=timezone.utc)
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app, reference_time=reference_time)
    first_operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    first_records = sorted(
        (
            operation.name,
            record.plugin_id,
            record.event_type.value,
            record.ttp_id,
            record.timestamp,
            record.payload,
        )
        for operation in first_operations
        for record in mounted_app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    )

    from apate.web import create_app

    second_app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": str(tmp_path / "second"),
            "APATE_MOUNT_EXTERNAL_TOOLS": True,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'second-buda.db'}",
        }
    )
    with second_app.app_context():
        seed_demo.seed_demo_operations(second_app, reference_time=reference_time)
    second_operations = list(second_app.config["OPERATION_REPOSITORY"].list())
    second_records = sorted(
        (
            operation.name,
            record.plugin_id,
            record.event_type.value,
            record.ttp_id,
            record.timestamp,
            record.payload,
        )
        for operation in second_operations
        for record in second_app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)
    )

    assert first_records == second_records


def test_seed_demo_updates_existing_template_operations_as_one_set(mounted_app):
    client = mounted_app.test_client()
    with mounted_app.app_context():
        for spec in seed_demo.list_templates():
            seed_demo._create_example_operation(client, spec)
        created = seed_demo.seed_demo_operations(
            mounted_app,
            reference_time=datetime(2026, 8, 29, 12, 45, tzinfo=timezone.utc),
        )

    operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    assert created == []
    assert sum(len(mounted_app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)) for operation in operations) == 2400
    apt28 = next(operation for operation in operations if operation.name.startswith("APT28"))
    assert len(mounted_app.config["INCIDENT_REPOSITORY"].list_for_operation(apt28.id)) == 1
    assert len(apt28.closure_criteria.trigger_conditions) == 1


def test_seed_demo_tells_a_coherent_story_for_each_capability_and_heatmap_state(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    collector = mounted_app.config["TELEMETRY_COLLECTOR"]
    operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    records_by_operation = collector.list_events_by_operation([operation.id for operation in operations])
    counts = {operation.name.split(" ")[0]: len(records_by_operation[operation.id]) for operation in operations}
    assert counts == {"APT28": 900, "FIN7": 800, "Lazarus": 700}
    for operation in operations:
        bindings = {binding.plugin_id for binding in operation.plugins}
        records = records_by_operation[operation.id]
        assert {record.plugin_id for record in records} <= bindings
        if operation.status.value == "closed":
            assert max(record.timestamp for record in records) <= operation.updated_at

    heatmap = build_portfolio(operations, collector)["ttp_heatmap"]["columns"]
    statuses = {cell["status"] for column in heatmap for cell in column["cells"]}
    assert {"matched", "not-observed", "unexpected"} <= statuses


def test_seed_demo_iocs_and_rule_firings_resolve_to_real_events(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    collector = mounted_app.config["TELEMETRY_COLLECTOR"]
    operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    records_by_operation = collector.list_events_by_operation([operation.id for operation in operations])
    iocs = [ioc for records in records_by_operation.values() for record in records for ioc in record.iocs]
    assert any(ioc.type == "ip" and re.fullmatch(r"(?:198\.51\.100|203\.0\.113)\.\d{1,3}", ioc.value) for ioc in iocs)
    assert any(ioc.type == "hash" and re.fullmatch(r"[0-9a-f]{64}", ioc.value) for ioc in iocs)

    firings = mounted_app.config["RULE_DECISION_REPOSITORY"].list_firings_for_operations(
        [operation.id for operation in operations]
    )
    event_ids = {operation.id: {record.source_event_id for record in records} for operation, records in ((op, records_by_operation[op.id]) for op in operations)}
    assert all(firing.triggering_event_id in event_ids[operation_id] for operation_id, firing in firings)


def test_seed_demo_creates_apt28_incident_and_tlp_classifications(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    apt28 = next(operation for operation in operations if operation.name.startswith("APT28"))
    apt28_events = {
        event.id
        for event in mounted_app.config["TELEMETRY_COLLECTOR"].list_events(apt28.id)
        if event.plugin_id == "dolost-apt28-finance"
    }
    incidents = mounted_app.config["INCIDENT_REPOSITORY"].list_for_operation(apt28.id)

    assert len(incidents) == 1
    incidente = incidents[0]

    # El incidente tiene que sostener lo que dice su propio nombre. Antes se
    # afirmaba `set(event_ids) == apt28_events` -- con la telemetria de demo a
    # volumen real eso agrupa ~900 eventos de ~180 origenes y 6 TTPs bajo un
    # titulo que nombra una sola IP y notas que hablan de dos observaciones.
    # Se verifica la coherencia, no la cantidad.
    eventos = {
        event.id: event
        for event in mounted_app.config["TELEMETRY_COLLECTOR"].list_events(apt28.id)
    }
    agrupados = [eventos[event_id] for event_id in incidente.event_ids]
    origenes = {event.payload.get("source_ip") for event in agrupados}

    assert agrupados, "El incidente de ejemplo no puede quedar vacio."
    assert set(incidente.event_ids) < apt28_events, "Agrupar todo no es un incidente."
    assert len(origenes) == 1, f"El incidente mezcla origenes: {origenes}"
    assert {event.ttp_id for event in agrupados} == {"T1046", "T1110.001"}
    assert origenes.pop() in incidente.name
    assert str(len(agrupados)) in incidente.notes

    classifications = [
        classification
        for operation in operations
        for classification in mounted_app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation(operation.id)
    ]
    assert {(classification.subject_type, classification.subject_key, classification.level.value) for classification in classifications} == {
        ("ioc", "ip:198.51.100.23", "green"),
        ("ioc", "credential:m.lopez@rrhh.example", "amber"),
        ("ioc", "domain:cdn-sync.example", "red"),
    }


def test_seed_demo_second_run_does_not_duplicate_incidents_or_tlp(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)
        incident_counts_before = {
            operation.id: len(mounted_app.config["INCIDENT_REPOSITORY"].list_for_operation(operation.id))
            for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
        }
        tlp_counts_before = {
            operation.id: len(mounted_app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation(operation.id))
            for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
        }
        second_run = seed_demo.seed_demo_operations(mounted_app)

    assert second_run == []
    assert {
        operation.id: len(mounted_app.config["INCIDENT_REPOSITORY"].list_for_operation(operation.id))
        for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
    } == incident_counts_before
    assert {
        operation.id: len(mounted_app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation(operation.id))
        for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
    } == tlp_counts_before


def test_seed_demo_creates_pending_apt28_gating_criteria(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    apt28 = next(
        operation
        for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
        if operation.name.startswith("APT28")
    )
    conditions = apt28.closure_criteria.trigger_conditions

    assert len(conditions) == 1
    assert conditions[0].event_type.value == "ttp_observed"
    assert conditions[0].plugin_id == "dolost-apt28-finance"
    assert conditions[0].payload == {"ttp_id": "T1021.004"}
    assert apt28.status.value == "active"


def test_seed_demo_second_run_does_not_duplicate_gating_criteria(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)
        apt28 = next(
            operation
            for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
            if operation.name.startswith("APT28")
        )
        conditions_before = list(apt28.closure_criteria.trigger_conditions)
        second_run = seed_demo.seed_demo_operations(mounted_app)

    apt28_after = mounted_app.config["OPERATION_REPOSITORY"].get(apt28.id)
    assert second_run == []
    assert apt28_after.closure_criteria.trigger_conditions == conditions_before


def test_lazarus_seed_has_configured_canarytoken_opencanary_and_breadcrumb(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)
        seed_demo.seed_demo_operations(mounted_app)

    lazarus = next(
        operation
        for operation in mounted_app.config["OPERATION_REPOSITORY"].list()
        if operation.name.startswith("Lazarus Group")
    )
    bindings = {binding.plugin_id: binding for binding in lazarus.plugins}
    canarytoken = bindings["canarytoken-lazarus-exfil"]
    opencanary = bindings["opencanary-lazarus-exfil"]

    assert len(bindings) == 4
    assert _canarytoken_panel_data(canarytoken)["configured"] is True
    assert _opencanary_panel_data(opencanary)["configured"] is True
    assert canarytoken.leads_to_plugin_id == "dolost-lazarus-exfil"
    assert lazarus.find_plugin_binding(canarytoken.leads_to_plugin_id) is not None


def test_seed_demo_running_three_times_still_only_three_operations(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)
        seed_demo.seed_demo_operations(mounted_app)
        seed_demo.seed_demo_operations(mounted_app)

    assert len(list(mounted_app.config["OPERATION_REPOSITORY"].list())) == 3


def test_each_example_operation_has_the_minimum_expected_fields(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    for operation in list(mounted_app.config["OPERATION_REPOSITORY"].list()):
        assert operation.adversary_profile.expected_ttps, operation.name
        assert operation.adversary_profile.motivation, operation.name
        assert operation.roe is not None
        assert operation.scenarios, operation.name
        assert all(scenario.related_ttps for scenario in operation.scenarios), operation.name
        assert operation.plugins, operation.name
        assert operation.narrative.psychological_impact, operation.name
        assert operation.strategic_decisions.objectives, operation.name
        assert operation.strategic_decisions.roles, operation.name


def test_dolost_example_operations_have_a_decoy_configured_inline(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    dolost_bindings = [
        binding
        for operation in list(mounted_app.config["OPERATION_REPOSITORY"].list())
        for binding in operation.plugins
        if binding.plugin_kind == "dolost"
    ]
    assert dolost_bindings
    for binding in dolost_bindings:
        assert binding.config.get("decoys"), binding.plugin_id
        assert binding.config["decoys"][0]["Hostname"]


def test_buda_example_operations_have_a_real_narrative_created(mounted_app):
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

        from BUDA.models import Narrative as BudaNarrative

        buda_bindings = [
            binding
            for operation in list(mounted_app.config["OPERATION_REPOSITORY"].list())
            for binding in operation.plugins
            if binding.plugin_kind == "buda"
        ]
        assert buda_bindings
        for binding in buda_bindings:
            narrative_id = binding.config.get("narrative_id")
            assert narrative_id is not None, binding.plugin_id
            assert buda_db.session.get(BudaNarrative, narrative_id) is not None


def test_at_least_one_example_operation_is_ready_to_demo_the_playground(mounted_app):
    # No hace falta CLOSED (generate_report()/la vista de defensor no lo
    # exigen desde M14f) -- alcanza con que exista y tenga plugins reales.
    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)

    operations = list(mounted_app.config["OPERATION_REPOSITORY"].list())
    assert any(operation.status.value == "active" and operation.plugins for operation in operations)


def test_seed_creates_identity_profiles_with_apate_local_key(tmp_path, monkeypatch):
    """Sin variable, APATE crea una clave estable antes de sembrar BUDA."""

    monkeypatch.delenv("BUDA_CREDENTIAL_ENCRYPTION_KEY", raising=False)
    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-local-key.db'}",
        }
    )
    with app.app_context():
        seed_demo.seed_demo_operations(app)
        assert BudaUserProfile.query.count() == 2
        assert all(profile.credentials_recoverable for profile in BudaUserProfile.query.all())

    assert (tmp_path / "data" / "buda_credential_encryption.key").is_file()


def test_seed_detects_profiles_encrypted_with_another_key(mounted_app, monkeypatch):
    """Si ya hay perfiles que esta clave no puede descifrar, no se siembra
    encima: se avisa. Sembrar mas filas solo agranda el problema."""

    from cryptography.fernet import Fernet

    with mounted_app.app_context():
        seed_demo.seed_demo_operations(mounted_app)
        from BUDA.models import UserProfile

        assert UserProfile.query.count(), "El fixture necesita al menos un perfil sembrado."

    monkeypatch.setenv("BUDA_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())
    from BUDA.utils.crypto_utils import reset_fernet_cache

    reset_fernet_cache()
    try:
        with mounted_app.app_context():
            puede, motivo = seed_demo._buda_credentials_usable()
    finally:
        reset_fernet_cache()

    assert puede is False
    assert "no se pueden descifrar" in motivo
