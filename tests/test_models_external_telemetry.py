"""Tests para `ExternalTelemetrySource` (puente de telemetría externo
configurable, primera de una tanda de tres tareas para ampliar el
ecosistema de herramientas que APATE orquesta). Ver docstring de
`ExternalTelemetrySource`/`apate.telemetry.external_bridge` para el
diseño completo.

Aditivo: cubre el roundtrip normal y, sobre todo, que una `Operation`
persistida ANTES de este campo (sin la clave `telemetry_bridges` en su
JSON) siga cargando con `telemetry_bridges == []` -- mismo criterio que
`leads_to_plugin_id` (breadcrumbs)/`plugin_kind` (M12h)."""

from __future__ import annotations

from datetime import datetime, timezone

from apate.core import AdversaryProfile, ExternalTelemetrySource, Narrative, Operation, RulesOfEngagement


def _operation(**overrides) -> Operation:
    defaults = dict(
        name="Operación de prueba",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


# -- Defaults y roundtrip -----------------------------------------------------


def test_defaults():
    source = ExternalTelemetrySource(name="T-Pot demo", elastic_url="http://localhost:9200", index="tpot-*")

    assert source.surface == "network"
    assert source.timestamp_field == "@timestamp"
    assert source.field_mapping == {}
    assert source.last_fetch_at is None
    assert source.id


def test_roundtrip():
    source = ExternalTelemetrySource(
        name="T-Pot demo",
        elastic_url="http://localhost:9200",
        index="tpot-*",
        surface="host",
        timestamp_field="event.created",
        field_mapping={"ttp_id": "mitre.technique_id", "detail": "message"},
        last_fetch_at=datetime(2026, 8, 21, 10, 0, tzinfo=timezone.utc),
    )

    restored = ExternalTelemetrySource.from_dict(source.to_dict())

    assert restored.name == "T-Pot demo"
    assert restored.elastic_url == "http://localhost:9200"
    assert restored.index == "tpot-*"
    assert restored.surface == "host"
    assert restored.timestamp_field == "event.created"
    assert restored.field_mapping == {"ttp_id": "mitre.technique_id", "detail": "message"}
    assert restored.last_fetch_at == datetime(2026, 8, 21, 10, 0, tzinfo=timezone.utc)
    assert restored.id == source.id


def test_from_dict_without_optional_keys_uses_defaults():
    minimal = {"name": "X", "elastic_url": "http://x", "index": "y*"}

    restored = ExternalTelemetrySource.from_dict(minimal)

    assert restored.surface == "network"
    assert restored.timestamp_field == "@timestamp"
    assert restored.field_mapping == {}
    assert restored.last_fetch_at is None


# -- Operation: composición, resolución, compatibilidad hacia atrás ----------


def test_add_telemetry_bridge():
    operation = _operation()
    source = ExternalTelemetrySource(name="X", elastic_url="http://x", index="y*")

    operation.add_telemetry_bridge(source)

    assert operation.telemetry_bridges == [source]


def test_find_telemetry_bridge_resolves_existing():
    operation = _operation()
    source = ExternalTelemetrySource(name="X", elastic_url="http://x", index="y*")
    operation.add_telemetry_bridge(source)

    assert operation.find_telemetry_bridge(source.id) is source


def test_find_telemetry_bridge_none_for_none_id():
    operation = _operation()
    assert operation.find_telemetry_bridge(None) is None


def test_find_telemetry_bridge_none_for_nonexistent_id():
    operation = _operation()
    assert operation.find_telemetry_bridge("no-existe") is None


def test_operation_to_dict_includes_telemetry_bridges():
    operation = _operation()
    operation.add_telemetry_bridge(ExternalTelemetrySource(name="X", elastic_url="http://x", index="y*"))

    assert len(operation.to_dict()["telemetry_bridges"]) == 1


def test_operation_roundtrip_with_telemetry_bridges():
    operation = _operation()
    operation.add_telemetry_bridge(
        ExternalTelemetrySource(
            name="T-Pot demo", elastic_url="http://localhost:9200", index="tpot-*", field_mapping={"ttp_id": "mitre.id"}
        )
    )

    restored = Operation.from_dict(operation.to_dict())

    assert len(restored.telemetry_bridges) == 1
    assert restored.telemetry_bridges[0].name == "T-Pot demo"
    assert restored.telemetry_bridges[0].field_mapping == {"ttp_id": "mitre.id"}


def test_operation_from_dict_without_telemetry_bridges_key_defaults_to_empty_list():
    # Simula una Operation persistida ANTES de este campo -- mismo
    # formato "legacy" que ya usan test_models_breadcrumbs.py/
    # test_models_m10.py, sin la clave nueva en absoluto.
    legacy_dict = {
        "id": "legacy-op-1",
        "name": "Operación legacy",
        "status": "planning",
        "adversary_profile": {"name": "Actor"},
        "roe": {},
        "narrative": {"name": "N"},
        "scenarios": [],
        "plugins": [],
    }

    restored = Operation.from_dict(legacy_dict)

    assert restored.telemetry_bridges == []


def test_json_file_repository_loads_legacy_operation_without_telemetry_bridges(tmp_path):
    import json

    from apate.core.repository import JSONFileOperationRepository

    operation_id = "legacy-op-2"
    legacy_operation = {
        "id": operation_id,
        "name": "Operación legacy",
        "status": "planning",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "closed_at": None,
        "adversary_profile": {"name": "Actor", "motivation": "", "skill_level": "unknown", "expected_ttps": [], "target_assets": [], "notes": ""},
        "roe": {"environment": "isolated", "allowed_actions": [], "forbidden_actions": [], "legal_constraints": "", "escalation_contact": ""},
        "narrative": {"name": "N", "description": "", "psychological_impact": ""},
        "scenarios": [],
        "plugins": [],
        "closure_criteria": {"end_date": None, "conditions": []},
        "strategic_decisions": {"objectives": [], "roles": {}, "resource_estimate": ""},
        "behavior_context_source_ids": [],
    }
    repo = JSONFileOperationRepository(tmp_path)
    (tmp_path / f"{operation_id}.json").write_text(json.dumps(legacy_operation), encoding="utf-8")

    operation = repo.get(operation_id)

    assert operation.telemetry_bridges == []
