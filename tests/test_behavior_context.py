"""Contrato de las fuentes reutilizables de contexto de comportamiento."""

import json

import pytest

from apate.core import (
    AdversaryProfile,
    BehaviorContextSource,
    BehaviorContextStatus,
    JSONFileBehaviorContextRepository,
    Narrative,
    Operation,
    RulesOfEngagement,
)


def _operation() -> Operation:
    return Operation(
        name="Operación con contexto",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


def test_source_records_fingerprint_and_refuses_tampered_confirmation():
    source = BehaviorContextSource(
        name="Inicio de sesión",
        data={"usernames": ["alice"]},
        provenance="EVTX:audit.evtx",
    )

    assert source.status == BehaviorContextStatus.PENDING
    assert source.integrity_ok
    source.data["usernames"].append("mallory")
    assert not source.integrity_ok
    with pytest.raises(ValueError, match="integridad"):
        source.confirm()


def test_source_confirmation_and_archive_preserve_data():
    data = {"work_hours": {"alice": [8, 17]}}
    source = BehaviorContextSource(name="Turnos", data=data, provenance="EVTX:turnos.evtx")

    source.confirm()
    assert source.status == BehaviorContextStatus.ACTIVE
    assert source.confirmed_at is not None
    assert source.data == data

    source.archive()
    assert source.status == BehaviorContextStatus.ARCHIVED
    assert source.archived_at is not None
    assert source.data == data


def test_repository_roundtrip_and_physical_delete_only_for_pending(tmp_path):
    repository = JSONFileBehaviorContextRepository(tmp_path / "sources")
    pending = BehaviorContextSource(name="Pendiente", data={"a": 1}, provenance="prueba")
    repository.save(pending)
    assert repository.get(pending.id).to_dict() == pending.to_dict()

    pending.confirm()
    repository.save(pending)
    with pytest.raises(ValueError, match="pendientes"):
        repository.delete_pending(pending.id)
    assert repository.get(pending.id).status == BehaviorContextStatus.ACTIVE

    discardable = BehaviorContextSource(name="Descartable", data={}, provenance="prueba")
    repository.save(discardable)
    repository.delete_pending(discardable.id)
    with pytest.raises(KeyError):
        repository.get(discardable.id)


def test_legacy_context_is_copied_once_without_deleting_original(tmp_path):
    legacy = tmp_path / "context.json"
    legacy.write_text(json.dumps({"usernames": ["legacy"]}), encoding="utf-8")
    repository = JSONFileBehaviorContextRepository(tmp_path / "sources")

    first = repository.import_legacy(legacy)
    second = repository.import_legacy(legacy)

    assert first is not None and second is not None
    assert first.id == second.id
    assert first.status == BehaviorContextStatus.ACTIVE
    assert first.data == {"usernames": ["legacy"]}
    assert legacy.exists()
    assert len(list(repository.list())) == 1


def test_legacy_non_object_is_ignored_without_deleting_original(tmp_path):
    legacy = tmp_path / "context.json"
    legacy.write_text('["not", "an", "object"]', encoding="utf-8")
    repository = JSONFileBehaviorContextRepository(tmp_path / "sources")

    assert repository.import_legacy(legacy) is None
    assert legacy.exists()
    assert list(repository.list()) == []


def test_operation_selection_is_explicit_deduplicated_and_serializable():
    operation = _operation()
    operation.select_behavior_context(["source-a", "source-b", "source-a"])

    assert operation.behavior_context_source_ids == ["source-a", "source-b"]
    restored = Operation.from_dict(operation.to_dict())
    assert restored.behavior_context_source_ids == ["source-a", "source-b"]


def test_old_operation_document_defaults_to_no_context_selection():
    document = _operation().to_dict()
    document.pop("behavior_context_source_ids")

    assert Operation.from_dict(document).behavior_context_source_ids == []
