from datetime import datetime, timezone

from apate.telemetry import Incident, JSONFileIncidentRepository


def _make_incident(operation_id: str = "op-1", **overrides) -> Incident:
    defaults = dict(operation_id=operation_id, name="Barrido inicial", event_ids=["e1", "e2"])
    defaults.update(overrides)
    return Incident(**defaults)


def test_incident_to_dict_and_from_dict_roundtrip():
    incident = _make_incident(notes="Escaneo desde la misma IP en dos escenarios.")

    restored = Incident.from_dict(incident.to_dict())

    assert restored.id == incident.id
    assert restored.operation_id == incident.operation_id
    assert restored.name == incident.name
    assert restored.notes == incident.notes
    assert restored.event_ids == incident.event_ids
    assert restored.created_at == incident.created_at
    assert restored.updated_at == incident.updated_at


def test_incident_from_dict_defaults_notes_and_updated_at_when_missing():
    data = {
        "operation_id": "op-1",
        "name": "Sin notas",
        "event_ids": [],
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
    }

    incident = Incident.from_dict(data)

    assert incident.notes == ""
    assert incident.updated_at == incident.created_at


def test_repository_list_for_operation_empty_when_no_file(tmp_path):
    repo = JSONFileIncidentRepository(tmp_path)
    assert repo.list_for_operation("no-existe") == []


def test_repository_save_creates_new_incident(tmp_path):
    repo = JSONFileIncidentRepository(tmp_path)
    incident = _make_incident()

    repo.save(incident)

    incidents = repo.list_for_operation("op-1")
    assert len(incidents) == 1
    assert incidents[0].id == incident.id
    assert incidents[0].event_ids == ["e1", "e2"]


def test_repository_save_upserts_existing_incident_by_id(tmp_path):
    repo = JSONFileIncidentRepository(tmp_path)
    incident = _make_incident()
    repo.save(incident)

    incident.name = "Nombre actualizado"
    incident.event_ids.append("e3")
    repo.save(incident)

    incidents = repo.list_for_operation("op-1")
    assert len(incidents) == 1
    assert incidents[0].name == "Nombre actualizado"
    assert incidents[0].event_ids == ["e1", "e2", "e3"]


def test_repository_save_keeps_operations_separate(tmp_path):
    repo = JSONFileIncidentRepository(tmp_path)
    repo.save(_make_incident(operation_id="op-1"))
    repo.save(_make_incident(operation_id="op-2"))

    assert len(repo.list_for_operation("op-1")) == 1
    assert len(repo.list_for_operation("op-2")) == 1


def test_repository_delete_removes_incident(tmp_path):
    repo = JSONFileIncidentRepository(tmp_path)
    incident = _make_incident()
    repo.save(incident)

    repo.delete("op-1", incident.id)

    assert repo.list_for_operation("op-1") == []


def test_repository_delete_is_idempotent_when_missing(tmp_path):
    repo = JSONFileIncidentRepository(tmp_path)

    repo.delete("op-1", "no-existe")

    assert repo.list_for_operation("op-1") == []


def test_repository_delete_only_removes_matching_incident(tmp_path):
    repo = JSONFileIncidentRepository(tmp_path)
    keep = _make_incident(name="Se queda")
    remove = _make_incident(name="Se borra")
    repo.save(keep)
    repo.save(remove)

    repo.delete("op-1", remove.id)

    remaining = repo.list_for_operation("op-1")
    assert len(remaining) == 1
    assert remaining[0].id == keep.id


def test_incidents_persist_across_repository_instances(tmp_path):
    repo = JSONFileIncidentRepository(tmp_path)
    repo.save(_make_incident())

    reloaded = JSONFileIncidentRepository(tmp_path)
    incidents = reloaded.list_for_operation("op-1")

    assert len(incidents) == 1
    assert incidents[0].name == "Barrido inicial"
