"""Tests para SQLiteTelemetryRepository -- Fase 4 post-BlackHat (ver
docs/roadmap.md). Mismo patron que test_telemetry_repository.py
(JSONFileTelemetryRepository) para los metodos que ambos backends
comparten via TelemetryRepository, mas los especificos de
list_ttps_by_operation() (la consulta agregada cross-operacion que
motiva esta fase)."""

from apate.plugins import EventType, PluginEvent
from apate.telemetry import SQLiteTelemetryRepository, TelemetryRecord


def _make_record(operation_id: str = "op-1", **overrides) -> TelemetryRecord:
    defaults = dict(
        event_type=EventType.INTERACTION,
        plugin_id="honeypot-mock-1",
        surface="network",
        operation_id=operation_id,
        payload={"kind": "scan", "source_ip": "203.0.113.10"},
    )
    defaults.update(overrides)
    event = PluginEvent(**defaults)
    return TelemetryRecord.from_event(event)


def _db_path(tmp_path):
    return tmp_path / "telemetry.db"


# -- Contrato compartido con JSONFileTelemetryRepository --------------------


def test_list_for_operation_empty_when_no_records(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    assert repo.list_for_operation("no-existe") == []


def test_append_and_list_for_operation(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    record = _make_record(resource_id="decoy:srv-1")

    repo.append(record)
    records = repo.list_for_operation("op-1")

    assert len(records) == 1
    assert records[0].id == record.id
    assert records[0].resource_id == "decoy:srv-1"
    assert records[0].payload == record.payload
    assert records[0].iocs == record.iocs


def test_append_accumulates_multiple_records_in_order(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    first = _make_record(payload={"kind": "scan"})
    second = _make_record(payload={"kind": "access"})

    repo.append(first)
    repo.append(second)

    records = repo.list_for_operation("op-1")
    assert [r.payload["kind"] for r in records] == ["scan", "access"]


def test_append_keeps_operations_separate(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    repo.append(_make_record(operation_id="op-1"))
    repo.append(_make_record(operation_id="op-2"))

    assert len(repo.list_for_operation("op-1")) == 1
    assert len(repo.list_for_operation("op-2")) == 1


def test_records_persist_across_repository_instances(tmp_path):
    path = _db_path(tmp_path)
    repo = SQLiteTelemetryRepository(path)
    repo.append(_make_record())

    reloaded = SQLiteTelemetryRepository(path)
    records = reloaded.list_for_operation("op-1")

    assert len(records) == 1
    assert records[0].plugin_id == "honeypot-mock-1"


def test_constructing_repository_twice_over_same_path_does_not_duplicate_schema(tmp_path):
    # __init__ corre CREATE TABLE IF NOT EXISTS -- confirma que no
    # explota ni pisa datos ya existentes al reabrir el mismo archivo.
    path = _db_path(tmp_path)
    SQLiteTelemetryRepository(path).append(_make_record())
    repo = SQLiteTelemetryRepository(path)

    assert len(repo.list_for_operation("op-1")) == 1


def test_existing_sqlite_schema_is_migrated_additively(tmp_path):
    import sqlite3

    path = _db_path(tmp_path)
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE telemetry_records (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL,
            operation_id TEXT NOT NULL, event_type TEXT NOT NULL,
            plugin_id TEXT NOT NULL, surface TEXT NOT NULL,
            timestamp TEXT NOT NULL, source_event_id TEXT NOT NULL,
            ttp_id TEXT, iocs_json TEXT NOT NULL, payload_json TEXT NOT NULL
        );
        """
    )
    connection.close()

    repo = SQLiteTelemetryRepository(path)
    repo.append(_make_record(resource_id="decoy:migrado"))

    assert repo.list_for_operation("op-1")[0].resource_id == "decoy:migrado"


# -- list_ttps_by_operation(): la consulta agregada nueva de la Fase 4 ------


def test_list_ttps_by_operation_empty_ids_returns_empty_dict(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    assert repo.list_ttps_by_operation([]) == {}


def test_list_ttps_by_operation_no_matching_records(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    assert repo.list_ttps_by_operation(["no-existe"]) == {}


def test_list_ttps_by_operation_ignores_records_without_ttp_id(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    repo.append(_make_record(payload={"kind": "scan"}))  # sin ttp_id

    assert repo.list_ttps_by_operation(["op-1"]) == {}


def test_list_ttps_by_operation_single_operation_sorted_and_deduped(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    repo.append(_make_record(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1595.002"}))
    repo.append(_make_record(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1046"}))
    repo.append(_make_record(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1046"}))  # repetido

    result = repo.list_ttps_by_operation(["op-1"])

    assert result == {"op-1": ["T1046", "T1595.002"]}


def test_list_ttps_by_operation_multiple_operations_in_one_call(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    repo.append(_make_record(operation_id="op-1", event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1046"}))
    repo.append(_make_record(operation_id="op-2", event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1595.002"}))
    repo.append(_make_record(operation_id="op-3", payload={"kind": "scan"}))  # sin ttp_id

    result = repo.list_ttps_by_operation(["op-1", "op-2", "op-3"])

    assert result == {"op-1": ["T1046"], "op-2": ["T1595.002"]}


def test_list_ttps_by_operation_only_returns_requested_operations(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    repo.append(_make_record(operation_id="op-1", event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1046"}))
    repo.append(_make_record(operation_id="op-2", event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1595.002"}))

    result = repo.list_ttps_by_operation(["op-1"])

    assert result == {"op-1": ["T1046"]}


def test_list_for_operations_groups_records_and_preserves_global_insertion_order(tmp_path):
    repo = SQLiteTelemetryRepository(_db_path(tmp_path))
    repo.append(_make_record(operation_id="op-1", payload={"kind": "first"}))
    repo.append(_make_record(operation_id="op-2", payload={"kind": "other"}))
    repo.append(_make_record(operation_id="op-1", payload={"kind": "second"}))

    result = repo.list_for_operations(["op-1", "op-2", "missing"])

    assert [record.payload["kind"] for record in result["op-1"]] == ["first", "second"]
    assert [record.payload["kind"] for record in result["op-2"]] == ["other"]
    assert "missing" not in result


def test_list_for_operations_empty_ids_returns_empty_dict(tmp_path):
    assert SQLiteTelemetryRepository(_db_path(tmp_path)).list_for_operations([]) == {}
