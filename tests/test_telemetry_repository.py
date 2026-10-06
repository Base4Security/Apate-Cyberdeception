from apate.plugins import EventType, PluginEvent
from apate.telemetry import JSONFileTelemetryRepository, TelemetryRecord


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


def test_list_for_operation_empty_when_no_file(tmp_path):
    repo = JSONFileTelemetryRepository(tmp_path)
    assert repo.list_for_operation("no-existe") == []


def test_append_and_list_for_operation(tmp_path):
    repo = JSONFileTelemetryRepository(tmp_path)
    record = _make_record()

    repo.append(record)
    records = repo.list_for_operation("op-1")

    assert len(records) == 1
    assert records[0].id == record.id
    assert records[0].payload == record.payload


def test_append_accumulates_multiple_records_in_order(tmp_path):
    repo = JSONFileTelemetryRepository(tmp_path)
    first = _make_record(payload={"kind": "scan"})
    second = _make_record(payload={"kind": "access"})

    repo.append(first)
    repo.append(second)

    records = repo.list_for_operation("op-1")
    assert [r.payload["kind"] for r in records] == ["scan", "access"]


def test_append_keeps_operations_separate(tmp_path):
    repo = JSONFileTelemetryRepository(tmp_path)
    repo.append(_make_record(operation_id="op-1"))
    repo.append(_make_record(operation_id="op-2"))

    assert len(repo.list_for_operation("op-1")) == 1
    assert len(repo.list_for_operation("op-2")) == 1


def test_records_persist_across_repository_instances(tmp_path):
    repo = JSONFileTelemetryRepository(tmp_path)
    repo.append(_make_record())

    reloaded = JSONFileTelemetryRepository(tmp_path)
    records = reloaded.list_for_operation("op-1")

    assert len(records) == 1
    assert records[0].plugin_id == "honeypot-mock-1"
