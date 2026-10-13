from datetime import datetime, timezone

from apate.telemetry import JSONFileTlpClassificationRepository, TlpClassification, TlpLevel, ioc_subject_key


def _make_classification(**overrides) -> TlpClassification:
    defaults = dict(operation_id="op-1", subject_type="event", subject_key="evt-1", level=TlpLevel.AMBER)
    defaults.update(overrides)
    return TlpClassification(**defaults)


def test_ioc_subject_key_combines_type_and_value():
    assert ioc_subject_key("ip", "1.2.3.4") == "ip:1.2.3.4"


def test_classification_to_dict_and_from_dict_roundtrip():
    classification = _make_classification(set_by="ana")

    restored = TlpClassification.from_dict(classification.to_dict())

    assert restored.operation_id == classification.operation_id
    assert restored.subject_type == classification.subject_type
    assert restored.subject_key == classification.subject_key
    assert restored.level == classification.level
    assert restored.set_by == classification.set_by
    assert restored.set_at == classification.set_at


def test_to_dict_serializes_level_as_plain_string():
    classification = _make_classification(level=TlpLevel.RED)
    assert classification.to_dict()["level"] == "red"


def test_from_dict_defaults_set_by_when_missing():
    data = {
        "operation_id": "op-1",
        "subject_type": "ioc",
        "subject_key": "ip:1.2.3.4",
        "level": "green",
        "set_at": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
    }

    classification = TlpClassification.from_dict(data)

    assert classification.set_by == ""
    assert classification.level == TlpLevel.GREEN


def test_repository_list_for_operation_empty_when_no_file(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)
    assert repo.list_for_operation("no-existe") == []


def test_repository_save_creates_new_classification(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)
    classification = _make_classification()

    repo.save(classification)

    saved = repo.list_for_operation("op-1")
    assert len(saved) == 1
    assert saved[0].subject_key == "evt-1"
    assert saved[0].level == TlpLevel.AMBER


def test_repository_save_upserts_by_subject_not_append_only(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)
    repo.save(_make_classification(level=TlpLevel.AMBER))

    repo.save(_make_classification(level=TlpLevel.RED))

    saved = repo.list_for_operation("op-1")
    assert len(saved) == 1
    assert saved[0].level == TlpLevel.RED


def test_repository_save_keeps_event_and_ioc_subjects_separate_even_with_same_key(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)
    repo.save(_make_classification(subject_type="event", subject_key="shared-key", level=TlpLevel.RED))
    repo.save(_make_classification(subject_type="ioc", subject_key="shared-key", level=TlpLevel.GREEN))

    saved = repo.list_for_operation("op-1")
    assert len(saved) == 2
    levels = {c.subject_type: c.level for c in saved}
    assert levels == {"event": TlpLevel.RED, "ioc": TlpLevel.GREEN}


def test_repository_save_keeps_operations_separate(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)
    repo.save(_make_classification(operation_id="op-1"))
    repo.save(_make_classification(operation_id="op-2"))

    assert len(repo.list_for_operation("op-1")) == 1
    assert len(repo.list_for_operation("op-2")) == 1


def test_repository_clear_removes_classification(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)
    repo.save(_make_classification())

    repo.clear("op-1", "event", "evt-1")

    assert repo.list_for_operation("op-1") == []


def test_repository_clear_is_idempotent_when_missing(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)

    repo.clear("op-1", "event", "no-existe")

    assert repo.list_for_operation("op-1") == []


def test_repository_clear_only_removes_matching_subject(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)
    repo.save(_make_classification(subject_type="event", subject_key="evt-1"))
    repo.save(_make_classification(subject_type="event", subject_key="evt-2"))

    repo.clear("op-1", "event", "evt-1")

    remaining = repo.list_for_operation("op-1")
    assert len(remaining) == 1
    assert remaining[0].subject_key == "evt-2"


def test_classifications_persist_across_repository_instances(tmp_path):
    repo = JSONFileTlpClassificationRepository(tmp_path)
    repo.save(_make_classification())

    reloaded = JSONFileTlpClassificationRepository(tmp_path)
    saved = reloaded.list_for_operation("op-1")

    assert len(saved) == 1
    assert saved[0].level == TlpLevel.AMBER
