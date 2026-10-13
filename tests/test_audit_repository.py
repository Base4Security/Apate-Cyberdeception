import json
from concurrent.futures import ThreadPoolExecutor

from apate.audit import JSONFileOperatorActionRepository, OperatorAction


def _make_action(operation_id: str = "op-1", **overrides) -> OperatorAction:
    defaults = dict(
        operation_id=operation_id,
        action="dolost_deploy",
        operator="fede",
        outcome="success",
        detail="ok",
    )
    defaults.update(overrides)
    return OperatorAction(**defaults)


def test_list_for_operation_empty_when_no_file(tmp_path):
    repo = JSONFileOperatorActionRepository(tmp_path)
    assert repo.list_for_operation("no-existe") == []


def test_append_and_list_for_operation(tmp_path):
    repo = JSONFileOperatorActionRepository(tmp_path)
    action = _make_action()

    repo.append(action)
    actions = repo.list_for_operation("op-1")

    assert len(actions) == 1
    assert actions[0].id == action.id
    assert actions[0].operator == action.operator


def test_append_accumulates_multiple_actions_in_order(tmp_path):
    repo = JSONFileOperatorActionRepository(tmp_path)
    first = _make_action(action="dolost_deploy")
    second = _make_action(action="dolost_retire")

    repo.append(first)
    repo.append(second)

    actions = repo.list_for_operation("op-1")
    assert [a.action for a in actions] == ["dolost_deploy", "dolost_retire"]


def test_append_keeps_operations_separate(tmp_path):
    repo = JSONFileOperatorActionRepository(tmp_path)
    repo.append(_make_action(operation_id="op-1"))
    repo.append(_make_action(operation_id="op-2"))

    assert len(repo.list_for_operation("op-1")) == 1
    assert len(repo.list_for_operation("op-2")) == 1


def test_actions_persist_across_repository_instances(tmp_path):
    repo = JSONFileOperatorActionRepository(tmp_path)
    repo.append(_make_action())

    reloaded = JSONFileOperatorActionRepository(tmp_path)
    actions = reloaded.list_for_operation("op-1")

    assert len(actions) == 1
    assert actions[0].operator == "fede"


def test_concurrent_appends_preserve_every_action_and_hash_link(tmp_path):
    repos = [JSONFileOperatorActionRepository(tmp_path) for _ in range(3)]
    actions = [_make_action(action=f"action-{index}") for index in range(24)]

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(repos[index % 3].append, action) for index, action in enumerate(actions)]
        for future in futures:
            future.result()

    stored = repos[0].list_for_operation("op-1")
    assert {action.id for action in stored} == {action.id for action in actions}
    assert len(stored) == len(actions)
    assert repos[0].verify("op-1").status == "valid"


def test_verify_accepts_an_intact_hash_chain(tmp_path):
    repo = JSONFileOperatorActionRepository(tmp_path)
    repo.append(_make_action(action="deploy"))
    repo.append(_make_action(action="retire"))

    verification = repo.verify("op-1")

    assert verification.status == "valid"
    assert verification.is_valid


def test_verify_detects_tampered_entry(tmp_path):
    repo = JSONFileOperatorActionRepository(tmp_path)
    repo.append(_make_action())
    path = tmp_path / "op-1.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data[0]["detail"] = "alterado a mano"
    path.write_text(json.dumps(data), encoding="utf-8")

    verification = repo.verify("op-1")

    assert verification.status == "broken"
    assert verification.broken_index == 0


def test_verify_detects_deleted_entry_that_breaks_the_link(tmp_path):
    repo = JSONFileOperatorActionRepository(tmp_path)
    repo.append(_make_action(action="uno"))
    repo.append(_make_action(action="dos"))
    repo.append(_make_action(action="tres"))
    path = tmp_path / "op-1.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data[1]
    path.write_text(json.dumps(data), encoding="utf-8")

    verification = repo.verify("op-1")

    assert verification.status == "broken"
    assert verification.broken_index == 1


def test_verify_distinguishes_legacy_entries_without_chain(tmp_path):
    action = _make_action()
    (tmp_path / "op-1.json").write_text(json.dumps([action.to_dict()]), encoding="utf-8")

    verification = JSONFileOperatorActionRepository(tmp_path).verify("op-1")

    assert verification.status == "no_chain"
