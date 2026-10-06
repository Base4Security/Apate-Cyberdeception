import pytest

from apate.core import (
    AdversaryProfile,
    JSONFileOperationRepository,
    Narrative,
    Operation,
    OperationNotFoundError,
    RulesOfEngagement,
)


def _make_operation(name: str = "Operacion de prueba") -> Operation:
    return Operation(
        name=name,
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


def test_save_and_get(tmp_path):
    repo = JSONFileOperationRepository(tmp_path)
    op = _make_operation()

    repo.save(op)
    fetched = repo.get(op.id)

    assert fetched.id == op.id
    assert fetched.name == op.name


def test_get_missing_raises(tmp_path):
    repo = JSONFileOperationRepository(tmp_path)
    with pytest.raises(OperationNotFoundError):
        repo.get("no-existe")


def test_list_returns_all_saved(tmp_path):
    repo = JSONFileOperationRepository(tmp_path)
    op1 = _make_operation("Operacion 1")
    op2 = _make_operation("Operacion 2")
    repo.save(op1)
    repo.save(op2)

    names = sorted(op.name for op in repo.list())
    assert names == ["Operacion 1", "Operacion 2"]


def test_save_is_upsert(tmp_path):
    repo = JSONFileOperationRepository(tmp_path)
    op = _make_operation()
    repo.save(op)

    op.mark_active()
    repo.save(op)

    fetched = repo.get(op.id)
    assert fetched.status.value == "active"
    assert len(list(repo.list())) == 1


def test_delete(tmp_path):
    repo = JSONFileOperationRepository(tmp_path)
    op = _make_operation()
    repo.save(op)

    repo.delete(op.id)

    with pytest.raises(OperationNotFoundError):
        repo.get(op.id)


def test_delete_missing_raises(tmp_path):
    repo = JSONFileOperationRepository(tmp_path)
    with pytest.raises(OperationNotFoundError):
        repo.delete("no-existe")
