from datetime import datetime, timezone

import pytest

from apate.deployment import (
    DeploymentAction,
    DeploymentNotFoundError,
    DeploymentPlan,
    DeploymentRecord,
    DeploymentValidationError,
    JSONFileDeploymentRepository,
    PlannedChange,
)


def _plan(operation_id: str = "op-1") -> DeploymentPlan:
    from apate.deployment import DeploymentTarget

    return DeploymentPlan(
        operation_id=operation_id,
        plugin_id="honeyuser-1",
        target=DeploymentTarget(
            id="target-1",
            name="Directorio",
            connector_kind="active-directory",
            address="dc.example.test",
        ),
        changes=[PlannedChange(DeploymentAction.CREATE, "ad_user", "honey.user", "Crear usuario")],
        created_at=datetime(2026, 9, 12, tzinfo=timezone.utc),
    )


def test_plan_and_record_persist_across_instances(tmp_path):
    first = JSONFileDeploymentRepository(tmp_path)
    plan = _plan()
    record = DeploymentRecord.from_plan(plan)
    first.save_plan(plan)
    first.save_record(record)

    reloaded = JSONFileDeploymentRepository(tmp_path)

    assert reloaded.get_plan(plan.id) == plan
    assert reloaded.get_record(record.id) == record
    assert reloaded.find_record_for_plan(plan.id) == record


def test_list_records_keeps_operations_separate(tmp_path):
    repository = JSONFileDeploymentRepository(tmp_path)
    first = DeploymentRecord.from_plan(_plan("op-1"))
    second = DeploymentRecord.from_plan(_plan("op-2"))
    repository.save_record(first)
    repository.save_record(second)

    assert repository.list_records_for_operation("op-1") == [first]


def test_list_plans_keeps_operations_separate(tmp_path):
    repository = JSONFileDeploymentRepository(tmp_path)
    first = _plan("op-1")
    second = _plan("op-2")
    repository.save_plan(first)
    repository.save_plan(second)

    assert repository.list_plans_for_operation("op-1") == [first]


def test_missing_plan_and_record_raise_typed_error(tmp_path):
    repository = JSONFileDeploymentRepository(tmp_path)

    with pytest.raises(DeploymentNotFoundError):
        repository.get_plan("missing")
    with pytest.raises(DeploymentNotFoundError):
        repository.get_record("missing")


@pytest.mark.parametrize("identifier", ["../outside", "a/b", "a\\b", "", "x" * 129])
def test_repository_rejects_identifiers_that_could_escape_its_directory(tmp_path, identifier):
    repository = JSONFileDeploymentRepository(tmp_path)

    with pytest.raises(DeploymentValidationError):
        repository.get_plan(identifier)
