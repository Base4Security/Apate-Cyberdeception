from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from apate.deployment import (
    ConnectorResult,
    DeploymentAction,
    DeploymentConnector,
    DeploymentExecutionError,
    DeploymentPlan,
    DeploymentRecord,
    DeploymentService,
    DeploymentStatus,
    DeploymentTarget,
    DeploymentValidationError,
    JSONFileDeploymentRepository,
    PlannedChange,
)


class FakeConnector(DeploymentConnector):
    kind = "fake"

    def __init__(self) -> None:
        self.deploy_calls = 0
        self.fail_deploy = False

    def validate(self, target: DeploymentTarget, configuration: dict[str, Any]) -> None:
        if configuration.get("invalid"):
            raise DeploymentValidationError("Configuración inválida.")

    def plan(self, *, operation_id, plugin_id, target, configuration):
        return DeploymentPlan(
            operation_id=operation_id,
            plugin_id=plugin_id,
            target=target,
            changes=[PlannedChange(DeploymentAction.CREATE, "fake_user", "honey", "Crear honeyuser")],
            parameters=configuration,
        )

    def deploy(self, plan: DeploymentPlan) -> ConnectorResult:
        self.deploy_calls += 1
        if self.fail_deploy:
            raise RuntimeError("Directorio no disponible")
        return ConnectorResult(DeploymentStatus.ACTIVE, "Creado", ["external-1"])

    def status(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        assert plan.id == record.plan_id
        return ConnectorResult(DeploymentStatus.ACTIVE, "Presente", record.external_resource_ids)

    def rotate(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        assert plan.id == record.plan_id
        return ConnectorResult(DeploymentStatus.ACTIVE, "Rotado", record.external_resource_ids)

    def retire(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        assert plan.id == record.plan_id
        return ConnectorResult(DeploymentStatus.RETIRED, "Retirado")


def _target() -> DeploymentTarget:
    return DeploymentTarget(name="Laboratorio", connector_kind="fake", address="lab.example.test")


def _service(tmp_path, connector=None):
    connector = connector or FakeConnector()
    repository = JSONFileDeploymentRepository(tmp_path)
    return DeploymentService(repository=repository, connectors={connector.kind: connector}), connector, repository


def test_prepare_validates_and_persists_the_exact_scope(tmp_path):
    service, _connector, repository = _service(tmp_path)
    target = _target()

    plan = service.prepare(
        operation_id="op-1",
        plugin_id="honeyuser-1",
        target=target,
        configuration={"sam_account_name": "honey.user"},
    )

    assert repository.get_plan(plan.id) == plan
    assert plan.target_id == target.id


def test_prepare_rejects_unknown_connector(tmp_path):
    service, _connector, _repository = _service(tmp_path)
    target = DeploymentTarget(name="AD", connector_kind="missing", address="dc.example.test")

    with pytest.raises(DeploymentValidationError, match="missing"):
        service.prepare(operation_id="op-1", plugin_id="p-1", target=target, configuration={})


def test_prepare_rejects_connector_redirecting_the_target(tmp_path):
    class RedirectingConnector(FakeConnector):
        def plan(self, *, operation_id, plugin_id, target, configuration):
            plan = super().plan(
                operation_id=operation_id,
                plugin_id=plugin_id,
                target=DeploymentTarget.from_dict(target.to_dict()),
                configuration=configuration,
            )
            plan.target.address = "otro-destino.example.test"
            return plan

    connector = RedirectingConnector()
    service, _connector, repository = _service(tmp_path, connector)

    with pytest.raises(DeploymentValidationError, match="fuera del alcance"):
        service.prepare(operation_id="op-1", plugin_id="p-1", target=_target(), configuration={})
    assert not list((tmp_path / "plans").glob("*.json"))


def test_execute_is_idempotent_for_the_same_plan(tmp_path):
    service, connector, _repository = _service(tmp_path)
    plan = service.prepare(operation_id="op-1", plugin_id="p-1", target=_target(), configuration={})

    first = service.execute(plan.id)
    second = service.execute(plan.id)

    assert first.id == second.id
    assert first.status is DeploymentStatus.ACTIVE
    assert first.external_resource_ids == ["external-1"]
    assert connector.deploy_calls == 1


def test_execute_rejects_expired_plan_without_calling_connector(tmp_path):
    service, connector, repository = _service(tmp_path)
    plan = service.prepare(operation_id="op-1", plugin_id="p-1", target=_target(), configuration={})
    plan.valid_until = datetime(2026, 9, 12, 12, tzinfo=timezone.utc)
    repository.save_plan(plan)

    with pytest.raises(DeploymentValidationError, match="venció"):
        service.execute(plan.id, now=plan.valid_until + timedelta(seconds=1))
    assert connector.deploy_calls == 0


def test_execute_persists_failure_before_raising(tmp_path):
    connector = FakeConnector()
    connector.fail_deploy = True
    service, _connector, repository = _service(tmp_path, connector)
    plan = service.prepare(operation_id="op-1", plugin_id="p-1", target=_target(), configuration={})

    with pytest.raises(DeploymentExecutionError, match="Directorio no disponible"):
        service.execute(plan.id)

    record = repository.find_record_for_plan(plan.id)
    assert record is not None
    assert record.status is DeploymentStatus.FAILED
    assert record.last_error == "Directorio no disponible"


def test_refresh_can_reconcile_a_failed_call_that_succeeded_remotely(tmp_path):
    connector = FakeConnector()
    connector.fail_deploy = True
    service, _connector, repository = _service(tmp_path, connector)
    plan = service.prepare(operation_id="op-1", plugin_id="p-1", target=_target(), configuration={})
    with pytest.raises(DeploymentExecutionError):
        service.execute(plan.id)
    record = repository.find_record_for_plan(plan.id)
    assert record is not None

    reconciled = service.refresh(record.id)

    assert reconciled.status is DeploymentStatus.ACTIVE
    assert reconciled.last_error == ""


def test_retry_is_explicit_and_reuses_the_confirmed_plan(tmp_path):
    connector = FakeConnector()
    connector.fail_deploy = True
    service, _connector, repository = _service(tmp_path, connector)
    plan = service.prepare(operation_id="op-1", plugin_id="p-1", target=_target(), configuration={})
    with pytest.raises(DeploymentExecutionError):
        service.execute(plan.id)
    record = repository.find_record_for_plan(plan.id)
    assert record is not None
    connector.fail_deploy = False

    retried = service.retry(record.id)

    assert retried.status is DeploymentStatus.ACTIVE
    assert connector.deploy_calls == 2


def test_retry_rejects_an_active_record(tmp_path):
    service, _connector, _repository = _service(tmp_path)
    plan = service.prepare(operation_id="op-1", plugin_id="p-1", target=_target(), configuration={})
    record = service.execute(plan.id)

    with pytest.raises(DeploymentValidationError, match="estado actual: active"):
        service.retry(record.id)


def test_refresh_rotate_and_retire_share_the_persisted_record(tmp_path):
    service, _connector, repository = _service(tmp_path)
    plan = service.prepare(operation_id="op-1", plugin_id="p-1", target=_target(), configuration={})
    deployed = service.execute(plan.id)

    refreshed = service.refresh(deployed.id)
    rotated = service.rotate(deployed.id)
    retired = service.retire(deployed.id)

    assert refreshed.status is DeploymentStatus.ACTIVE
    assert rotated.status is DeploymentStatus.ACTIVE
    assert retired.status is DeploymentStatus.RETIRED
    assert repository.get_record(deployed.id).status is DeploymentStatus.RETIRED
