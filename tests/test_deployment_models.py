"""Modelos neutrales del control plane de despliegue."""

from datetime import datetime, timedelta, timezone

import pytest

from apate.deployment import (
    ConnectorResult,
    DeploymentAction,
    DeploymentPlan,
    DeploymentRecord,
    DeploymentStatus,
    DeploymentTarget,
    InvalidDeploymentTransitionError,
    PlannedChange,
)


def _target() -> DeploymentTarget:
    return DeploymentTarget(
        name="Directorio de laboratorio",
        connector_kind="active-directory",
        address="dc-lab.example.test",
        asset_id="asset-ad-1",
        credential_ref="secret://ad/deception-operator",
        config={"ou_allowlist": ["OU=Deception,DC=example,DC=test"]},
    )


def _plan(target: DeploymentTarget | None = None) -> DeploymentPlan:
    target = target or _target()
    return DeploymentPlan(
        operation_id="op-1",
        plugin_id="honeyuser-finanzas",
        target=target,
        changes=[
            PlannedChange(
                action=DeploymentAction.CREATE,
                resource_type="ad_user",
                resource_name="laura.fernandez",
                summary="Crear una identidad señuelo en la OU autorizada.",
            )
        ],
        parameters={"sam_account_name": "laura.fernandez"},
    )


@pytest.mark.parametrize("field", ["name", "connector_kind", "address"])
def test_target_requires_routing_fields(field):
    values = {"name": "AD", "connector_kind": "active-directory", "address": "dc.example.test"}
    values[field] = "   "

    with pytest.raises(ValueError, match=field):
        DeploymentTarget(**values)


def test_target_roundtrip_keeps_asset_and_secret_reference():
    target = _target()

    restored = DeploymentTarget.from_dict(target.to_dict())

    assert restored == target
    assert restored.credential_ref == "secret://ad/deception-operator"


def test_plan_roundtrip_and_destructive_signal():
    target = _target()
    plan = _plan(target)
    plan.changes.append(
        PlannedChange(
            action=DeploymentAction.DELETE,
            resource_type="ad_user",
            resource_name="usuario-viejo",
            summary="Retirar el recurso anterior.",
            destructive=True,
        )
    )

    restored = DeploymentPlan.from_dict(plan.to_dict())

    assert restored == plan
    assert restored.has_destructive_changes


def test_plan_expiration_uses_explicit_clock():
    plan = _plan()
    plan.valid_until = datetime(2026, 9, 12, 12, 0, tzinfo=timezone.utc)

    assert not plan.is_expired(now=plan.valid_until - timedelta(seconds=1))
    assert plan.is_expired(now=plan.valid_until)


def test_record_follows_deploy_rotate_and_retire_lifecycle():
    record = DeploymentRecord.from_plan(_plan())

    record.transition_to(DeploymentStatus.APPLYING)
    record.apply_result(
        ConnectorResult(
            status=DeploymentStatus.ACTIVE,
            detail="Creado.",
            external_resource_ids=["S-1-5-21-123"],
        )
    )
    record.transition_to(DeploymentStatus.ROTATING)
    record.apply_result(
        ConnectorResult(
            status=DeploymentStatus.ACTIVE,
            detail="Rotado.",
            external_resource_ids=["S-1-5-21-123"],
        )
    )
    record.transition_to(DeploymentStatus.RETIRING)
    record.apply_result(ConnectorResult(status=DeploymentStatus.RETIRED, detail="Retirado."))

    assert record.status is DeploymentStatus.RETIRED
    assert record.last_error == ""
    assert DeploymentRecord.from_dict(record.to_dict()) == record


def test_record_rejects_skipping_the_execution_state():
    record = DeploymentRecord.from_plan(_plan())

    with pytest.raises(InvalidDeploymentTransitionError):
        record.transition_to(DeploymentStatus.ACTIVE)


def test_failed_result_preserves_error_detail():
    record = DeploymentRecord.from_plan(_plan())
    record.transition_to(DeploymentStatus.APPLYING)

    record.apply_result(ConnectorResult(status=DeploymentStatus.FAILED, detail="Acceso denegado."))

    assert record.last_error == "Acceso denegado."
