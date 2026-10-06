"""Una segunda identidad aprueba únicamente la instantánea registrada."""

import pytest

from apate.deployment.approvals import PlanApprovalRepository
from apate.deployment.models import DeploymentPlan, DeploymentTarget


def _plan(tmp_path):
    target = DeploymentTarget(name="Archivos", connector_kind="filesystem-honeyfile",
                              address=str(tmp_path), config={"allowed_subdirs": ["decoys"]})
    return DeploymentPlan(operation_id="op-1", plugin_id="honeyfile-1", target=target,
                          changes=[], parameters={"relative_path": "decoys/a.txt"})


def test_two_distinct_identities_and_exact_plan(tmp_path):
    repo = PlanApprovalRepository(tmp_path / "approvals.db")
    plan = _plan(tmp_path)
    repo.register(plan, "maker")
    with pytest.raises(ValueError, match="segunda"):
        repo.require_approved(plan)
    with pytest.raises(ValueError, match="autor"):
        repo.approve(plan, "maker")
    repo.approve(plan, "reviewer")
    repo.require_approved(plan)
    plan.parameters["relative_path"] = "decoys/changed.txt"
    with pytest.raises(ValueError, match="cambió"):
        repo.require_approved(plan)


def test_unregistered_and_repeated_approval(tmp_path):
    repo = PlanApprovalRepository(tmp_path / "approvals.db")
    plan = _plan(tmp_path)
    with pytest.raises(ValueError):
        repo.approve(plan, "reviewer")
    repo.register(plan, "maker")
    repo.approve(plan, "reviewer")
    with pytest.raises(ValueError, match="ya fue"):
        repo.approve(plan, "another")
