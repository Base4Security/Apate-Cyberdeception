"""Revisión determinista del diseño y de recursos registrados por operación."""

from __future__ import annotations

from ..reporting.dry_run import simulate_dry_run
from ._asset_coverage import build_asset_coverage


def build_readiness(operation, assets, deployment_records, *, source: str,
                    approved_deployment_plan_ids: set[str] | None = None) -> dict:
    """Señala brechas locales; nunca certifica el estado físico remoto."""
    dry_run = simulate_dry_run(operation)
    coverage = build_asset_coverage(operation, assets)
    bindings = {binding.plugin_id for binding in operation.plugins}
    states = {state: 0 for state in (
        "planned", "applying", "active", "degraded", "failed", "rotating", "retiring", "retired")}
    unbound_active = 0
    outside_approved_plan = 0
    for record in deployment_records:
        states[record.status.value] += 1
        if record.status.value in {"applying", "active", "degraded", "rotating", "retiring"}:
            unbound_active += record.plugin_id not in bindings
            if approved_deployment_plan_ids is not None:
                outside_approved_plan += record.plan_id not in approved_deployment_plan_ids
    gaps = sorted({finding.category for finding in dry_run.findings if finding.severity == "gap"})
    return {
        "format": 1,
        "design_source": source,
        "design_gap_categories": gaps,
        "design_gap_count": sum(finding.severity == "gap" for finding in dry_run.findings),
        "target_assets": len(coverage["targets"]),
        "uncovered_target_assets": len(coverage["uncovered"]),
        "unassigned_capabilities": len(coverage["unassigned_capabilities"]),
        "unresolved_asset_references": len(coverage["unresolved_references"]),
        "deployment_states": states,
        "active_resources_without_binding": unbound_active,
        "active_resources_outside_approved_plan": (outside_approved_plan
            if approved_deployment_plan_ids is not None else None),
        "external_validation": "pending",
        "decision": "human_review_required",
    }
