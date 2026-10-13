"""Resumen de salud operativa basado en comprobaciones, no en ruido de eventos."""

from __future__ import annotations

from datetime import datetime, timezone

from ..deployment import DeploymentStatus


def build_operation_health(records, monitor_status: dict, telemetry_records, *, now: datetime | None = None) -> list[dict]:
    """Distingue recurso, sondeo y actividad; el silencio adversario es normal."""

    instant = now or datetime.now(timezone.utc)
    observed = {}
    for event in telemetry_records:
        observed[event.plugin_id] = event.timestamp.isoformat()
    states = monitor_status.get("records", {})
    interval = float(monitor_status.get("interval_seconds") or 30)
    result = []
    for record in records:
        state = states.get(record.id, {})
        last_success = state.get("last_success")
        last_refresh = state.get("last_refresh")
        error = state.get("last_error") or state.get("last_refresh_error")
        if record.status in {DeploymentStatus.FAILED, DeploymentStatus.DEGRADED} or error:
            health = "degraded"
        elif record.status not in {DeploymentStatus.ACTIVE, DeploymentStatus.APPLYING}:
            health = "inactive"
        elif record.connector_kind == "active-directory-honeyuser" and monitor_status.get("enabled"):
            if not last_success:
                health = "unverified"
            elif (instant - datetime.fromisoformat(last_success)).total_seconds() > 2 * interval:
                health = "stale"
            else:
                health = "healthy"
        else:
            health = "unverified" if not last_refresh else "healthy"
        result.append({"record": record, "health": health, "last_poll": state.get("last_poll"),
                       "last_success": last_success, "last_refresh": last_refresh,
                       "last_refresh_status": state.get("last_refresh_status"), "error": error,
                       "last_observed_event": observed.get(record.plugin_id)})
    return result
