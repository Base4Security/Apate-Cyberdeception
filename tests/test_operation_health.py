"""La salud no confunde silencio del adversario con una fuente caída."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from apate.deployment import DeploymentStatus
from apate.web._operation_health import build_operation_health


def test_health_distinguishes_event_silence_source_failure_and_staleness():
    now = datetime(2026, 9, 15, 12, tzinfo=timezone.utc)
    records = [SimpleNamespace(id=name, plugin_id=name, target_id=name,
                               connector_kind="active-directory-honeyuser", status=DeploymentStatus.ACTIVE)
               for name in ("quiet", "failed", "stale")]
    status = {"enabled": True, "interval_seconds": 30, "records": {
        "quiet": {"last_success": (now - timedelta(seconds=10)).isoformat()},
        "failed": {"last_error": "TimeoutError"},
        "stale": {"last_success": (now - timedelta(seconds=100)).isoformat()},
    }}
    result = build_operation_health(records, status, [], now=now)
    assert [item["health"] for item in result] == ["healthy", "degraded", "stale"]
    assert all(item["last_observed_event"] is None for item in result)


def test_health_page_is_read_only(app, client):
    operation = client.post("/operations/new", data={"name": "Salud", "adversary_name": "APT",
                                                     "narrative_name": "Historia"})
    operation_id = operation.headers["Location"].rsplit("/", 1)[-1]
    before = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation_id)
    response = client.get(f"/operations/{operation_id}/health")
    assert response.status_code == 200
    assert b"Salud de la operaci" in response.data
    assert app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation_id) == before
