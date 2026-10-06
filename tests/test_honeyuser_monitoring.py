"""Un DC caído no detiene otras fuentes ni declara éxito global."""

from types import SimpleNamespace

from flask import Flask

from apate.deployment import DeploymentStatus
from apate.web._honeyuser_monitoring import HoneyuserMonitoringService


def test_partial_reconciliation_and_poll_failure_are_visible_per_source():
    app = Flask(__name__)
    operation = SimpleNamespace(id="op-1")
    first = SimpleNamespace(id="dc01", connector_kind="active-directory-honeyuser", status=DeploymentStatus.ACTIVE)
    second = SimpleNamespace(id="dc02", connector_kind="active-directory-honeyuser", status=DeploymentStatus.ACTIVE)
    app.config["OPERATION_REPOSITORY"] = SimpleNamespace(list=lambda: [operation])
    app.config["DEPLOYMENT_REPOSITORY"] = SimpleNamespace(list_records_for_operation=lambda _: [first, second])

    def refresh(record_id):
        if record_id == "dc01":
            raise RuntimeError("fuente caída")
        return SimpleNamespace(status=DeploymentStatus.ACTIVE)

    app.config["DEPLOYMENT_SERVICE"] = SimpleNamespace(refresh=refresh)
    monitor = HoneyuserMonitoringService(app, enabled=False)

    def poll(_operation, record):
        if record.id == "dc01":
            raise RuntimeError("fuente caída")
        return ["evento"]

    monitor._poll_record_unlocked = poll
    assert monitor.poll_once() == 1
    state = monitor.status()
    assert state["last_success"] is None
    assert state["records"]["dc01"]["last_error"] == "RuntimeError"
    assert state["records"]["dc01"]["last_refresh_error"] == "RuntimeError"
    assert state["records"]["dc02"]["last_success"]
    assert state["records"]["dc02"]["last_refresh_status"] == "active"

    def recovered_refresh(record_id):
        return SimpleNamespace(status=DeploymentStatus.ACTIVE)

    app.config["DEPLOYMENT_SERVICE"] = SimpleNamespace(refresh=recovered_refresh)
    monitor._poll_record_unlocked = lambda _operation, _record: ["evento"]
    assert monitor.poll_once() == 2
    recovered = monitor.status()
    assert recovered["last_success"]
    assert recovered["records"]["dc01"]["last_error"] is None
