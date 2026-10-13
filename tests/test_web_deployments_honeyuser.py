"""Vertical web: destino -> plan -> confirmación -> AD -> telemetría."""

from datetime import datetime, timezone

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.deployment import (
    ActiveDirectoryHoneyuserConnector,
    ActiveDirectoryLogonEvent,
    ActiveDirectoryUser,
    DeploymentService,
    HoneyuserEventMonitor,
)


class FakeActiveDirectoryTransport:
    def __init__(self):
        self.user = None
        self.events = []

    def validate(self, target, credential, ou_dn):
        assert credential["username"] == r"EXAMPLE\svc-apate"

    def find_user(self, target, credential, sam_account_name):
        return self.user

    def create_or_update_user(self, target, credential, parameters, password):
        self.user = ActiveDirectoryUser(
            sid="S-1-5-21-123-456-789-1001",
            distinguished_name=f"CN={parameters['display_name']},{parameters['ou_dn']}",
            sam_account_name=parameters["sam_account_name"],
            user_principal_name=parameters["user_principal_name"],
            description=parameters["management_marker"],
            enabled=True,
        )
        return self.user

    def get_user(self, target, credential, identity):
        return self.user

    def set_password_and_enable(self, target, credential, identity, password):
        return self.user

    def disable_user(self, target, credential, identity):
        self.user = ActiveDirectoryUser(**{**self.user.__dict__, "enabled": False})
        return self.user

    def logon_events(self, target, credential, **kwargs):
        return self.events


def _operation(app):
    operation = Operation(
        name="Operación identidad",
        adversary_profile=AdversaryProfile(name="APT"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Historia"),
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def _configure_fake_connector(app):
    transport = FakeActiveDirectoryTransport()
    connector = ActiveDirectoryHoneyuserConnector(
        credential_store=app.config["DEPLOYMENT_CREDENTIAL_STORE"],
        transport=transport,
        password_factory=lambda: "Clave-Senuelo-123!",
    )
    app.config["DEPLOYMENT_SERVICE"] = DeploymentService(
        repository=app.config["DEPLOYMENT_REPOSITORY"],
        connectors={connector.kind: connector},
    )
    app.config["HONEYUSER_EVENT_MONITOR"] = HoneyuserEventMonitor(
        connector=connector,
        checkpoint_repository=app.config["HONEYUSER_EVENT_MONITOR"]._checkpoints,
    )
    return transport


def _create_target(client):
    response = client.post(
        "/deployments/targets",
        data={
            "name": "DC principal",
            "address": "dc01.example.test",
            "administrative_username": r"EXAMPLE\svc-apate",
            "administrative_password": "secreto-administrativo",
            "ou_allowlist": "OU=Deception,DC=example,DC=test",
            "allowed_upn_suffixes": "example.test",
            "transport": "ntlm",
            "server_cert_validation": "validate",
        },
    )
    assert response.status_code == 302


def test_target_password_is_encrypted_and_never_rendered(app, client):
    _create_target(client)

    page = client.get("/deployments/targets")
    raw = "".join(path.read_text() for path in (app.config["APATE_DATA_DIR"] / "deployment_credentials").glob("*.json"))

    assert page.status_code == 200
    assert b"secreto-administrativo" not in page.data
    assert "secreto-administrativo" not in raw
    assert app.config["DEPLOYMENT_TARGET_REPOSITORY"].list()[0].credential_ref.startswith("secret://")


def test_administrator_can_rotate_target_service_credential(app, client):
    _create_target(client)
    target = app.config["DEPLOYMENT_TARGET_REPOSITORY"].list()[0]

    response = client.post(
        f"/deployments/targets/{target.id}/credential",
        data={
            "administrative_username": r"EXAMPLE\svc-apate-v2",
            "administrative_password": "nuevo-secreto",
        },
    )

    assert response.status_code == 302
    assert app.config["DEPLOYMENT_CREDENTIAL_STORE"].get(target.credential_ref) == {
        "username": r"EXAMPLE\svc-apate-v2",
        "password": "nuevo-secreto",
    }


def test_complete_honeyuser_flow_publishes_authentication_telemetry(app, client):
    transport = _configure_fake_connector(app)
    operation = _operation(app)
    _create_target(client)
    target = app.config["DEPLOYMENT_TARGET_REPOSITORY"].list()[0]

    prepared = client.post(
        f"/operations/{operation.id}/deployments/honeyuser/prepare",
        data={
            "target_id": target.id,
            "plugin_id": "honeyuser-finanzas",
            "sam_account_name": "laura.fernandez",
            "display_name": "Laura Fernández",
            "given_name": "Laura",
            "surname": "Fernández",
            "ou_dn": "OU=Deception,DC=example,DC=test",
            "upn_suffix": "example.test",
        },
    )
    assert prepared.status_code == 302
    plan = app.config["DEPLOYMENT_REPOSITORY"].list_plans_for_operation(operation.id)[0]
    assert transport.user is None

    executed = client.post(f"/operations/{operation.id}/deployments/plans/{plan.id}/execute")
    record = app.config["DEPLOYMENT_REPOSITORY"].list_records_for_operation(operation.id)[0]
    assert executed.status_code == 302
    assert transport.user.enabled is True

    transport.events = [
        ActiveDirectoryLogonEvent(
            record_id=42,
            event_id=4624,
            timestamp=datetime.now(timezone.utc),
            target_user="laura.fernandez",
            target_sid=transport.user.sid,
            source_ip="203.0.113.50",
            status="0x0",
        )
    ]
    polled = client.post(f"/operations/{operation.id}/deployments/{record.id}/poll")

    telemetry = app.config["TELEMETRY_COLLECTOR"].list_events(operation_id=operation.id)
    assert polled.status_code == 302
    assert len(telemetry) == 1
    assert telemetry[0].payload["kind"] == "honeyuser_authentication_success"
    assert telemetry[0].payload["ttp_id"] == "T1078"

    transport.events.append(
        ActiveDirectoryLogonEvent(
            record_id=43,
            event_id=4625,
            timestamp=datetime.now(timezone.utc),
            target_user="laura.fernandez",
            target_sid=transport.user.sid,
            source_ip="203.0.113.51",
            status="0xc000006a",
        )
    )
    assert app.config["HONEYUSER_MONITORING_SERVICE"].poll_once() == 1
    assert len(app.config["TELEMETRY_COLLECTOR"].list_events(operation.id)) == 2
    monitor = app.config["HONEYUSER_MONITORING_SERVICE"]
    initial_status = monitor.status()
    assert initial_status["records"][record.id]["last_success"]
    assert b"OU=Deception,DC=example,DC=test" in client.get(f"/operations/{operation.id}/deployments").data

    def unavailable(*args, **kwargs):
        raise RuntimeError("DC sin conexión")

    transport.logon_events = unavailable
    assert monitor.poll_once() == 0
    failed_status = monitor.status()
    assert failed_status["records"][record.id]["last_error"] == "RuntimeError"
    assert failed_status["last_success"] == initial_status["last_success"]
    assert b"RuntimeError" in client.get(f"/operations/{operation.id}/deployments").data


def test_cross_operation_record_action_is_hidden(app, client):
    first = _operation(app)
    second = _operation(app)
    _create_target(client)

    assert client.post(f"/operations/{first.id}/deployments/not-a-record/refresh").status_code == 404
    assert client.get(f"/operations/{second.id}/deployments").status_code == 200
