"""La API de máquina no hereda cookies y respeta scopes e idempotencia."""

from datetime import datetime, timedelta, timezone

from apate.api import MachineTokenRepository
from apate.deployment import ActiveDirectoryHoneyuserConnector, DeploymentService, DeploymentTarget


class _PlanningTransport:
    def validate(self, target, credential, ou_dn):
        assert credential["username"] == "svc-apate"

    def find_user(self, target, credential, sam_account_name):
        return None


def _token(app, operation_id, scopes):
    return app.config["MACHINE_TOKEN_REPOSITORY"].create(
        name="integración de prueba", scopes=set(scopes), operation_ids={operation_id},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def _operation(client, name="Operación API"):
    response = client.post("/operations/new", data={"name": name, "adversary_name": "APT", "narrative_name": "Historia"})
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_machine_api_requires_bearer_and_filters_operations(app, client):
    allowed_id = _operation(client)
    other_id = _operation(client, "Otra operación")
    bearer = _token(app, allowed_id, {"operations:read"})
    headers = {"Authorization": f"Bearer {bearer}"}

    assert client.get("/api/v1/operations").status_code == 401
    assert client.get("/api/v1/operations", headers=headers).status_code == 200
    result = client.get("/api/v1/operations", headers=headers).json
    assert [operation["id"] for operation in result["operations"]] == [allowed_id]
    assert client.get(f"/api/v1/operations/{other_id}", headers=headers).status_code == 403
    assert client.get(f"/api/v1/operations/{allowed_id}/telemetry", headers=headers).status_code == 403
    assert client.post(f"/api/v1/operations/{allowed_id}/honeyusers/plans", headers=headers, json={}).status_code == 403
    assert app.config["MACHINE_TOKEN_REPOSITORY"].list_audit()


def test_token_revocation_expiration_and_rate_limit(tmp_path):
    repository = MachineTokenRepository(tmp_path / "machine_tokens.db")
    bearer = repository.create(name="sensor", scopes={"telemetry:read"}, operation_ids={"op-1"},
                               expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
    token = repository.authenticate(bearer)
    assert token is not None and token.permits("telemetry:read", "op-1")
    assert not token.permits("telemetry:read", "op-2")
    assert repository.allow_request(token.id, limit_per_minute=1)
    assert not repository.allow_request(token.id, limit_per_minute=1)
    repository.revoke(token.id)
    assert repository.authenticate(bearer) is None


def test_prepare_plan_idempotency_is_scoped_to_same_request(app, client):
    operation_id = _operation(client)
    connector = ActiveDirectoryHoneyuserConnector(
        credential_store=app.config["DEPLOYMENT_CREDENTIAL_STORE"], transport=_PlanningTransport()
    )
    app.config["DEPLOYMENT_SERVICE"] = DeploymentService(
        repository=app.config["DEPLOYMENT_REPOSITORY"], connectors={connector.kind: connector}
    )
    target = DeploymentTarget(
        name="DC de prueba", connector_kind=connector.kind, address="dc01.example.test",
        config={"ou_allowlist": ["OU=Deception,DC=example,DC=test"], "allowed_upn_suffixes": ["example.test"]},
    )
    target.credential_ref = f"secret://deployment-target/{target.id}/administrative"
    app.config["DEPLOYMENT_CREDENTIAL_STORE"].save(target.credential_ref, {"username": "svc-apate", "password": "test-secret"})
    app.config["DEPLOYMENT_TARGET_REPOSITORY"].save(target)
    target = app.config["DEPLOYMENT_TARGET_REPOSITORY"].list()[0]
    bearer = _token(app, operation_id, {"honeyuser:prepare"})
    headers = {"Authorization": f"Bearer {bearer}", "Idempotency-Key": "plan-finanzas-1"}
    payload = {"target_id": target.id, "plugin_id": "honeyuser-finanzas", "configuration": {
        "sam_account_name": "laura.fernandez", "display_name": "Laura Fernández",
        "given_name": "Laura", "surname": "Fernández",
        "ou_dn": "OU=Deception,DC=example,DC=test", "upn_suffix": "example.test",
    }}
    first = client.post(f"/api/v1/operations/{operation_id}/honeyusers/plans", headers=headers, json=payload)
    again = client.post(f"/api/v1/operations/{operation_id}/honeyusers/plans", headers=headers, json=payload)
    assert first.status_code == again.status_code == 201
    assert first.json == again.json
    assert len(app.config["DEPLOYMENT_REPOSITORY"].list_plans_for_operation(operation_id)) == 1
    changed = {**payload, "plugin_id": "otro"}
    assert client.post(f"/api/v1/operations/{operation_id}/honeyusers/plans", headers=headers, json=changed).status_code == 409
