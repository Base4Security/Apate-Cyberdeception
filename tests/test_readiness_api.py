"""La revisión de diseño respeta el alcance de la API de máquina."""

from datetime import datetime, timedelta, timezone

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.deployment import DeploymentStatus
from apate.web._readiness import build_readiness


def test_readiness_solo_informa_brechas_locales_y_exige_scope(app, client):
    operation = Operation(name="Operación sintética", adversary_profile=AdversaryProfile(
        "Hipótesis", target_assets=["activo-ficticio-sin-cobertura"]),
        roe=RulesOfEngagement(), narrative=Narrative("Ficción"))
    app.config["OPERATION_REPOSITORY"].save(operation)
    before = app.config["OPERATION_REPOSITORY"].get(operation.id).to_dict()
    tokens = app.config["MACHINE_TOKEN_REPOSITORY"]
    expiry = datetime.now(timezone.utc) + timedelta(minutes=10)
    allowed = tokens.create(name="readiness", scopes={"operations:read"},
        operation_ids={operation.id}, expires_at=expiry)
    denied = tokens.create(name="other", scopes={"telemetry:read"},
        operation_ids={operation.id}, expires_at=expiry)
    path = f"/api/v1/operations/{operation.id}/readiness"

    assert client.get(path, headers={"Authorization": f"Bearer {denied}"}).status_code == 403
    response = client.get(path, headers={"Authorization": f"Bearer {allowed}"})
    assert response.status_code == 200
    review = response.json["review"]
    assert review["design_source"] == "draft"
    assert review["external_validation"] == "pending"
    assert review["decision"] == "human_review_required"
    assert review["target_assets"] == 1
    assert review["uncovered_target_assets"] == 1
    assert review["deployment_states"]["active"] == 0
    assert "Operación sintética" not in str(review)
    assert "activo-ficticio-sin-cobertura" not in str(review)
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).to_dict() == before
    assert client.get("/api/v1/operations/otra/readiness",
        headers={"Authorization": f"Bearer {allowed}"}).status_code == 403


def test_readiness_figura_en_openapi():
    from apate.api.openapi import specification

    route = specification()["paths"]["/api/v1/operations/{operation_id}/readiness"]["get"]
    assert route["x-apate-scope"] == "operations:read"


def test_recurso_activo_fuera_del_plan_aprobado_requiere_revision():
    from types import SimpleNamespace

    operation = Operation(name="Prueba", adversary_profile=AdversaryProfile("Hipótesis"),
        roe=RulesOfEngagement(), narrative=Narrative("Ficción"))
    record = SimpleNamespace(status=DeploymentStatus.ACTIVE, plugin_id="sin-binding",
                             plan_id="plan-antiguo")

    review = build_readiness(operation, [], [record], source="approved_plan",
                             approved_deployment_plan_ids={"plan-vigente"})

    assert review["active_resources_without_binding"] == 1
    assert review["active_resources_outside_approved_plan"] == 1
    assert review["external_validation"] == "pending"
