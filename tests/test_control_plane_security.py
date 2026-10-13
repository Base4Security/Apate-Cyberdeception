"""Cruces adversariales entre sesión web, bearer y plano de ejecución."""

import re
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement


def _operation(app, name):
    operation = Operation(name=name, adversary_profile=AdversaryProfile("Hipótesis"),
                          roe=RulesOfEngagement(), narrative=Narrative("Prueba"))
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def _token(app, operation_id, scopes):
    return app.config["MACHINE_TOKEN_REPOSITORY"].create(
        name="prueba adversarial", scopes=set(scopes), operation_ids={operation_id},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1))


@pytest.mark.parametrize("suffix,scope", [
    ("/plans", "plans:propose"),
    ("/plans/plan-falso/activate", "plans:activate"),
    ("/stop", "operations:stop"),
    ("/capabilities/capacidad/deploy", "capabilities:execute"),
    ("/honeyusers/plans", "honeyuser:prepare"),
    ("/honeyusers/plans/plan-falso/execute", "honeyuser:execute"),
])
@pytest.mark.parametrize("denial", ["wrong_operation", "missing_scope"])
def test_bearer_denegado_no_reserva_idempotencia_ni_ejecuta(app, client, suffix, scope, denial):
    allowed = _operation(app, "Permitida")
    forbidden = _operation(app, "Ajena")
    before = app.config["OPERATION_REPOSITORY"].get(forbidden.id).to_dict()
    bearer = (_token(app, allowed.id, {scope}) if denial == "wrong_operation"
              else _token(app, forbidden.id, {"operations:read"}))
    response = client.post(f"/api/v1/operations/{forbidden.id}{suffix}", json={},
                           headers={"Authorization": f"Bearer {bearer}", "Idempotency-Key": "intento-1"})

    assert response.status_code == 403
    with sqlite3.connect(app.config["MACHINE_TOKEN_REPOSITORY"].path) as db:
        assert db.execute("SELECT count(*) FROM idempotency").fetchone()[0] == 0
    assert any(item["status"] == 403 and item["outcome"] == "rejected"
               for item in app.config["MACHINE_TOKEN_REPOSITORY"].list_audit())
    assert app.config["OPERATION_REPOSITORY"].get(forbidden.id).to_dict() == before


@pytest.mark.csrf
@pytest.mark.parametrize("human_path", ["/control/adopt", "/control/plans/plan-falso/approve"])
def test_cookie_y_bearer_no_cruzan_los_dos_planos(app, client, human_path):
    operation = _operation(app, "Separación de identidades")
    bearer = _token(app, operation.id, {"operations:read", "plans:propose"})
    machine_path = f"/api/v1/operations/{operation.id}/plans"

    # La cookie web no autentica una mutación de máquina aunque haya sesión CSRF.
    assert client.post(machine_path, json={}, headers={"Idempotency-Key": "sin-bearer"}).status_code == 401
    # El bearer no da identidad humana ni permite aprobar/adoptar desde la web.
    body = client.get("/").get_data(as_text=True)
    token = re.search(r'name="csrf-token" content="([^"]+)"', body).group(1)
    response = client.post(f"/operations/{operation.id}{human_path}",
                           json={}, headers={"Authorization": f"Bearer {bearer}", "X-CSRF-Token": token})
    assert response.status_code == 409
    assert response.json["error"] == "authenticated_principal_required"
    assert not app.config["OPERATION_EXECUTOR"].managed(operation.id)
    # API sin testigo CSRF es válida únicamente si tiene bearer y scope.
    assert client.get(f"/api/v1/operations/{operation.id}",
                      headers={"Authorization": f"Bearer {bearer}"}).status_code == 200
