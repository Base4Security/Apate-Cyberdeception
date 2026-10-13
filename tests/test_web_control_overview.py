"""El resumen visual no confunde el borrador con la autoridad aprobada."""

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement


def test_control_overview_is_read_only_and_reports_draft_difference(app, client):
    operation = Operation(name="Plan original", adversary_profile=AdversaryProfile("APT"),
                          narrative=Narrative("Contenido privado"), roe=RulesOfEngagement())
    app.config["OPERATION_REPOSITORY"].save(operation)
    app.config["APATE_RULES_PATH"].write_text("rules: []\n", encoding="utf-8")
    service = app.config["OPERATION_PLAN_SERVICE"]
    service.adopt(operation.id, actor="admin")
    plan = service.propose(operation.id, parent_id=None, reason="Diseño inicial", actor="autor",
                           execution_policy={"contract": 1, "budget_window": operation.id,
                                             "modification_limit": 3, "max_attempts": 2,
                                             "autonomous": False, "query_limit": 10, "query_autonomous": False})
    service.ledger.approve(operation.id, plan["id"], expected_digest=plan["digest"], actor="revisor")
    service.ledger.activate(operation.id, plan["id"], expected_digest=plan["digest"], actor="admin")

    anonymous_detail = client.get(f"/operations/{operation.id}")
    assert anonymous_detail.status_code == 200
    assert b"control/overview" not in anonymous_detail.data
    app.config["IDENTITY_PROVIDER"].create("Admin", "Clave-de-prueba")
    assert client.post("/login", data={"display_name": "Admin", "password": "Clave-de-prueba"}).status_code == 302
    assert b"control/overview" in client.get(f"/operations/{operation.id}").data

    initial = client.get(f"/operations/{operation.id}/control/overview")
    assert initial.status_code == 200
    assert plan["digest"].encode() in initial.data
    assert b"0 secci" in initial.data
    assert b"Contenido privado" not in initial.data

    operation.name = "Borrador distinto"
    app.config["OPERATION_REPOSITORY"].save(operation)
    changed = client.get(f"/operations/{operation.id}/control/overview")
    assert changed.status_code == 200
    assert b"1 secci" in changed.data
    assert b"Camb" in changed.data
    assert b"Contenido privado" not in changed.data
    assert b"name=approve" not in changed.data
