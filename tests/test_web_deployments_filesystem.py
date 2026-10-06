"""La interfaz confirma el plan antes de escribir un honeyfile."""

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement


def test_web_honeyfile_requires_confirmed_plan(app, client, tmp_path):
    root = tmp_path / "share"
    (root / "finance").mkdir(parents=True)
    operation = Operation(name="Operación archivos", adversary_profile=AdversaryProfile(name="APT"),
                          roe=RulesOfEngagement(), narrative=Narrative(name="Historia"))
    app.config["OPERATION_REPOSITORY"].save(operation)
    response = client.post("/deployments/targets/filesystem", data={
        "name": "SMB Finanzas", "address": str(root), "allowed_subdirs": "finance"})
    assert response.status_code == 302
    target = next(target for target in app.config["DEPLOYMENT_TARGET_REPOSITORY"].list()
                  if target.connector_kind == "filesystem-honeyfile")
    page = client.get(f"/operations/{operation.id}/deployments")
    assert b"Preparar honeyfile" in page.data
    response = client.post(f"/operations/{operation.id}/deployments/honeyfile/prepare", data={
        "target_id": target.id, "plugin_id": "honeyfile-finanzas",
        "relative_path": "finance/credenciales.txt", "content": "usuario=demo",
        "rotation_content": "usuario=rotado"})
    assert response.status_code == 302
    assert not (root / "finance" / "credenciales.txt").exists()
    plan = app.config["DEPLOYMENT_REPOSITORY"].list_plans_for_operation(operation.id)[0]
    page = client.get(f"/operations/{operation.id}/deployments")
    assert b"Confirmar y crear archivo" in page.data
    response = client.post(f"/operations/{operation.id}/deployments/plans/{plan.id}/execute")
    assert response.status_code == 302
    assert (root / "finance" / "credenciales.txt").read_text(encoding="utf-8") == "usuario=demo"
