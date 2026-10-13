"""Integración web de la edición de Rules of Engagement."""

from apate.core import PluginBinding


def _create_operation(client, **overrides):
    form = {
        "name": "Operación con RoE",
        "adversary_name": "APT ficticio",
        "narrative_name": "Narrativa base",
        "environment": "isolated",
    }
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_update_roe_from_web_persists_action_lists_and_operational_fields(client, app):
    operation_id = _create_operation(client)
    repo = app.config["OPERATION_REPOSITORY"]
    operation = repo.get(operation_id)
    operation.bind_plugin(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    repo.save(operation)

    response = client.post(
        f"/operations/{operation_id}/roe",
        data={
            "allowed_actions": ["deploy", "rotate"],
            "allowed_action_signatures": "transition:closed",
            "forbidden_actions": ["retire"],
            "forbidden_action_signatures": "retire:mock-1",
            "legal_constraints": "No tocar producción\nAprobación jurídica previa",
            "escalation_contact": "soc@example.test",
        },
        follow_redirects=True,
    )

    operation = repo.get(operation_id)
    assert response.status_code == 200
    assert operation.roe.allowed_actions == ["deploy", "rotate", "transition:closed"]
    assert operation.roe.forbidden_actions == ["retire", "retire:mock-1"]
    assert operation.roe.legal_constraints == ["No tocar producción", "Aprobación jurídica previa"]
    assert operation.roe.escalation_contact == "soc@example.test"
    text = response.get_data(as_text=True)
    assert "Allowlist activa" in text
    assert '<option value="mock-1">' in text


def test_empty_allowlist_remains_unrestricted_after_web_edit(client, app):
    operation_id = _create_operation(client)

    client.post(
        f"/operations/{operation_id}/roe",
        data={
            "allowed_action_signatures": "",
            "forbidden_action_signatures": "",
            "legal_constraints": "Revisión humana",
            "escalation_contact": "guardia@example.test",
        },
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.roe.allowed_actions == []
    assert operation.roe.permits("deploy", "deploy:mock-1") is True
    assert operation.roe.permits("retire", "retire:mock-1") is True
