"""Integración: `GET /operations/<id>/tree.graphml` -- descarga del
árbol de la operación como GraphML (tercera de la tanda de mejoras de
UI/UX con referencia CounterCraft, ver docs/roadmap.md)."""

import xml.etree.ElementTree as ET

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario

_NS = {"g": "http://graphml.graphdrawing.org/xmlns"}


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación exportable"),
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def test_download_responds_with_xml_content_type_and_graphml_filename(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}/tree.graphml")

    assert response.status_code == 200
    assert response.mimetype == "application/xml"
    assert response.headers["Content-Disposition"] == f'attachment; filename="arbol-{operation.id}.graphml"'


def test_download_body_is_valid_graphml_with_real_data(client, app):
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network", scenario_id=scenario.id)
    )
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}/tree.graphml")

    root = ET.fromstring(response.get_data(as_text=True))
    nodes = {node.get("id") for node in root.findall(".//g:node", _NS)}
    assert nodes == {"root", f"scenario:{scenario.id}", "capability:mock-1"}


def test_download_404s_for_unknown_operation(client, app):
    response = client.get("/operations/no-existe/tree.graphml")
    assert response.status_code == 404


def test_download_button_present_in_operation_tree_section(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    body = client.get(f"/operations/{operation.id}").get_data(as_text=True)

    assert f'/operations/{operation.id}/tree.graphml' in body
    assert "Descargar GraphML (Gephi)" in body
