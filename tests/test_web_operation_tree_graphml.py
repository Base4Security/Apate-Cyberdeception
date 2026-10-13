"""`apate.web._operation_tree_graphml.operation_tree_to_graphml()` --
export GraphML del árbol de la operación (tercera de la tanda de
mejoras de UI/UX con referencia CounterCraft, ver docs/roadmap.md).
Mismo criterio que `tests/test_reporting_stix.py`: fixtures de
`Operation`/`PluginBinding` reales, sin mocks."""

import xml.etree.ElementTree as ET

from apate.core import AdversaryProfile, DeceptionEffect, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario
from apate.web._operation_tree import build_operation_tree
from apate.web._operation_tree_graphml import operation_tree_to_graphml

_NS = {"g": "http://graphml.graphdrawing.org/xmlns"}


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación del grafo"),
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def _tree(operation, telemetry_records=None, **panels):
    return build_operation_tree(
        operation,
        telemetry_records or [],
        dolost_panels=panels.get("dolost_panels", {}),
        buda_panels=panels.get("buda_panels", {}),
        honeytoken_panels=panels.get("honeytoken_panels", {}),
    )


def _graphml(operation, tree):
    return operation_tree_to_graphml(operation, tree)


def _nodes(root):
    return {node.get("id"): {d.get("key"): d.text for d in node} for node in root.findall(".//g:node", _NS)}


def _edges(root):
    return [
        {"id": edge.get("id"), "source": edge.get("source"), "target": edge.get("target"), **{d.get("key"): d.text for d in edge}}
        for edge in root.findall(".//g:edge", _NS)
    ]


def test_output_is_well_formed_xml_and_parses_with_elementtree():
    operation = _operation()
    tree = _tree(operation)

    xml_text = operation_tree_to_graphml(operation, tree)

    root = ET.fromstring(xml_text)
    assert root.tag == "{http://graphml.graphdrawing.org/xmlns}graphml"


def test_every_data_key_used_is_declared_in_a_key_element():
    """El requisito no negociable de GraphML: cada <data key="..."> usado
    en el documento tiene que corresponder a un <key id="..."> declarado
    antes -- si no, Gephi importa el grafo pero ignora el atributo en
    silencio."""

    operation = _operation()
    scenario = Scenario(description="Acceso inicial", related_ttps=["T1078"])
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            scenario_id=scenario.id,
            config={"decoys": [{"Hostname": "srv1"}]},
            effect=DeceptionEffect(engage_activity_ids=["EAC0001"]),
        )
    )
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))
    declared_keys = {key.get("id") for key in root.findall("g:key", _NS)}
    used_keys = {
        data.get("key")
        for element in (*root.findall(".//g:node", _NS), *root.findall(".//g:edge", _NS))
        for data in element.findall("g:data", _NS)
    }
    assert used_keys
    assert used_keys <= declared_keys


def test_empty_operation_still_produces_only_the_root_node():
    operation = _operation()
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    nodes = _nodes(root)
    assert list(nodes.keys()) == ["root"]
    assert nodes["root"]["n_label"] == operation.name
    assert nodes["root"]["n_node_type"] == "operation"
    assert root.findall(".//g:edge", _NS) == []


def test_binding_without_scenario_still_appears_as_a_node():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    nodes = _nodes(root)
    assert "scenario:unassigned" in nodes
    assert nodes["scenario:unassigned"]["n_label"] == "Sin escenario asignado"
    assert "capability:mock-1" in nodes


def test_scenario_capability_hierarchy_edges():
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network", scenario_id=scenario.id))
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    edges = _edges(root)
    scenario_anchor = tree["scenarios"][0]["anchor_id"]
    assert {"source": "root", "target": scenario_anchor, "e_edge_type": "hierarchy"}.items() <= next(
        e for e in edges if e["target"] == scenario_anchor
    ).items()
    assert any(e["source"] == scenario_anchor and e["target"] == "capability:mock-1" and e["e_edge_type"] == "hierarchy" for e in edges)


def test_resources_become_their_own_nodes_connected_to_the_capability():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            config={"decoys": [{"Hostname": "srv-finanzas"}]},
        )
    )
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    nodes = _nodes(root)
    resource_nodes = {node_id: attrs for node_id, attrs in nodes.items() if attrs.get("n_node_type") == "resource"}
    assert len(resource_nodes) == 1
    resource_id, attrs = next(iter(resource_nodes.items()))
    assert attrs["n_label"] == "srv-finanzas"
    assert attrs["n_kind"] == "decoy"
    edges = _edges(root)
    assert any(e["source"] == "capability:dolost-1" and e["target"] == resource_id and e["e_edge_type"] == "hierarchy" for e in edges)


def test_mock_binding_has_no_resource_nodes():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    nodes = _nodes(root)
    assert not any(attrs.get("n_node_type") == "resource" for attrs in nodes.values())


def test_breadcrumb_edge_present_when_it_resolves():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    edges = _edges(root)
    breadcrumbs = [e for e in edges if e["e_edge_type"] == "breadcrumb"]
    assert len(breadcrumbs) == 1
    assert breadcrumbs[0]["source"] == "capability:honeytoken-1"
    assert breadcrumbs[0]["target"] == "capability:dolost-1"


def test_breadcrumb_edge_absent_when_target_is_broken():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="no-existe")
    )
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    edges = _edges(root)
    assert not any(e["e_edge_type"] == "breadcrumb" for e in edges)


def test_breadcrumb_edge_crosses_scenarios():
    operation = _operation()
    first = Scenario(description="Primero")
    second = Scenario(description="Segundo")
    operation.scenarios.extend([first, second])
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=first.id))
    operation.plugins.append(
        PluginBinding(
            plugin_id="honeytoken-1",
            plugin_kind="honeytoken",
            surface="data",
            scenario_id=second.id,
            leads_to_plugin_id="dolost-1",
        )
    )
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    edges = _edges(root)
    assert any(
        e["source"] == "capability:honeytoken-1" and e["target"] == "capability:dolost-1" and e["e_edge_type"] == "breadcrumb"
        for e in edges
    )


def test_capability_node_carries_kind_state_and_engage_activities():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            effect=DeceptionEffect(engage_activity_ids=["EAC0001"]),
        )
    )
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    nodes = _nodes(root)
    capability = nodes["capability:dolost-1"]
    assert capability["n_kind"] == "dolost"
    assert capability["n_state"] == "planned"
    assert capability["n_state_label"] == "Planificado"
    assert capability["n_engage_activities"] == "API Monitoring"


def test_scenario_node_detail_summarizes_ttp_stats():
    from datetime import datetime, timezone

    from apate.plugins import EventType
    from apate.telemetry import TelemetryRecord

    operation = _operation()
    scenario = Scenario(description="Acceso inicial", related_ttps=["T1078", "T1110.001"])
    operation.scenarios.append(scenario)
    event = TelemetryRecord(
        event_type=EventType.TTP_OBSERVED,
        operation_id=operation.id,
        plugin_id="mock-1",
        surface="network",
        timestamp=datetime.now(timezone.utc),
        source_event_id="source-1",
        ttp_id="T1078",
    )
    tree = _tree(operation, [event])

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    nodes = _nodes(root)
    detail = nodes[tree["scenarios"][0]["anchor_id"]]["n_detail"]
    assert "1 coincidentes" in detail
    assert "1 no observadas" in detail


def test_root_node_includes_operation_status_and_adversary_name():
    operation = _operation(adversary_profile=AdversaryProfile(name="APT99"))
    tree = _tree(operation)

    root = ET.fromstring(operation_tree_to_graphml(operation, tree))

    nodes = _nodes(root)
    assert "APT99" in nodes["root"]["n_detail"]
    assert operation.status.value in nodes["root"]["n_detail"]
