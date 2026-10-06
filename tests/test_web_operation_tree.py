"""`apate.web._operation_tree.build_operation_tree()` -- arbol visual
Operación → Escenario → PluginBinding → detalle (referencia declarada:
CounterCraft). Ver docstring del modulo para el diseno completo."""

from datetime import datetime, timezone

from apate.core import AdversaryProfile, DeceptionEffect, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario
from apate.plugins import EventType
from apate.telemetry import TelemetryRecord
from apate.web._operation_tree import build_operation_tree


def _operation(**kwargs):
    return Operation(
        name=kwargs.pop("name", "Operación del árbol"),
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def _build(operation, telemetry_records=None, **panels):
    return build_operation_tree(
        operation,
        telemetry_records or [],
        dolost_panels=panels.get("dolost_panels", {}),
        buda_panels=panels.get("buda_panels", {}),
        honeytoken_panels=panels.get("honeytoken_panels", {}),
        canarytoken_panels=panels.get("canarytoken_panels", {}),
        opencanary_panels=panels.get("opencanary_panels", {}),
    )


def test_empty_operation_has_no_content():
    tree = _build(_operation())
    assert tree["has_content"] is False
    assert tree["scenarios"] == []


def test_scenario_without_bindings_still_appears():
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)

    tree = _build(operation)

    assert tree["has_content"] is True
    assert len(tree["scenarios"]) == 1
    assert tree["scenarios"][0]["bindings"] == []
    assert tree["scenarios"][0]["unassigned"] is False


def test_binding_without_scenario_hangs_off_explicit_unassigned_bucket():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))

    tree = _build(operation)

    assert len(tree["scenarios"]) == 1
    bucket = tree["scenarios"][0]
    assert bucket["unassigned"] is True
    assert bucket["label"] == "Sin escenario asignado"
    assert bucket["anchor_id"] == "scenario:unassigned"
    assert [entry["binding"].plugin_id for entry in bucket["bindings"]] == ["mock-1"]


def test_unassigned_bucket_absent_when_every_binding_has_a_scenario():
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network", scenario_id=scenario.id))

    tree = _build(operation)

    assert len(tree["scenarios"]) == 1
    assert tree["scenarios"][0]["unassigned"] is False


def test_scenario_ttp_stats_reuse_compare_ttps_not_reimplemented():
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

    tree = _build(operation, [event])

    stats = tree["scenarios"][0]["ttp_stats"]
    assert stats == {"matched": 1, "not_observed": 1, "total": 2}


def test_scenario_without_related_ttps_has_no_ttp_stats():
    operation = _operation()
    operation.scenarios.append(Scenario(description="Sin TTPs"))

    tree = _build(operation)

    assert tree["scenarios"][0]["ttp_stats"] is None


def test_binding_engage_activities_resolve_to_real_catalog_entries():
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(
            plugin_id="mock-1",
            plugin_kind="mock",
            surface="network",
            scenario_id=scenario.id,
            effect=DeceptionEffect(engage_activity_ids=["EAC0001"]),
        )
    )

    tree = _build(operation)

    binding_entry = tree["scenarios"][0]["bindings"][0]
    assert [activity.id for activity in binding_entry["engage_activities"]] == ["EAC0001"]
    assert binding_entry["engage_activities"][0].name == "API Monitoring"


def test_binding_effect_has_content_false_when_all_three_fields_empty():
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network", scenario_id=scenario.id))

    tree = _build(operation)

    assert tree["scenarios"][0]["bindings"][0]["effect_has_content"] is False


def test_mock_binding_has_no_resource_concept():
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network", scenario_id=scenario.id))

    tree = _build(operation)

    binding_entry = tree["scenarios"][0]["bindings"][0]
    assert binding_entry["resource_supported"] is False
    assert binding_entry["resources"] == []


def test_dolost_binding_reports_resource_supported_true_even_without_docker_data():
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            scenario_id=scenario.id,
            config={"decoys": [{"Hostname": "srv-finanzas"}]},
        )
    )

    tree = _build(operation)

    binding_entry = tree["scenarios"][0]["bindings"][0]
    assert binding_entry["resource_supported"] is True
    assert [item["label"] for item in binding_entry["resources"]] == ["srv-finanzas"]


def test_binding_state_reflects_live_docker_data():
    operation = _operation()
    scenario = Scenario(description="Acceso inicial")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id, config={"decoys": [{"Hostname": "srv-finanzas"}]})
    )

    tree = _build(operation, dolost_panels={"dolost-1": {"decoys": [{"hostname": "srv-finanzas", "up": True, "status": "Up 2 minutes"}]}})

    binding_entry = tree["scenarios"][0]["bindings"][0]
    assert binding_entry["state"] == "active"
    assert binding_entry["resources"][0]["state"] == "active"


def test_canarytoken_and_opencanary_bindings_have_supported_real_resources():
    operation = _operation()
    operation.plugins.extend(
        [
            PluginBinding(plugin_id="canarytoken-1", plugin_kind="canarytoken", surface="data"),
            PluginBinding(plugin_id="opencanary-1", plugin_kind="opencanary", surface="network"),
        ]
    )

    tree = _build(
        operation,
        canarytoken_panels={
            "canarytoken-1": {
                "configured": True,
                "deployed": False,
                "memo": "Credencial nube",
                "token_type": "aws_keys",
            }
        },
        opencanary_panels={
            "opencanary-1": {
                "configured": True,
                "deployed": False,
                "docker_available": False,
                "services": {"ssh": {"enabled": True, "port": 2222}},
            }
        },
    )

    canarytoken = _entry_for(tree, "canarytoken-1")
    opencanary = _entry_for(tree, "opencanary-1")
    assert canarytoken["resource_supported"] is True
    assert canarytoken["resources"][0]["label"] == "Credencial nube"
    assert canarytoken["state"] == "deployed"
    assert opencanary["resource_supported"] is True
    assert opencanary["resources"][0]["label"] == "ssh:2222"
    assert opencanary["state"] == "unknown"
    assert opencanary["state_label"] == "Estado desconocido"


def test_multiple_scenarios_keep_their_own_bindings_separate():
    operation = _operation()
    first = Scenario(description="Primero")
    second = Scenario(description="Segundo")
    operation.scenarios.extend([first, second])
    operation.plugins.append(PluginBinding(plugin_id="mock-first", plugin_kind="mock", surface="network", scenario_id=first.id))
    operation.plugins.append(PluginBinding(plugin_id="mock-second", plugin_kind="mock", surface="network", scenario_id=second.id))

    tree = _build(operation)

    by_label = {entry["label"]: entry for entry in tree["scenarios"]}
    assert [b["binding"].plugin_id for b in by_label["Primero"]["bindings"]] == ["mock-first"]
    assert [b["binding"].plugin_id for b in by_label["Segundo"]["bindings"]] == ["mock-second"]


# -- Breadcrumbs (referencia declarada: CounterCraft) --------------------------


def _entry_for(tree, plugin_id):
    for scenario_entry in tree["scenarios"]:
        for binding_entry in scenario_entry["bindings"]:
            if binding_entry["binding"].plugin_id == plugin_id:
                return binding_entry
    raise AssertionError(f"'{plugin_id}' no aparece en el árbol")


def test_leads_to_resolves_to_the_real_target_anchor_id():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )

    tree = _build(operation)

    entry = _entry_for(tree, "honeytoken-1")
    assert entry["leads_to_plugin_id"] == "dolost-1"
    assert entry["leads_to_target_anchor_id"] == "capability:dolost-1"
    assert entry["leads_to_broken"] is False


def test_leads_to_across_different_scenarios_still_resolves():
    # La relacion "lleva a" puede cruzar escenarios distintos -- el
    # arbol es una jerarquia estricta por escenario, pero la resolucion
    # del breadcrumb no depende de que las dos capacidades compartan
    # escenario.
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

    tree = _build(operation)

    entry = _entry_for(tree, "honeytoken-1")
    assert entry["leads_to_target_anchor_id"] == "capability:dolost-1"


def test_leads_to_nonexistent_target_is_broken_not_silently_dropped():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="no-existe")
    )

    tree = _build(operation)

    entry = _entry_for(tree, "honeytoken-1")
    assert entry["leads_to_plugin_id"] == "no-existe"
    assert entry["leads_to_target_anchor_id"] is None
    assert entry["leads_to_broken"] is True


def test_binding_without_leads_to_has_no_breadcrumb_fields_set():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))

    tree = _build(operation)

    entry = _entry_for(tree, "mock-1")
    assert entry["leads_to_plugin_id"] is None
    assert entry["leads_to_target_anchor_id"] is None
    assert entry["leads_to_broken"] is False
    assert entry["leads_from_plugin_ids"] == []


def test_target_binding_knows_who_leads_to_it():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )

    tree = _build(operation)

    target_entry = _entry_for(tree, "dolost-1")
    assert target_entry["leads_from_plugin_ids"] == ["honeytoken-1"]


def test_a_broken_reference_is_not_counted_as_incoming_for_anyone():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="no-existe")
    )

    tree = _build(operation)

    # Ningun otro binding existe en esta operacion -- nada que pueda
    # aparecer marcado como receptor de esa referencia rota.
    for scenario_entry in tree["scenarios"]:
        for binding_entry in scenario_entry["bindings"]:
            assert binding_entry["leads_from_plugin_ids"] == []


def test_two_node_cycle_both_resolve_independently_in_the_tree():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="a", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="b"))
    operation.plugins.append(PluginBinding(plugin_id="b", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="a"))

    tree = _build(operation)

    entry_a = _entry_for(tree, "a")
    entry_b = _entry_for(tree, "b")
    assert entry_a["leads_to_target_anchor_id"] == "capability:b"
    assert entry_b["leads_to_target_anchor_id"] == "capability:a"
    assert entry_a["leads_from_plugin_ids"] == ["b"]
    assert entry_b["leads_from_plugin_ids"] == ["a"]
