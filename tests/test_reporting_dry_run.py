"""Ensayo en seco de una operacion (referencia declarada: CounterCraft --
simular sobre el diseño, sin clonar infraestructura). Ver docstring de
`apate.reporting.dry_run` para el diseño completo."""

from __future__ import annotations

import inspect

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario
from apate.core.models import DeceptionEffect
from apate.reporting import OperationDryRun, simulate_dry_run


def _operation(**kwargs) -> Operation:
    return Operation(
        name=kwargs.pop("name", "Operación de prueba"),
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


# -- Garantía estructural de "cero side effects" ---------------------------


def test_simulate_dry_run_signature_takes_only_an_operation():
    """Sin `TelemetryCollector`, sin paneles de mecanica especifica, sin
    ningun cliente de Docker/WinRM/EventBus -- la firma en si misma hace
    imposible por construccion que esta funcion tenga un side effect."""

    params = list(inspect.signature(simulate_dry_run).parameters)
    assert params == ["operation"]


def test_simulate_dry_run_is_pure_same_input_same_output():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))

    first = simulate_dry_run(operation)
    second = simulate_dry_run(operation)

    assert first.to_dict() == second.to_dict()


def test_simulate_dry_run_does_not_mutate_the_operation():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    before = operation.to_dict()

    simulate_dry_run(operation)

    assert operation.to_dict() == before


# -- Caso vacío --------------------------------------------------------------


def test_empty_operation_has_no_content():
    operation = _operation()

    result = simulate_dry_run(operation)

    assert result.has_content is False
    assert result.chains == []
    assert result.findings == []


# -- Cadenas: orden, contenido, terminación ---------------------------------


def test_single_root_capability_with_no_leads_to_is_a_one_step_chain():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))

    result = simulate_dry_run(operation)

    assert len(result.chains) == 1
    chain = result.chains[0]
    assert [s.plugin_id for s in chain.steps] == ["dolost-1"]
    assert chain.terminal_reason == "sin_miga_saliente"
    assert chain.entry_is_arbitrary is False


def test_breadcrumb_chain_follows_leads_to_in_order():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )

    result = simulate_dry_run(operation)

    assert len(result.chains) == 1
    chain = result.chains[0]
    assert [s.plugin_id for s in chain.steps] == ["honeytoken-1", "dolost-1"]
    assert chain.terminal_reason == "sin_miga_saliente"


def test_step_carries_declared_design_data_not_live_state():
    operation = _operation()
    scenario = Scenario(description="Escenario de prueba", related_ttps=["T1046"])
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            scenario_id=scenario.id,
            effect=DeceptionEffect(
                expected_adversary_belief="Cree que es un host real.",
                expected_adversary_action="Intenta moverse lateralmente.",
                success_metric="Se conecta al decoy.",
                engage_activity_ids=["EAC0005"],  # Lures
            ),
        )
    )

    result = simulate_dry_run(operation)

    step = result.chains[0].steps[0]
    assert step.scenario_id == scenario.id
    assert step.scenario_label == "Escenario de prueba"
    assert step.expected_adversary_belief == "Cree que es un host real."
    assert step.expected_adversary_action == "Intenta moverse lateralmente."
    assert step.success_metric == "Se conecta al decoy."
    assert step.engage_activity_names == ["Lures"]
    # Nunca un estado de despliegue real -- eso es "Esperado vs. observado"
    # (apate.playground), no este modulo.
    assert not hasattr(step, "state")
    assert not hasattr(step, "deployed")


def test_broken_breadcrumb_terminates_the_chain_without_crashing():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="no-existe")
    )

    result = simulate_dry_run(operation)

    assert len(result.chains) == 1
    chain = result.chains[0]
    assert [s.plugin_id for s in chain.steps] == ["honeytoken-1"]
    assert chain.terminal_reason == "miga_rota"


def test_two_node_cycle_with_no_external_entry_terminates_without_looping_forever():
    """A lleva a B, B lleva a A -- ninguno de los dos es "raiz" (ambos
    tienen una miga entrante), asi que ninguno arranca su propia cadena
    en la Fase 1. La Fase 2 lo recorre igual, explicito, en vez de
    dejarlo fuera del recorrido en silencio."""

    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="a", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="b"))
    operation.plugins.append(PluginBinding(plugin_id="b", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="a"))

    result = simulate_dry_run(operation)

    assert len(result.chains) == 1
    chain = result.chains[0]
    assert chain.terminal_reason == "ciclo_detectado"
    assert chain.entry_is_arbitrary is True
    assert [s.plugin_id for s in chain.steps] == ["a", "b"]


def test_cycle_reachable_from_a_root_is_also_detected():
    """root (raiz de verdad, nadie le lleva ninguna miga) -> a -> b -> a
    -- el ciclo (a<->b) no incluye a la raiz, asi que root SI arranca en
    la Fase 1 y el ciclo se detecta al volver a pisar "a"."""

    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="root", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="a"))
    operation.plugins.append(PluginBinding(plugin_id="a", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="b"))
    operation.plugins.append(PluginBinding(plugin_id="b", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="a"))

    result = simulate_dry_run(operation)

    assert len(result.chains) == 1
    chain = result.chains[0]
    assert chain.entry_is_arbitrary is False
    assert chain.terminal_reason == "ciclo_detectado"
    assert [s.plugin_id for s in chain.steps] == ["root", "a", "b"]


def test_breadcrumb_crossing_different_scenarios_is_one_chain():
    operation = _operation()
    scenario_a = Scenario(description="Escenario A")
    scenario_b = Scenario(description="Escenario B")
    operation.scenarios.extend([scenario_a, scenario_b])
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario_b.id)
    )
    operation.plugins.append(
        PluginBinding(
            plugin_id="honeytoken-1",
            plugin_kind="honeytoken",
            surface="data",
            scenario_id=scenario_a.id,
            leads_to_plugin_id="dolost-1",
        )
    )

    result = simulate_dry_run(operation)

    assert len(result.chains) == 1
    steps = result.chains[0].steps
    assert steps[0].scenario_label == "Escenario A"
    assert steps[1].scenario_label == "Escenario B"


def test_two_independent_roots_produce_two_chains():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(PluginBinding(plugin_id="buda-1", plugin_kind="buda", surface="identity"))

    result = simulate_dry_run(operation)

    assert len(result.chains) == 2
    assert {chain.steps[0].plugin_id for chain in result.chains} == {"dolost-1", "buda-1"}


# -- Hallazgos: TTP esperada sin escenario que la cubra ----------------------


def test_finding_ttp_uncovered_by_any_scenario():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1046", "T1059.004"]))
    operation.scenarios.append(Scenario(description="Solo cubre una", related_ttps=["T1046"]))

    result = simulate_dry_run(operation)

    findings = [f for f in result.findings if f.category == "ttp_uncovered"]
    assert len(findings) == 1
    assert "T1059.004" in findings[0].message
    assert "T1046" not in findings[0].message
    assert findings[0].severity == "gap"


def test_no_ttp_uncovered_finding_when_every_expected_ttp_is_covered():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1046"]))
    operation.scenarios.append(Scenario(description="Cubre todo", related_ttps=["T1046"]))

    result = simulate_dry_run(operation)

    assert [f for f in result.findings if f.category == "ttp_uncovered"] == []


# -- Hallazgos: escenario con TTPs pero sin capacidades ----------------------


def test_finding_scenario_with_ttps_but_no_bound_capability():
    operation = _operation()
    scenario = Scenario(description="Vacío pero con TTPs", related_ttps=["T1046"])
    operation.scenarios.append(scenario)

    result = simulate_dry_run(operation)

    findings = [f for f in result.findings if f.category == "scenario_ttps_unreachable"]
    assert len(findings) == 1
    assert findings[0].anchor == "tab-scenarios"
    assert findings[0].severity == "gap"


def test_no_unreachable_finding_when_scenario_has_a_bound_capability():
    operation = _operation()
    scenario = Scenario(description="Con capacidad", related_ttps=["T1046"])
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id)
    )

    result = simulate_dry_run(operation)

    assert [f for f in result.findings if f.category == "scenario_ttps_unreachable"] == []


# -- Hallazgos: escenario sin miga entrante (informativo) --------------------


def test_finding_scenario_without_incoming_breadcrumb_is_informational():
    operation = _operation()
    scenario = Scenario(description="Sin migas")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id)
    )

    result = simulate_dry_run(operation)

    findings = [f for f in result.findings if f.category == "scenario_no_entry"]
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].anchor == "tab-scenarios"


def test_no_entry_finding_when_scenario_receives_a_breadcrumb():
    operation = _operation()
    scenario = Scenario(description="Con miga entrante")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id)
    )
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )

    result = simulate_dry_run(operation)

    assert [f for f in result.findings if f.category == "scenario_no_entry"] == []


# -- Hallazgos: capacidad totalmente desconectada ----------------------------


def test_finding_isolated_capability():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))

    result = simulate_dry_run(operation)

    findings = [f for f in result.findings if f.category == "isolated_capability"]
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].anchor == "tab-plugins"


def test_no_isolated_finding_when_capability_has_a_scenario():
    operation = _operation()
    scenario = Scenario(description="Con escenario")
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network", scenario_id=scenario.id)
    )

    result = simulate_dry_run(operation)

    assert [f for f in result.findings if f.category == "isolated_capability"] == []


def test_no_isolated_finding_when_capability_is_part_of_a_breadcrumb_chain():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="dolost-1")
    )

    result = simulate_dry_run(operation)

    isolated_ids = {f.anchor for f in result.findings if f.category == "isolated_capability"}
    assert "capability:dolost-1" not in isolated_ids
    assert "capability:honeytoken-1" not in isolated_ids


# -- Hallazgos: miga rota y ciclo, también como findings ---------------------


def test_finding_broken_breadcrumb():
    operation = _operation()
    operation.plugins.append(
        PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="no-existe")
    )

    result = simulate_dry_run(operation)

    findings = [f for f in result.findings if f.category == "broken_breadcrumb"]
    assert len(findings) == 1
    assert findings[0].severity == "gap"
    assert findings[0].anchor == "tab-plugins"


def test_finding_breadcrumb_cycle():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="a", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="b"))
    operation.plugins.append(PluginBinding(plugin_id="b", plugin_kind="honeytoken", surface="data", leads_to_plugin_id="a"))

    result = simulate_dry_run(operation)

    findings = [f for f in result.findings if f.category == "breadcrumb_cycle"]
    assert len(findings) == 1
    assert findings[0].severity == "gap"
    assert "a" in findings[0].message and "b" in findings[0].message


# -- Una operación bien armada no genera hallazgos falsos --------------------


def test_well_designed_operation_has_no_findings():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1046"]))
    scenario = Scenario(description="Escenario completo", related_ttps=["T1046"])
    operation.scenarios.append(scenario)
    operation.plugins.append(
        PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id)
    )
    operation.plugins.append(
        PluginBinding(
            plugin_id="honeytoken-1",
            plugin_kind="honeytoken",
            surface="data",
            scenario_id=scenario.id,
            leads_to_plugin_id="dolost-1",
        )
    )

    result = simulate_dry_run(operation)

    assert result.findings == []
    assert isinstance(result, OperationDryRun)
