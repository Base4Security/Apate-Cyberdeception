"""Tests para `apate.reporting.generate_workshop_kit()` (M12i) -- ver
docs/roadmap.md seccion M12i. Sigue el mismo patron que
tests/test_reporting_generator.py: opera sobre un TelemetryCollector
real (JSONFileTelemetryRepository en tmp_path), sin mockear nada."""

from apate.core import (
    AdversaryProfile,
    DeceptionEffect,
    Narrative,
    Operation,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
)
from apate.plugins import EventBus, MockHoneypotPlugin
from apate.reporting import generate_workshop_kit
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba M12i",
        adversary_profile=AdversaryProfile(
            name="APT ficticio",
            motivation="espionaje",
            skill_level="intermediate",
            expected_ttps=["T1046", "T1078"],
            target_assets=["ERP", "Active Directory"],
            notes="Notas del analista",
        ),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _make_collector(tmp_path) -> TelemetryCollector:
    return TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))


# -- Sin telemetria: heatmap degradado a solo esperadas ----------------------


def test_without_telemetry_heatmap_only_lists_expected_ttps():
    operation = _make_operation()

    kit = generate_workshop_kit(operation)

    assert kit.expected_ttps == ["T1046", "T1078"]
    assert kit.observed_ttps is None
    assert kit.matched_ttps is None
    assert kit.ttps_not_observed is None
    assert kit.unexpected_ttps is None


def test_no_telemetry_kit_reflects_full_adversary_profile():
    operation = _make_operation()

    kit = generate_workshop_kit(operation)

    assert kit.adversary_profile == operation.adversary_profile
    assert kit.operation_id == operation.id
    assert kit.operation_name == operation.name
    assert kit.operation_status == operation.status.value


# -- Con telemetria: reusa generate_report() ---------------------------------


def test_with_telemetry_reuses_generate_report_breakdown(tmp_path):
    operation = _make_operation(
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046", "T1078"])
    )
    bus = EventBus()
    collector = _make_collector(tmp_path)
    collector.attach(bus)
    mock = MockHoneypotPlugin(plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus)
    mock.deploy()
    mock.simulate_access(ttp_id="T1078")  # esperada, se observa
    mock.simulate_access(ttp_id="T1595.002")  # no esperada

    kit = generate_workshop_kit(operation, collector)

    assert kit.expected_ttps == ["T1046", "T1078"]
    assert kit.observed_ttps == ["T1078", "T1595.002"]
    assert kit.matched_ttps == ["T1078"]
    assert kit.ttps_not_observed == ["T1046"]
    assert kit.unexpected_ttps == ["T1595.002"]


def test_with_telemetry_but_no_events_still_marks_heatmap_as_compared(tmp_path):
    # A diferencia de "sin telemetry" (None), pasar un TelemetryCollector
    # sin eventos todavia SI cuenta como "se comparo" -- generate_report()
    # ya degrada correctamente a listas vacias/ttps_not_observed=esperadas,
    # no hace falta un chequeo especial de "hay datos" aparte.
    operation = _make_operation()
    collector = _make_collector(tmp_path)

    kit = generate_workshop_kit(operation, collector)

    assert kit.observed_ttps == []
    assert kit.matched_ttps == []
    assert kit.ttps_not_observed == ["T1046", "T1078"]
    assert kit.unexpected_ttps == []


# -- Escenarios (paso 3) ------------------------------------------------------


def test_includes_operation_scenarios():
    scenario = Scenario(description="Detectar escaneo interno", related_ttps=["T1046"])
    operation = _make_operation()
    operation.add_scenario(scenario)

    kit = generate_workshop_kit(operation)

    assert kit.scenarios == [scenario]


def test_operation_without_scenarios_does_not_crash_and_kit_says_so_explicitly():
    operation = _make_operation()

    kit = generate_workshop_kit(operation)

    assert kit.scenarios == []
    markdown = kit.to_markdown()
    assert "Sin escenarios cargados todavía" in markdown


# -- Fase 2 post-BlackHat: efecto de engaño planificado vs. medido -----------


def test_plugin_effects_present_without_telemetry():
    # A diferencia del heatmap de TTPs (que degrada a None sin
    # telemetria), plugin_effects no depende de TelemetryCollector --
    # es directamente lo que ya esta cargado en cada DeceptionEffect.
    operation = _make_operation()
    operation.bind_plugin(
        PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(measured_outcome="observado"))
    )

    kit = generate_workshop_kit(operation)

    assert len(kit.plugin_effects) == 1
    assert kit.plugin_effects[0].plugin_id == "honeytoken-1"
    assert kit.plugin_effects[0].is_measured is True


def test_plugin_effects_reused_from_generate_report_with_telemetry(tmp_path):
    operation = _make_operation()
    operation.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data"))
    collector = _make_collector(tmp_path)

    kit = generate_workshop_kit(operation, collector)

    assert len(kit.plugin_effects) == 1
    assert kit.plugin_effects[0].plugin_id == "honeytoken-1"
    assert kit.plugin_effects[0].is_measured is False


def test_workshop_kit_markdown_includes_plugin_effects_section():
    operation = _make_operation()
    operation.bind_plugin(
        PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(measured_outcome="observado"))
    )

    markdown = generate_workshop_kit(operation).to_markdown()

    assert "planificado vs. medido" in markdown
    assert "honeytoken-1" in markdown
    assert "observado" in markdown
