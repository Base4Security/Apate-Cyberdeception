from datetime import datetime, timezone

from apate.core import AdversaryProfile, DeceptionEffect, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.plugins import EventBus, MockHoneypotPlugin
from apate.reporting import generate_report
from apate.reporting.generator import plugin_effect_summaries
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046", "T1078", "T1110"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _make_collector(tmp_path) -> TelemetryCollector:
    return TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path))


def test_generate_report_with_no_telemetry_marks_all_expected_ttps_as_not_observed(tmp_path):
    operation = _make_operation()
    collector = _make_collector(tmp_path)

    report = generate_report(operation, collector)

    assert report.expected_ttps == ["T1046", "T1078", "T1110"]
    assert report.observed_ttps == []
    assert report.matched_ttps == []
    assert report.ttps_not_observed == ["T1046", "T1078", "T1110"]
    assert report.unexpected_ttps == []
    assert report.iocs == []
    assert report.event_count == 0


def test_generate_report_reflects_operation_metadata(tmp_path):
    operation = _make_operation(name="Operacion X")
    operation.mark_active()
    collector = _make_collector(tmp_path)

    report = generate_report(operation, collector)

    assert report.operation_id == operation.id
    assert report.operation_name == "Operacion X"
    assert report.operation_status == "active"


def test_generate_report_computes_matched_not_observed_and_unexpected_ttps(tmp_path):
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

    report = generate_report(operation, collector)

    assert report.matched_ttps == ["T1078"]
    assert report.ttps_not_observed == ["T1046"]
    assert report.unexpected_ttps == ["T1595.002"]


def test_generate_report_includes_iocs_from_telemetry(tmp_path):
    operation = _make_operation()
    bus = EventBus()
    collector = _make_collector(tmp_path)
    collector.attach(bus)
    mock = MockHoneypotPlugin(plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus)
    mock.deploy()

    report = generate_report(operation, collector)

    assert len(report.iocs) == 1
    assert report.iocs[0].type == "ip"
    assert report.iocs[0].value == "203.0.113.10"


def test_generate_report_only_considers_events_for_this_operation(tmp_path):
    collector = _make_collector(tmp_path)
    bus = EventBus()
    collector.attach(bus)

    operation_a = _make_operation(name="Operacion A")
    operation_b = _make_operation(name="Operacion B", adversary_profile=AdversaryProfile(name="Otro"))

    mock_a = MockHoneypotPlugin(plugin_id="mock-a", surface="network", operation_id=operation_a.id, bus=bus)
    mock_b = MockHoneypotPlugin(plugin_id="mock-b", surface="network", operation_id=operation_b.id, bus=bus)
    mock_a.deploy()
    mock_b.deploy()
    mock_b.simulate_access(ttp_id="T1110")

    report_a = generate_report(operation_a, collector)

    assert report_a.event_count == 1
    assert report_a.observed_ttps == []


# -- Fase 2 post-BlackHat: efecto de engaño planificado vs. medido -----------


def test_plugin_effect_summaries_reflects_each_binding():
    measured_at = datetime(2026, 8, 17, 10, 30, tzinfo=timezone.utc)
    operation = _make_operation()
    operation.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-1",
            surface="data",
            effect=DeceptionEffect(
                success_metric="alerta en 5 min",
                measured_outcome="alerta a los 3 min",
                measured_at=measured_at,
                measured_by="Federico",
            ),
        )
    )
    operation.bind_plugin(PluginBinding(plugin_id="mock-1", surface="network"))

    summaries = plugin_effect_summaries(operation)

    assert len(summaries) == 2
    assert summaries[0].plugin_id == "honeytoken-1"
    assert summaries[0].is_measured is True
    assert summaries[0].measured_outcome == "alerta a los 3 min"
    assert summaries[0].measured_by == "Federico"
    assert summaries[1].plugin_id == "mock-1"
    assert summaries[1].is_measured is False


def test_plugin_effect_summaries_empty_without_plugins():
    assert plugin_effect_summaries(_make_operation()) == []


def test_generate_report_includes_plugin_effects(tmp_path):
    operation = _make_operation()
    operation.bind_plugin(
        PluginBinding(plugin_id="honeytoken-1", surface="data", effect=DeceptionEffect(measured_outcome="observado"))
    )
    collector = _make_collector(tmp_path)

    report = generate_report(operation, collector)

    assert len(report.plugin_effects) == 1
    assert report.plugin_effects[0].plugin_id == "honeytoken-1"
    assert report.plugin_effects[0].is_measured is True
