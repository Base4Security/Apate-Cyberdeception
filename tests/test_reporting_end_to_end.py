"""Caso end-to-end de M6: una operacion con TTPs esperadas conocidas,
eventos simulados via MockHoneypotPlugin (M2) que generan algunas (no
todas) de esas TTPs mas una TTP extra no esperada, y verificacion de
que el informe (generate_report, M6) refleja las discrepancias
correctamente en su estructura interna y en ambos formatos de
exportacion."""

import json

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.plugins import EventBus, MockHoneypotPlugin
from apate.reporting import generate_report
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector


def test_operation_report_reflects_ttp_discrepancies_end_to_end(tmp_path):
    # Perfil de amenaza (paso 1 de la metodologia): tres TTPs esperadas.
    operation = Operation(
        name="Operacion de prueba - informe CTI",
        adversary_profile=AdversaryProfile(
            name="APT ficticio", expected_ttps=["T1046", "T1078", "T1110"]
        ),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )

    bus = EventBus()
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path), bus=bus)
    honeypot = MockHoneypotPlugin(
        plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus
    )

    # Interaccion real observada: escaneo (sin TTP) + acceso con una de
    # las TTPs esperadas (T1078) + acceso con una TTP no esperada
    # (T1595.002, reconocimiento activo). T1046 y T1110 nunca ocurren.
    honeypot.deploy()
    honeypot.simulate_access(ttp_id="T1078", source_ip="203.0.113.20")
    honeypot.simulate_access(ttp_id="T1595.002", source_ip="203.0.113.21")

    operation.mark_active()
    operation.mark_compromised()
    operation.close()

    report = generate_report(operation, collector)

    # Discrepancias: T1078 coincide, T1046/T1110 esperadas y no
    # observadas, T1595.002 observada y no esperada.
    assert report.expected_ttps == ["T1046", "T1078", "T1110"]
    assert report.observed_ttps == ["T1078", "T1595.002"]
    assert report.matched_ttps == ["T1078"]
    assert report.ttps_not_observed == ["T1046", "T1110"]
    assert report.unexpected_ttps == ["T1595.002"]
    assert report.operation_status == "closed"
    assert report.event_count == 5  # deploy: 1 scan; 2x simulate_access: interaccion + ttp_observed cada una

    ioc_values = {ioc.value for ioc in report.iocs}
    assert {"203.0.113.10", "203.0.113.20", "203.0.113.21"} <= ioc_values

    markdown = report.to_markdown()
    assert "T1046" in markdown and "T1110" in markdown  # esperadas y no observadas
    assert "T1595.002" in markdown  # observada y no esperada
    assert "T1078" in markdown  # coincidente

    exported = report.to_json()
    parsed = json.loads(exported)
    assert parsed["ttps_not_observed"] == ["T1046", "T1110"]
    assert parsed["unexpected_ttps"] == ["T1595.002"]
    assert parsed["matched_ttps"] == ["T1078"]
