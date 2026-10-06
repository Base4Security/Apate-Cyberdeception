"""Ejemplo local completo con reglas, dos plugins simulados y telemetría."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from apate.core import (
    AdversaryProfile, JSONFileOperationRepository, Narrative, Operation,
    PluginBinding, RulesOfEngagement,
)
from apate.plugins import EventBus, MockHoneypotPlugin
from apate.rules import RuleEngine, load_rules
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector


def main() -> None:
    base = Path(".apate_data")
    operation = Operation(
        name="Demostración local",
        adversary_profile=AdversaryProfile(name="Actor ficticio", expected_ttps=["T1046", "T1078"]),
        roe=RulesOfEngagement(allowed_actions=["deploy", "transition", "retire"]),
        narrative=Narrative(name="Entorno simulado"),
    )
    for plugin_id in ("honeypot-mock-1", "honeypot-mock-2"):
        operation.bind_plugin(PluginBinding(plugin_id=plugin_id, surface="network"))

    bus = EventBus()
    plugins = {
        plugin_id: MockHoneypotPlugin(
            plugin_id=plugin_id, surface="network", operation_id=operation.id, bus=bus,
        )
        for plugin_id in ("honeypot-mock-1", "honeypot-mock-2")
    }
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(base / "telemetry"), bus=bus)
    rules = load_rules(str(Path(__file__).with_name("rules_example.yaml")))
    engine = RuleEngine(operation=operation, plugins=plugins, bus=bus, rules=rules)

    plugins["honeypot-mock-1"].deploy()
    plugins["honeypot-mock-1"].simulate_access()
    operation.closure_criteria.end_date = datetime.now(timezone.utc) - timedelta(seconds=1)
    engine.check_closure()
    JSONFileOperationRepository(base / "operations").save(operation)

    print(f"Operación: {operation.id}")
    print(f"Estado final: {operation.status.value}")
    print(f"Eventos observados: {len(collector.list_events(operation.id))}")
    print(f"TTP observadas: {collector.list_ttps(operation.id)}")
    print(f"Acciones rechazadas: {len(engine.rejected_actions)}")


if __name__ == "__main__":
    main()
