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


def main(language: str = "es") -> None:
    """Ejecuta el recorrido sintético; el idioma afecta sólo los datos demo."""

    if language not in {"es", "en"}:
        raise ValueError("Idioma de demostración no soportado")
    english = language == "en"
    base = Path(".apate_data")
    operation = Operation(
        name="Local demonstration" if english else "Demostración local",
        adversary_profile=AdversaryProfile(
            name="Simulated network actor" if english else "Actor simulado de red",
            motivation="Reconnaissance of a lab network segment" if english else "Reconocimiento de un segmento de laboratorio",
            skill_level="intermediate", expected_ttps=["T1046", "T1078"],
        ),
        roe=RulesOfEngagement(allowed_actions=["deploy", "transition", "retire"]),
        narrative=Narrative(
            name="Internal lab service" if english else "Servicio interno de laboratorio",
            description=(
                "A test decoy observes interactions without exposing real services."
                if english else "Un señuelo de prueba observa interacciones sin exponer servicios reales."
            ),
        ),
    )
    for plugin_id in ("honeypot-mock-1", "honeypot-mock-2"):
        operation.bind_plugin(PluginBinding(plugin_id=plugin_id, surface="network"))

    bus = EventBus()
    plugins = {
        plugin_id: MockHoneypotPlugin(
            plugin_id=plugin_id, surface="network", operation_id=operation.id, bus=bus,
            config={"language": language},
        )
        for plugin_id in ("honeypot-mock-1", "honeypot-mock-2")
    }
    collector = TelemetryCollector(repository=JSONFileTelemetryRepository(base / "telemetry"), bus=bus)
    rules_name = "rules_example.en.yaml" if english else "rules_example.yaml"
    rules = load_rules(str(Path(__file__).with_name(rules_name)))
    engine = RuleEngine(operation=operation, plugins=plugins, bus=bus, rules=rules)

    plugins["honeypot-mock-1"].deploy()
    plugins["honeypot-mock-1"].simulate_access()
    operation.closure_criteria.end_date = datetime.now(timezone.utc) - timedelta(seconds=1)
    engine.check_closure()
    JSONFileOperationRepository(base / "operations").save(operation)

    labels = (
        ("Operation", "Final status", "Observed events", "Observed TTPs", "Rejected actions")
        if english else
        ("Operación", "Estado final", "Eventos observados", "TTP observadas", "Acciones rechazadas")
    )
    print(f"{labels[0]}: {operation.id}")
    print(f"{labels[1]}: {operation.status.value}")
    print(f"{labels[2]}: {len(collector.list_events(operation.id))}")
    print(f"{labels[3]}: {collector.list_ttps(operation.id)}")
    print(f"{labels[4]}: {len(engine.rejected_actions)}")


if __name__ == "__main__":
    main()
