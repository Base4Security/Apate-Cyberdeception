"""Prepara tres operaciones sintéticas para explorar la GUI local."""

from pathlib import Path

from apate.core import (
    AdversaryProfile, JSONFileOperationRepository, Narrative, Operation,
    PluginBinding, RulesOfEngagement, Scenario,
)
from apate.plugins import EventBus, MockHoneypotPlugin
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector

from quickstart import main as run_quickstart


def main() -> None:
    base = Path(".apate_data")
    rules_path = base / "rules.yaml"
    if not rules_path.exists():
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        rules_path.write_text(Path(__file__).with_name("rules_example.yaml").read_text(encoding="utf-8"), encoding="utf-8")

    run_quickstart()  # operación cerrada con eventos y TTP sintéticos
    repo = JSONFileOperationRepository(base / "operations")
    bus = EventBus()
    TelemetryCollector(repository=JSONFileTelemetryRepository(base / "telemetry"), bus=bus)

    active = Operation(
        name="Reconocimiento lateral · laboratorio",
        adversary_profile=AdversaryProfile(name="Actor simulado de red", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Servicio interno de prueba", description="Escenario de demostración local."),
    )
    active.add_scenario(Scenario(description="Observar un escaneo sintético", related_ttps=["T1046"]))
    active.bind_plugin(PluginBinding(plugin_id="mock-network", surface="network"))
    active.mark_active()
    MockHoneypotPlugin(plugin_id="mock-network", surface="network", operation_id=active.id, bus=bus).deploy()
    repo.save(active)

    planning = Operation(
        name="Acceso a credenciales · diseño",
        adversary_profile=AdversaryProfile(name="Actor simulado de identidad", expected_ttps=["T1078"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Identidad de laboratorio", description="Operación pendiente de activación."),
    )
    planning.add_scenario(Scenario(description="Planificar observación de acceso", related_ttps=["T1078"]))
    repo.save(planning)
    print("GUI preparada: operaciones sintéticas en planificación, activa y cerrada.")


if __name__ == "__main__":
    main()
