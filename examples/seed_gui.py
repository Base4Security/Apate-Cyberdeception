"""Prepara tres operaciones sintéticas para explorar la GUI local."""

import argparse
from pathlib import Path

from apate.core import (
    AdversaryProfile, JSONFileOperationRepository, Narrative, Operation,
    PluginBinding, RulesOfEngagement, Scenario,
)
from apate.plugins import EventBus, MockHoneypotPlugin
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector

from quickstart import main as run_quickstart


def main(language: str = "es") -> None:
    """Genera datos en español o inglés sin modificar el idioma de la GUI."""

    if language not in {"es", "en"}:
        raise ValueError("Idioma de demostración no soportado")
    english = language == "en"
    base = Path(".apate_data")
    rules_path = base / "rules.yaml"
    if not rules_path.exists():
        rules_path.parent.mkdir(parents=True, exist_ok=True)
        rules_name = "rules_example.en.yaml" if english else "rules_example.yaml"
        rules_path.write_text(Path(__file__).with_name(rules_name).read_text(encoding="utf-8"), encoding="utf-8")

    run_quickstart(language)  # operación cerrada con eventos y TTP sintéticos
    repo = JSONFileOperationRepository(base / "operations")
    bus = EventBus()
    TelemetryCollector(repository=JSONFileTelemetryRepository(base / "telemetry"), bus=bus)

    active = Operation(
        name="Lateral reconnaissance · lab" if english else "Reconocimiento lateral · laboratorio",
        adversary_profile=AdversaryProfile(
            name="Simulated network actor" if english else "Actor simulado de red",
            expected_ttps=["T1046"],
        ),
        roe=RulesOfEngagement(),
        narrative=Narrative(
            name="Internal test service" if english else "Servicio interno de prueba",
            description="Local demonstration scenario." if english else "Escenario de demostración local.",
        ),
    )
    active.add_scenario(Scenario(
        description="Observe a synthetic scan" if english else "Observar un escaneo sintético",
        related_ttps=["T1046"],
    ))
    active.bind_plugin(PluginBinding(plugin_id="mock-network", surface="network"))
    active.mark_active()
    MockHoneypotPlugin(
        plugin_id="mock-network", surface="network", operation_id=active.id, bus=bus,
        config={"language": language},
    ).deploy()
    repo.save(active)

    planning = Operation(
        name="Credential access · design" if english else "Acceso a credenciales · diseño",
        adversary_profile=AdversaryProfile(
            name="Simulated identity actor" if english else "Actor simulado de identidad",
            expected_ttps=["T1078"],
        ),
        roe=RulesOfEngagement(),
        narrative=Narrative(
            name="Lab identity" if english else "Identidad de laboratorio",
            description="Operation awaiting activation." if english else "Operación pendiente de activación.",
        ),
    )
    planning.add_scenario(Scenario(
        description="Plan an access observation" if english else "Planificar observación de acceso",
        related_ttps=["T1078"],
    ))
    repo.save(planning)
    print(
        "GUI ready: synthetic planning, active, and closed operations."
        if english else "GUI preparada: operaciones sintéticas en planificación, activa y cerrada."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lang", choices=("es", "en"), default="es", help="Idioma de los datos sintéticos")
    main(parser.parse_args().lang)
