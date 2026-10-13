"""Modo Playground (M5) - ver documento de diseno, seccion 6.

Reutiliza tal cual el stack docker-compose del repositorio Cyber
Deception Playground como entorno aislado de ensayo: este paquete solo
aporta el wrapper de ciclo de vida (lifecycle.py, subprocess sobre un
checkout configurado via PlaygroundConfig), el cliente minimo de
Elasticsearch (elastic.py) y el puente que traduce sus datos al
EventBus de M2 (events.py), mas el objeto que ata todo eso a una
Operacion (session.py).

**Corregido post-M14 (vendorizacion, ver docs/roadmap.md):** un
subconjunto funcional de ese repo (no el codigo Python de APATE, que
sigue viviendo aparte) esta vendorizado en `playground-stack/`, en la
raiz del repo -- `PlaygroundConfig.from_env()` lo usa por defecto si
`APATE_PLAYGROUND_PATH` no esta definida, ver `VENDORED_PLAYGROUND_PATH`."""

from .config import ENV_VAR, PlaygroundConfig, VENDORED_PLAYGROUND_PATH
from .elastic import DEFAULT_ELASTIC_URL, fetch_recent_hits
from .events import ELASTIC_INDEX, PLAYGROUND_PLUGIN_ID, PlaygroundEventBridge, PlaygroundSource
from .exceptions import PlaygroundCommandError, PlaygroundConfigError, PlaygroundError
from .lifecycle import PlaygroundCommandResult, run_attacker_script, start_stack, stop_stack
from .scenario_ttps import ScenarioTTP, ScenarioTTPCoverage, list_producible_ttps, match_scenario_ttps
from .session import PlaygroundSession

__all__ = [
    "DEFAULT_ELASTIC_URL",
    "ELASTIC_INDEX",
    "ENV_VAR",
    "PLAYGROUND_PLUGIN_ID",
    "PlaygroundCommandError",
    "PlaygroundCommandResult",
    "PlaygroundConfig",
    "PlaygroundConfigError",
    "PlaygroundError",
    "PlaygroundEventBridge",
    "PlaygroundSession",
    "PlaygroundSource",
    "ScenarioTTP",
    "ScenarioTTPCoverage",
    "VENDORED_PLAYGROUND_PATH",
    "fetch_recent_hits",
    "list_producible_ttps",
    "match_scenario_ttps",
    "run_attacker_script",
    "start_stack",
    "stop_stack",
]
