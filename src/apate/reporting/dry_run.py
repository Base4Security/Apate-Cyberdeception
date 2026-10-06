"""Ensayo en seco de una operacion (referencia declarada: CounterCraft --
sin llegar a "clonar infraestructura"/digital twins, explicitamente fuera
de alcance por pedido del usuario, pero si a *simular* sobre el diseño).

Dado el arbol real de una operacion ya diseñada (escenarios, capacidades
vinculadas, la relacion "lleva a" de breadcrumbs, TTPs esperadas,
actividades de Engage), recorre deterministamente las cadenas de migas
para previsualizar que camino haria un adversario y que se veria en cada
paso -- **antes de que exista ninguna corrida real**. El valor concreto:
detectar huecos de diseño (un escenario sin punto de entrada, una TTP que
ninguna capacidad podria llegar a observar, una capacidad aislada) sin
haber desplegado nada todavia.

**Cero side effects, garantizado por construccion, no por disciplina:**
`simulate_dry_run()` recibe solo un `Operation` -- ni `TelemetryCollector`,
ni los paneles de mecanica especifica (`dolost_panels`/`buda_panels`/
`honeytoken_panels`), ni ningun cliente de Docker/WinRM/EventBus. No hay
forma de que esta funcion despliegue, rote, retire, publique un evento,
escriba telemetria o genere un `OperatorAction`, porque no tiene acceso a
nada de eso -- a diferencia de `apate.web._operation_tree`, que si recibe
esos paneles para mostrar estado EN VIVO de recursos ya desplegados. Test
dedicado (`test_dry_run_never_touches_anything_external`) confirma que la
firma de `simulate_dry_run()` es `(Operation) -> OperationDryRun` sin mas
parametros, y que dos llamadas sucesivas sobre la misma `Operation` dan
resultados identicos e inmutables (no hay estado global mutado).

**No es un motor de simulacion probabilistico.** Es un recorrido
deterministico sobre el grafo que ya existe (`PluginBinding.leads_to_plugin_id`,
`Operation.find_plugin_binding()`, ya construidos para el arbol visual de
breadcrumbs). No hay "que tan probable es que el adversario haga X" en
ningun lado -- mismo criterio que ya rechazo los scores sinteticos en
`apate.web._portfolio`.

**No confundir con "Esperado vs. observado"** (`apate.playground`,
`playground/defender.html`): esa vista compara el diseño contra
telemetria REAL de una corrida ya sucedida. Esto es sobre el diseño, antes
de que exista ninguna corrida -- por eso cada paso muestra lo DECLARADO
(actividades de Engage seleccionadas, efecto Ver-Pensar-Hacer), nunca
estado de despliegue real ni eventos observados.

**Que constituye un "paso" y como se ordena:** cada `PluginBinding` es un
paso. Los pasos se agrupan en "cadenas" -- secuencias que siguen
`leads_to_plugin_id` de miga en miga -- porque eso es lo unico en el
modelo que dice "de esta capacidad, el adversario llegaria a aquella
otra". Una cadena arranca en una capacidad "raiz" (ninguna otra capacidad
le lleva una miga) y sigue hasta: quedarse sin miga saliente (fin natural
del camino), encontrar una miga rota (destino no vinculado a esta
operacion), o volver a pisar un paso ya visitado (ciclo -- ver
`DryRunChain.terminal_reason`). Un caso borde real, manejado sin
reventar: un ciclo CERRADO sin ningun punto de entrada externo (A lleva a
B, B lleva a A, y nada mas apunta a ninguno de los dos) no tiene ninguna
capacidad "raiz" desde donde arrancar -- se recorre igual, empezando por
la primera en el orden de `Operation.plugins`, marcado explicito como
tal en vez de quedar fuera del recorrido en silencio."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..core.models import Operation, PluginBinding
from ..engage import get_activity
from ..i18n import gettext as _


@dataclass
class DryRunStep:
    """Un paso del recorrido: una capacidad puntual, con lo DECLARADO
    para ella (nunca estado de despliegue real ni telemetria -- ver
    docstring del modulo)."""

    plugin_id: str
    plugin_kind: Optional[str]
    surface: str
    scenario_id: Optional[str]
    scenario_label: Optional[str]
    engage_activity_names: list[str]
    expected_adversary_belief: str
    expected_adversary_action: str
    success_metric: str
    leads_to_plugin_id: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "plugin_kind": self.plugin_kind,
            "surface": self.surface,
            "scenario_id": self.scenario_id,
            "scenario_label": self.scenario_label,
            "engage_activity_names": list(self.engage_activity_names),
            "expected_adversary_belief": self.expected_adversary_belief,
            "expected_adversary_action": self.expected_adversary_action,
            "success_metric": self.success_metric,
            "leads_to_plugin_id": self.leads_to_plugin_id,
        }


@dataclass
class DryRunChain:
    """Una cadena de migas: uno o mas `DryRunStep` en el orden en que el
    adversario los recorreria siguiendo `leads_to_plugin_id`."""

    steps: list[DryRunStep]
    # "sin_miga_saliente" | "miga_rota" | "ciclo_detectado"
    terminal_reason: str
    # True solo para el caso borde de un ciclo cerrado sin ninguna
    # capacidad raiz externa (ver docstring del modulo) -- el punto de
    # arranque de esta cadena es arbitrario (el primero en orden de
    # `Operation.plugins`), no una raiz real del grafo.
    entry_is_arbitrary: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": [s.to_dict() for s in self.steps],
            "terminal_reason": self.terminal_reason,
            "entry_is_arbitrary": self.entry_is_arbitrary,
        }


@dataclass
class DryRunFinding:
    """Un hueco de diseño detectado, puramente estructural (ver docstring
    del modulo sobre por que no hay scoring). `severity` distingue lo que
    es un dato objetivamente roto (`"gap"` -- ej. una miga rota, una TTP
    que nada podria observar) de lo que es solo informativo y puede ser
    intencional (`"info"` -- ej. un escenario sin miga entrante: puede
    ser, a proposito, un punto de entrada natural, como un decoy expuesto
    directo en la red sin necesitar ninguna miga que lleve a el)."""

    category: str
    severity: str  # "gap" | "info"
    message: str
    # id del tab real de `operations/detail.html` donde se revisa/corrige
    # esto (ej. "tab-scenarios", "tab-plugins") -- mismo formato que ya
    # usa `href="#{{ row.target }}"` en la tabla de Preparación, no un id
    # de nodo del árbol (esos no son anclas navegables, son atributos
    # `data-tree-id` internos del SVG).
    anchor: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "anchor": self.anchor,
        }


@dataclass
class OperationDryRun:
    chains: list[DryRunChain] = field(default_factory=list)
    findings: list[DryRunFinding] = field(default_factory=list)
    has_content: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "chains": [c.to_dict() for c in self.chains],
            "findings": [f.to_dict() for f in self.findings],
            "has_content": self.has_content,
        }


def _step_kind(binding: PluginBinding) -> Optional[str]:
    # Mismo heuristico simple que `apate.web._deception_path` (no el de
    # `apate.web._portfolio`, que valida contra `PluginRegistry` -- este
    # modulo es capa de dominio pura, sin importar nada de `apate.web`,
    # asi que usa el heuristico auto-contenido, no el que depende del
    # registro de plugins).
    return binding.plugin_kind or (binding.plugin_id.split("-", 1)[0] or None)


def _build_step(binding: PluginBinding, operation: Operation) -> DryRunStep:
    scenario = operation.find_scenario(binding.scenario_id)
    activity_names = [
        activity.name
        for activity in (get_activity(activity_id) for activity_id in binding.effect.engage_activity_ids)
        if activity is not None
    ]
    return DryRunStep(
        plugin_id=binding.plugin_id,
        plugin_kind=_step_kind(binding),
        surface=binding.surface,
        scenario_id=binding.scenario_id,
        scenario_label=scenario.description if scenario is not None else None,
        engage_activity_names=activity_names,
        expected_adversary_belief=binding.effect.expected_adversary_belief,
        expected_adversary_action=binding.effect.expected_adversary_action,
        success_metric=binding.effect.success_metric,
        leads_to_plugin_id=binding.leads_to_plugin_id,
    )


def _walk_chain(start: PluginBinding, operation: Operation, visited: set[str], *, entry_is_arbitrary: bool) -> DryRunChain:
    steps: list[DryRunStep] = []
    visited_this_chain: set[str] = set()
    current: Optional[PluginBinding] = start
    terminal_reason = "sin_miga_saliente"
    # Tope defensivo: con `visited_this_chain` alcanza para nunca repetir
    # un paso (garantiza terminacion), pero un limite explicito documenta
    # la intencion en vez de confiar solo en el chequeo de membership --
    # mismo criterio de defensa en profundidad que `max_actions_per_event`
    # (M9, `apate.rules.engine`).
    max_steps = len(operation.plugins) + 1

    while current is not None and len(steps) < max_steps:
        if current.plugin_id in visited_this_chain:
            terminal_reason = "ciclo_detectado"
            break
        visited_this_chain.add(current.plugin_id)
        visited.add(current.plugin_id)
        steps.append(_build_step(current, operation))

        next_id = current.leads_to_plugin_id
        if next_id is None:
            terminal_reason = "sin_miga_saliente"
            current = None
            break
        next_binding = operation.find_plugin_binding(next_id)
        if next_binding is None:
            terminal_reason = "miga_rota"
            current = None
            break
        current = next_binding

    return DryRunChain(steps=steps, terminal_reason=terminal_reason, entry_is_arbitrary=entry_is_arbitrary)


def _findings(operation: Operation, chains: list[DryRunChain], incoming_targets: set[str]) -> list[DryRunFinding]:
    findings: list[DryRunFinding] = []

    # TTP esperada (paso 1) que ningun escenario (paso 3) declara cubrir
    # -- nada en el diseño podria producirla, por construccion.
    scenario_ttp_ids = {ttp for scenario in operation.scenarios for ttp in scenario.related_ttps}
    uncovered_ttps = sorted(t for t in operation.adversary_profile.expected_ttps if t not in scenario_ttp_ids)
    if uncovered_ttps:
        findings.append(
            DryRunFinding(
                category="ttp_uncovered",
                severity="gap",
                message=_(
                    "%(count)s TTP(s) esperada(s) sin ningún escenario que las cubra: %(ttps)s.",
                    count=len(uncovered_ttps),
                    ttps=", ".join(uncovered_ttps),
                ),
                anchor="tab-scenarios",
            )
        )

    bindings_by_scenario: dict[str, list[PluginBinding]] = {}
    for binding in operation.plugins:
        if binding.scenario_id:
            bindings_by_scenario.setdefault(binding.scenario_id, []).append(binding)

    for scenario in operation.scenarios:
        scenario_bindings = bindings_by_scenario.get(scenario.id, [])
        has_binding = bool(scenario_bindings)
        if scenario.related_ttps and not has_binding:
            findings.append(
                DryRunFinding(
                    category="scenario_ttps_unreachable",
                    severity="gap",
                    message=_(
                        "El escenario '%(description)s' declara %(count)s TTP(s) esperada(s) pero no tiene "
                        "ninguna capacidad vinculada -- por diseño, ninguna podría llegar a observarse.",
                        description=scenario.description,
                        count=len(scenario.related_ttps),
                    ),
                    anchor="tab-scenarios",
                )
            )
        elif has_binding and not any(b.plugin_id in incoming_targets for b in scenario_bindings):
            findings.append(
                DryRunFinding(
                    category="scenario_no_entry",
                    severity="info",
                    message=_(
                        "Ningún breadcrumb declarado lleva a una capacidad del escenario '%(description)s' -- el "
                        "diseño no muestra cómo llegaría el adversario ahí (puede ser intencional, si es un punto "
                        "de entrada expuesto directo, sin necesitar ninguna miga).",
                        description=scenario.description,
                    ),
                    anchor="tab-scenarios",
                )
            )

    for binding in operation.plugins:
        if binding.scenario_id is None and binding.leads_to_plugin_id is None and binding.plugin_id not in incoming_targets:
            findings.append(
                DryRunFinding(
                    category="isolated_capability",
                    severity="info",
                    message=_(
                        "'%(plugin_id)s' no está vinculada a ningún escenario ni conectada por breadcrumb a "
                        "ninguna otra capacidad -- no forma parte de ninguna historia del recorrido.",
                        plugin_id=binding.plugin_id,
                    ),
                    anchor="tab-plugins",
                )
            )
        if binding.leads_to_plugin_id is not None and operation.find_plugin_binding(binding.leads_to_plugin_id) is None:
            findings.append(
                DryRunFinding(
                    category="broken_breadcrumb",
                    severity="gap",
                    message=_(
                        "'%(plugin_id)s' lleva a '%(target_id)s', que no está vinculado a esta operación -- la "
                        "cadena se corta ahí.",
                        plugin_id=binding.plugin_id,
                        target_id=binding.leads_to_plugin_id,
                    ),
                    anchor="tab-plugins",
                )
            )

    for chain in chains:
        if chain.terminal_reason == "ciclo_detectado" and chain.steps:
            plugin_ids = " -> ".join(step.plugin_id for step in chain.steps)
            findings.append(
                DryRunFinding(
                    category="breadcrumb_cycle",
                    severity="gap",
                    message=_(
                        "Ciclo de breadcrumbs sin fin: %(chain)s -> %(first)s.",
                        chain=plugin_ids,
                        first=chain.steps[0].plugin_id,
                    ),
                    anchor="tab-plugins",
                )
            )

    return findings


def simulate_dry_run(operation: Operation) -> OperationDryRun:
    """Recorre deterministamente las cadenas de breadcrumbs de
    `operation` y detecta huecos de diseño -- ver docstring del modulo.
    Puramente de solo lectura: no muta `operation` ni nada externo."""

    if not operation.scenarios and not operation.plugins:
        return OperationDryRun(chains=[], findings=[], has_content=False)

    incoming_targets: set[str] = set()
    for source in operation.plugins:
        if source.leads_to_plugin_id and operation.find_plugin_binding(source.leads_to_plugin_id) is not None:
            incoming_targets.add(source.leads_to_plugin_id)

    visited: set[str] = set()
    chains: list[DryRunChain] = []

    # Fase 1: cadenas que arrancan en una capacidad raiz (nadie le lleva
    # una miga) -- el caso normal.
    for binding in operation.plugins:
        if binding.plugin_id in incoming_targets or binding.plugin_id in visited:
            continue
        chains.append(_walk_chain(binding, operation, visited, entry_is_arbitrary=False))

    # Fase 2: lo que sobra, si algo sobra, son ciclos cerrados sin ninguna
    # capacidad raiz externa (ver docstring del modulo) -- se recorren
    # igual, explicitos, en vez de quedar fuera en silencio.
    for binding in operation.plugins:
        if binding.plugin_id in visited:
            continue
        chains.append(_walk_chain(binding, operation, visited, entry_is_arbitrary=True))

    findings = _findings(operation, chains, incoming_targets)

    return OperationDryRun(chains=chains, findings=findings, has_content=True)
