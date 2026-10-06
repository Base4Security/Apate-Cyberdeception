"""APATE - plataforma de orquestacion para operaciones de ciberengano.

Ver el documento de diseno ("APATE - Documento de diseno.md") y el
roadmap ("APATE - Roadmap de implementacion.md") para el contexto
completo. Este paquete implementa, por ahora, M1 (Nucleo de
Operacion), M2 (interfaz de plugins + plugin mock), M3 (motor de
decision - reglas deterministas), M4 (telemetria y correlacion), M6
(retroalimentacion CTI), M7 (plugin de honeytokens), M8c (adaptadores
DolosTPlugin/BudaPlugin) y M10 (`StrategicDecisions`/`DeceptionEffect`,
campos de modelo que completan el producto de cada paso de la
metodologia CTI-a-ciberengano -- ver docs/analisis-metodologia-cti.md).
apate.web (M4b) y apate.playground (M5) no se re-exportan aca: son
subsistemas que se importan explicitamente por su propio nombre, no
parte de esta superficie de libreria.

Desde M8c, `import apate` requiere que `DOLOST` y `BUDA` esten
instalados (dependencias editables locales obligatorias, no
opcionales -- ver pyproject.toml y docs/diseno.md seccion 4.5): este
paquete deja de ser "liviano" a partir de aca, por decision explicita
de arquitectura (un unico proceso), no por descuido.
"""

from .audit import AuditVerification, JSONFileOperatorActionRepository, OperatorAction, OperatorActionRepository
from .identity import Identity, IdentityRole
from .core import (
    AdversaryProfile,
    ClosureCriteria,
    DeceptionEffect,
    DeceptionLevel,
    Environment,
    JSONFileOperationRepository,
    Narrative,
    Operation,
    OperationRepository,
    OperationStatus,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
    StrategicDecisions,
    StrategicObjective,
)
from .plugins import (
    BudaPlugin,
    DeceptionPlugin,
    DolosTPlugin,
    EventBus,
    EventType,
    HoneytokenPlugin,
    MockHoneypotPlugin,
    PluginEvent,
    PluginLifecycleState,
    PluginRegistry,
)
from .reporting import (
    OperationReport,
    PluginEffectSummary,
    TTPComparison,
    WorkshopKit,
    compare_ttps,
    generate_report,
    generate_workshop_kit,
    plugin_effect_summaries,
)
from .rules import (
    Action,
    ActionKind,
    Condition,
    Rule,
    RuleEngine,
    SQLiteRuleDecisionRepository,
    load_rules,
    parse_rules,
)
from .telemetry import (
    IoC,
    JSONFileTelemetryRepository,
    SQLiteTelemetryRepository,
    TelemetryCollector,
    TelemetryRecord,
    TelemetryRepository,
)

__version__ = "0.1.0rc1"

__all__ = [
    "Action",
    "ActionKind",
    "AdversaryProfile",
    "AuditVerification",
    "BudaPlugin",
    "ClosureCriteria",
    "Condition",
    "DeceptionEffect",
    "DeceptionLevel",
    "DeceptionPlugin",
    "DolosTPlugin",
    "Environment",
    "EventBus",
    "EventType",
    "HoneytokenPlugin",
    "Identity",
    "IdentityRole",
    "IoC",
    "JSONFileOperationRepository",
    "JSONFileOperatorActionRepository",
    "JSONFileTelemetryRepository",
    "MockHoneypotPlugin",
    "Narrative",
    "Operation",
    "OperationRepository",
    "OperationReport",
    "OperationStatus",
    "OperatorAction",
    "OperatorActionRepository",
    "PluginBinding",
    "PluginEffectSummary",
    "PluginEvent",
    "PluginLifecycleState",
    "PluginRegistry",
    "Rule",
    "RuleEngine",
    "RulesOfEngagement",
    "Scenario",
    "SQLiteTelemetryRepository",
    "SQLiteRuleDecisionRepository",
    "StrategicDecisions",
    "StrategicObjective",
    "TelemetryCollector",
    "TelemetryRecord",
    "TelemetryRepository",
    "TTPComparison",
    "WorkshopKit",
    "compare_ttps",
    "generate_report",
    "generate_workshop_kit",
    "load_rules",
    "parse_rules",
    "plugin_effect_summaries",
    "__version__",
]
