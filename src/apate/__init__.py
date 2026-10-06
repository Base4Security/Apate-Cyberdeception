"""Apate Core: operaciones, plugins, reglas y telemetría básica."""

from .core import (
    AdversaryProfile,
    ClosureCriteria,
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
)
from .plugins import (
    DeceptionPlugin,
    EventBus,
    EventType,
    MockHoneypotPlugin,
    PluginEvent,
    PluginLifecycleState,
)
from .rules import (
    Action,
    ActionKind,
    Condition,
    Rule,
    RuleEngine,
    load_rules,
    parse_rules,
)
from .telemetry import (
    IoC,
    JSONFileTelemetryRepository,
    TelemetryCollector,
    TelemetryRecord,
    TelemetryRepository,
)

__version__ = "0.1.0a2"

__all__ = [
    "Action",
    "ActionKind",
    "AdversaryProfile",
    "ClosureCriteria",
    "Condition",
    "DeceptionLevel",
    "DeceptionPlugin",
    "Environment",
    "EventBus",
    "EventType",
    "IoC",
    "JSONFileOperationRepository",
    "JSONFileTelemetryRepository",
    "MockHoneypotPlugin",
    "Narrative",
    "Operation",
    "OperationRepository",
    "OperationStatus",
    "PluginBinding",
    "PluginEvent",
    "PluginLifecycleState",
    "Rule",
    "RuleEngine",
    "RulesOfEngagement",
    "Scenario",
    "TelemetryCollector",
    "TelemetryRecord",
    "TelemetryRepository",
    "load_rules",
    "parse_rules",
    "__version__",
]
