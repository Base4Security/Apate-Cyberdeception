from datetime import datetime, timedelta, timezone
from pathlib import Path

from apate.core import (
    AdversaryProfile,
    ClosureCriteria,
    Narrative,
    Operation,
    OperationStatus,
    PluginBinding,
    RulesOfEngagement,
)
from apate.plugins import DeceptionPlugin, EventBus, MockHoneypotPlugin, PluginLifecycleState
from apate.rules import RuleEngine, load_rules

_RULES_PATH = Path(__file__).resolve().parents[1] / "examples" / "rules_example.yaml"


def _make_operation() -> Operation:
    return Operation(
        name="Operacion de prueba end-to-end",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046", "T1078"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


def test_rules_example_yaml_end_to_end_against_mock_plugin():
    """Replica los tres ejemplos de reglas de la seccion 4.3 del
    documento de diseno, encadenados sobre la misma Operacion y el
    mismo MockHoneypotPlugin: escaneo -> deploy + activar; acceso ->
    comprometida; vencimiento -> retirar todo + cerrar."""

    bus = EventBus()
    operation = _make_operation()

    mock1 = MockHoneypotPlugin(
        plugin_id="honeypot-mock-1", surface="network", operation_id=operation.id, bus=bus
    )
    mock2 = MockHoneypotPlugin(
        plugin_id="honeypot-mock-2", surface="network", operation_id=operation.id, bus=bus
    )
    operation.bind_plugin(PluginBinding(plugin_id="honeypot-mock-1", surface="network"))
    operation.bind_plugin(PluginBinding(plugin_id="honeypot-mock-2", surface="network"))

    plugins: dict[str, DeceptionPlugin] = {"honeypot-mock-1": mock1, "honeypot-mock-2": mock2}
    rules = load_rules(str(_RULES_PATH))
    engine = RuleEngine(operation=operation, plugins=plugins, bus=bus, rules=rules)

    # 1. "si se detecta escaneo -> desplegar señuelo y activar la operacion".
    assert operation.status == OperationStatus.PLANNING
    mock1.deploy()

    assert mock1.state == PluginLifecycleState.DEPLOYED
    assert mock2.state == PluginLifecycleState.DEPLOYED  # desplegado por la regla, no a mano
    assert operation.status == OperationStatus.ACTIVE

    # 2. "si se produce acceso a un honeytoken -> marcar comprometida".
    mock1.simulate_access(ttp_id="T1078")

    assert operation.status == OperationStatus.COMPROMISED

    # 3. "si la operacion vence sin cierre -> retirar todo y cerrar".
    operation.closure_criteria = ClosureCriteria(
        end_date=datetime.now(timezone.utc) - timedelta(days=1)
    )
    engine.check_closure()

    assert mock1.state == PluginLifecycleState.RETIRED
    assert mock2.state == PluginLifecycleState.RETIRED
    assert operation.status == OperationStatus.CLOSED
