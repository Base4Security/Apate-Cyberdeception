"""Regresiones del límite público y de las guardas del motor."""

from pathlib import Path

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.plugins import DeceptionPlugin, EventBus, EventType, PluginEvent
from apate.rules import Action, ActionKind, Condition, Rule, RuleEngine
from apate.core import JSONFileOperationRepository
from apate.telemetry import JSONFileTelemetryRepository
import pytest


class LoopPlugin(DeceptionPlugin):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.rotations = 0

    def deploy(self) -> None:
        pass

    def rotate(self) -> None:
        self.rotations += 1
        self._publish(EventType.INTERACTION, {"kind": "loop"})

    def retire(self) -> None:
        pass


def setup(roe=None, *, bind=True, max_actions=50):
    operation = Operation(
        name="Prueba",
        adversary_profile=AdversaryProfile(name="Actor ficticio"),
        roe=roe or RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    if bind:
        operation.bind_plugin(PluginBinding(plugin_id="mock", surface="network"))
    bus = EventBus()
    plugin = LoopPlugin(plugin_id="mock", surface="network", operation_id=operation.id, bus=bus)
    rule = Rule(
        name="Rotación",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "loop"}),
        then=[Action(kind=ActionKind.ROTATE, plugin_id="mock")],
    )
    engine = RuleEngine(
        operation=operation, plugins={"mock": plugin}, bus=bus,
        rules=[rule], max_actions_per_event=max_actions,
    )
    return operation, bus, plugin, engine


def test_roe_prohibition_blocks_rule_action():
    operation, bus, plugin, engine = setup(RulesOfEngagement(forbidden_actions=["rotate:mock"]))
    bus.publish(PluginEvent(event_type=EventType.INTERACTION, plugin_id="mock", surface="network",
                            operation_id=operation.id, payload={"kind": "loop"}))
    assert plugin.rotations == 0
    assert engine.rejected_actions[0][0] == "roe"


def test_event_from_another_operation_cannot_trigger_action():
    _, bus, plugin, _ = setup()
    bus.publish(PluginEvent(event_type=EventType.INTERACTION, plugin_id="mock", surface="network",
                            operation_id="another-operation", payload={"kind": "loop"}))
    assert plugin.rotations == 0


def test_event_from_unbound_plugin_cannot_trigger_transition():
    operation, bus, plugin, engine = setup()
    bus.publish(PluginEvent(event_type=EventType.INTERACTION, plugin_id="intruder", surface="network",
                            operation_id=operation.id, payload={"kind": "loop"}))
    assert plugin.rotations == 0
    assert engine.rejected_actions == []


def test_unbound_plugin_cannot_be_targeted():
    operation, bus, plugin, _ = setup(bind=False)
    from apate.rules import UnknownPluginError
    import pytest
    with pytest.raises(UnknownPluginError):
        _._resolve_targets("mock")
    assert plugin.rotations == 0


def test_recursive_event_chain_is_bounded():
    operation, bus, plugin, engine = setup(max_actions=3)
    bus.publish(PluginEvent(event_type=EventType.INTERACTION, plugin_id="mock", surface="network",
                            operation_id=operation.id, payload={"kind": "loop"}))
    assert plugin.rotations == 3
    assert engine.rejected_actions[-1][0] == "cascade_limit"


def test_public_package_boundary():
    package = Path(__file__).resolve().parents[1] / "src" / "apate"
    assert {path.name for path in package.iterdir() if path.is_dir() and path.name != "__pycache__"} == {
        "core", "plugins", "rules", "telemetry"
    }


@pytest.mark.parametrize("value", ["../outside", "..\\outside", "", "C:outside"])
def test_local_repositories_reject_unsafe_operation_ids(tmp_path, value):
    for repository in (JSONFileOperationRepository(tmp_path), JSONFileTelemetryRepository(tmp_path)):
        with pytest.raises(ValueError):
            repository._path_for(value)
