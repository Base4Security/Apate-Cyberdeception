"""El historial se reproduce con el motor real y dobles sin efectos."""

from datetime import datetime, timezone

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.plugins import EventType, PluginEvent
from apate.rules import replay_rules, RuleRevisionRepository
from apate.telemetry.models import TelemetryRecord


RULES = """
rules:
  - name: responder
    when:
      event_type: interaction
      plugin_id: mock-1
      payload:
        kind: access
    then:
      - action: rotate
        plugin_id: mock-1
"""


def _operation():
    operation = Operation(name="Replay", adversary_profile=AdversaryProfile(name="APT"),
                          roe=RulesOfEngagement(forbidden_actions=["rotate"]),
                          narrative=Narrative(name="Historia"))
    operation.bind_plugin(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="host"))
    return operation


def test_replay_is_repeatable_and_does_not_mutate_operation(tmp_path):
    operation = _operation()
    original = operation.to_dict()
    event = PluginEvent(event_type=EventType.INTERACTION, operation_id=operation.id,
                        plugin_id="mock-1", surface="host", payload={"kind": "access"},
                        timestamp=datetime(2026, 9, 15, tzinfo=timezone.utc))
    record = TelemetryRecord.from_event(event)
    first = replay_rules(operation, [record], RULES)
    assert first == replay_rules(operation, [record], RULES)
    assert operation.to_dict() == original
    assert first["firings"][0]["triggering_event_id"] == event.id
    assert first["rejections"][0]["kind"] == "roe"
    assert first["plugin_attempts"] == []
    assert not list(tmp_path.iterdir())


def test_revision_is_immutable_and_web_replay_is_read_only(app, client):
    revisions: RuleRevisionRepository = app.config["RULE_REVISION_REPOSITORY"]
    revision = revisions.save(RULES)
    assert revisions.get(revision) == RULES
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)
    page = client.get(f"/rules/replay/{operation.id}?revision={revision}")
    assert page.status_code == 200
    assert b"Reproducir reglas" in page.data
    assert client.get(f"/rules/replay/{operation.id}?revision=../fuera").status_code == 404
