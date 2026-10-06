from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.plugins import EventType, PluginEvent


def _operation(app, name: str, expected_ttps: list[str]) -> Operation:
    operation = Operation(
        name=name,
        adversary_profile=AdversaryProfile(name=f"Actor {name}", expected_ttps=expected_ttps),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def test_compare_requires_two_distinct_operations(client, app):
    operation = _operation(app, "Uno", ["T1078"])
    text = client.get(f"/operations/compare?left={operation.id}&right={operation.id}").get_data(as_text=True)
    assert "dos operaciones distintas" in text


def test_compare_shows_each_real_ttp_set_without_score(client, app):
    left = _operation(app, "Izquierda", ["T1078", "T1005"])
    right = _operation(app, "Derecha", ["T1057"])
    app.config["TELEMETRY_COLLECTOR"].handle_event(
        PluginEvent(event_type=EventType.TTP_OBSERVED, operation_id=left.id, plugin_id="mock-1", surface="network", payload={"ttp_id": "T1078"})
    )
    text = client.get(f"/operations/compare?left={left.id}&right={right.id}").get_data(as_text=True)
    assert "Izquierda" in text and "Derecha" in text
    assert "T1078" in text and "T1005" in text and "T1057" in text
    assert "no punt" in text
    assert "score" not in text.casefold()
