"""La bandeja conserva evidencia profunda y exige transiciones humanas."""

from apate.plugins.base import EventType, PluginEvent


def _operation(client):
    response = client.post("/operations/new", data={"name": "Atención de prueba", "adversary_name": "APT", "narrative_name": "Historia"})
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_attention_web_flow_and_cross_operation_guard(app, client):
    operation_id = _operation(client)
    other_id = _operation(client)
    collector = app.config["TELEMETRY_COLLECTOR"]
    collector.handle_event(PluginEvent(event_type=EventType.INTERACTION, operation_id=operation_id,
                                       plugin_id="honeyuser-1", surface="identity", resource_id="sid-1",
                                       payload={"kind": "honeyuser_authentication_success"}))
    event_id = collector.list_events(operation_id)[0].id
    signals = app.config["ATTENTION_REPOSITORY"].list_signals(operation_id)
    assert len(signals) == 1
    assert signals[0].origin == "rule"
    page = client.get(f"/operations/{operation_id}/attention")
    assert page.status_code == 200
    assert f"event_id={event_id}".encode() in page.data
    assert b"Autenticaci" in client.get(f"/operations/{operation_id}").data

    created = client.post(f"/operations/{operation_id}/attention/signals",
                          data={"title": "Revisar origen", "severity": "medium", "event_ids": event_id})
    assert created.status_code == 302
    manual = next(signal for signal in app.config["ATTENTION_REPOSITORY"].list_signals(operation_id) if signal.origin == "manual")
    assert client.post(f"/operations/{other_id}/attention/signals/{manual.id}/acknowledge").status_code == 404
    assert client.post(f"/operations/{operation_id}/attention/signals/{manual.id}/acknowledge").status_code == 302
    assert app.config["ATTENTION_REPOSITORY"].get_signal(operation_id, manual.id).status == "acknowledged"
    client.post(f"/operations/{operation_id}/attention/signals/{manual.id}/resolve", data={"note": "investigado"})
    assert app.config["ATTENTION_REPOSITORY"].get_signal(operation_id, manual.id).status == "resolved"

    client.post(f"/operations/{operation_id}/attention/cases", data={"title": "Caso", "signal_ids": manual.id})
    case = app.config["ATTENTION_REPOSITORY"].list_cases(operation_id)[0]
    assert case.signal_ids == [manual.id]
    inbox = client.get("/attention")
    assert inbox.status_code == 200
    assert b"Caso" in inbox.data
    handoff = client.get(f"/operations/{operation_id}/attention/cases/{case.id}/handoff.json")
    assert handoff.status_code == 200
    assert handoff.json["schema"] == "apate.soc.handoff.v1"
    assert handoff.json["event_summaries"][0]["id"] == event_id
    assert client.post(f"/operations/{other_id}/attention/cases/{case.id}/resolve", data={"note": "cerrado"}).status_code == 404
    assert app.config["OPERATOR_ACTION_REPOSITORY"].verify(operation_id).status == "valid"


def test_soc_inbox_filters_and_opens_exact_case(app, client):
    first = _operation(client)
    second = _operation(client)
    for operation_id, title, severity in ((first, "Caso crítico", "critical"),
                                          (second, "Caso leve", "low")):
        client.post(f"/operations/{operation_id}/attention/signals",
                    data={"title": title, "severity": severity, "note": "Evidencia humana"})
        signal = app.config["ATTENTION_REPOSITORY"].list_signals(operation_id)[0]
        client.post(f"/operations/{operation_id}/attention/cases",
                    data={"title": title, "signal_ids": signal.id})
    case = app.config["ATTENTION_REPOSITORY"].list_cases(first)[0]
    client.post(f"/operations/{first}/attention/cases/{case.id}/assign", data={"responsible": "Ana"})

    inbox = client.get("/attention?severity=critical&responsible=Ana")
    assert inbox.status_code == 200
    assert b"Caso cr" in inbox.data
    assert b"Caso leve" not in inbox.data
    assert f"/operations/{first}/attention/cases/{case.id}".encode() in inbox.data

    detail = client.get(f"/operations/{first}/attention/cases/{case.id}")
    assert detail.status_code == 200
    assert b"Evidencia humana" in detail.data
    assert b"Cerrar caso" in detail.data
    assert client.get(f"/operations/{second}/attention/cases/{case.id}").status_code == 404
    closed = client.post(f"/operations/{first}/attention/cases/{case.id}/resolve", data={"note": "Investigado"})
    assert closed.headers["Location"].endswith(f"/operations/{first}/attention/cases/{case.id}")


def test_soc_inbox_paginates_without_losing_filters(app, client):
    operation_id = _operation(client)
    for index in range(26):
        client.post(f"/operations/{operation_id}/attention/signals",
                    data={"title": f"Señal {index}", "severity": "medium", "note": "Revisar"})
        signal = next(item for item in app.config["ATTENTION_REPOSITORY"].list_signals(operation_id)
                      if item.title == f"Señal {index}")
        client.post(f"/operations/{operation_id}/attention/cases",
                    data={"title": f"Caso {index}", "signal_ids": signal.id})
    first_page = client.get(f"/attention?operation_id={operation_id}")
    second_page = client.get(f"/attention?operation_id={operation_id}&page=2")
    assert first_page.status_code == second_page.status_code == 200
    assert first_page.data.count(b"soc-case-card\"") == 25
    assert second_page.data.count(b"soc-case-card\"") == 1
    assert b"operation_id=" in first_page.data
