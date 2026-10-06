from apate.plugins import EventType, PluginEvent


def _seed_event(app, **overrides) -> None:
    defaults = dict(
        event_type=EventType.INTERACTION,
        plugin_id="honeypot-mock-1",
        surface="network",
        operation_id="op-1",
        payload={"kind": "scan", "source_ip": "203.0.113.10"},
    )
    defaults.update(overrides)
    app.config["TELEMETRY_COLLECTOR"].handle_event(PluginEvent(**defaults))


def test_telemetry_index_returns_200(client):
    response = client.get("/telemetry/")
    assert response.status_code == 200


def test_telemetry_detail_returns_200_for_operation_without_events(client):
    response = client.get("/telemetry/no-existe")
    assert response.status_code == 200
    assert b"Sin eventos registrados" in response.data


def test_telemetry_detail_lists_events_iocs_and_ttps(client, app):
    _seed_event(app, payload={"kind": "scan", "source_ip": "203.0.113.10"})
    _seed_event(app, event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1078"})

    response = client.get("/telemetry/op-1")

    assert response.status_code == 200
    assert b"203.0.113.10" in response.data
    assert b"T1078" in response.data
    assert b"honeypot-mock-1" in response.data


def test_telemetry_detail_filters_by_plugin_id(client, app):
    _seed_event(app, plugin_id="honeypot-mock-1", payload={"kind": "scan"})
    _seed_event(app, plugin_id="honeypot-mock-2", payload={"kind": "scan"})

    response = client.get("/telemetry/op-1?plugin_id=honeypot-mock-2")

    assert response.status_code == 200
    assert b"Eventos (1)" in response.data


def test_telemetry_detail_filters_by_surface(client, app):
    _seed_event(app, surface="network", payload={"kind": "scan"})
    _seed_event(app, surface="identity", payload={"kind": "scan"})

    response = client.get("/telemetry/op-1?surface=identity")

    assert response.status_code == 200
    assert b"Eventos (1)" in response.data


def test_telemetry_index_shows_created_operation(client):
    client.post(
        "/operations/new",
        data=dict(
            name="Operacion telemetria",
            adversary_name="APT ficticio",
            narrative_name="Narrativa base",
        ),
    )
    response = client.get("/telemetry/")
    assert b"Operacion telemetria" in response.data
