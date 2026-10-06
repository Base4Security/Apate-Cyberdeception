from apate.plugins import EventType, PluginEvent


def _seed_event(app, **overrides):
    defaults = dict(
        event_type=EventType.INTERACTION,
        plugin_id="honeypot-mock-1",
        surface="network",
        operation_id="op-1",
        payload={"kind": "scan", "source_ip": "203.0.113.10"},
    )
    defaults.update(overrides)
    app.config["TELEMETRY_COLLECTOR"].handle_event(PluginEvent(**defaults))
    return app.config["TELEMETRY_COLLECTOR"].list_events("op-1")[-1]


def test_set_tlp_on_event_shows_badge(client, app):
    event = _seed_event(app)

    response = client.post(
        "/telemetry/op-1/tlp",
        data={"subject_type": "event", "subject_key": event.id, "level": "red", "view": "events"},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'tlp-badge tlp-red' in text
    assert "TLP:RED" in text
    assert app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation("op-1")[0].level.value == "red"


def test_set_tlp_on_ioc_shows_badge(client, app):
    event = _seed_event(app, payload={"kind": "scan", "source_ip": "203.0.113.10"})
    subject_key = "ip:203.0.113.10"

    response = client.post(
        "/telemetry/op-1/tlp",
        data={"subject_type": "ioc", "subject_key": subject_key, "level": "amber", "view": "iocs"},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert 'tlp-badge tlp-amber' in text
    saved = app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation("op-1")
    assert saved[0].subject_type == "ioc"
    assert saved[0].subject_key == subject_key
    assert saved[0].level.value == "amber"


def test_changing_tlp_level_upserts_not_appends(client, app):
    event = _seed_event(app)
    client.post("/telemetry/op-1/tlp", data={"subject_type": "event", "subject_key": event.id, "level": "red"})

    client.post("/telemetry/op-1/tlp", data={"subject_type": "event", "subject_key": event.id, "level": "green"})

    saved = app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation("op-1")
    assert len(saved) == 1
    assert saved[0].level.value == "green"


def test_clearing_tlp_level_removes_classification(client, app):
    event = _seed_event(app)
    client.post("/telemetry/op-1/tlp", data={"subject_type": "event", "subject_key": event.id, "level": "red"})

    response = client.post(
        "/telemetry/op-1/tlp",
        data={"subject_type": "event", "subject_key": event.id, "level": ""},
        follow_redirects=True,
    )

    assert app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation("op-1") == []
    assert 'tlp-badge' not in response.get_data(as_text=True)


def test_set_tlp_rejects_invalid_subject_type(client, app):
    event = _seed_event(app)

    response = client.post(
        "/telemetry/op-1/tlp",
        data={"subject_type": "not-a-real-type", "subject_key": event.id, "level": "red"},
        follow_redirects=True,
    )

    assert "inv" in response.get_data(as_text=True).lower()
    assert app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation("op-1") == []


def test_set_tlp_rejects_invalid_level(client, app):
    event = _seed_event(app)

    response = client.post(
        "/telemetry/op-1/tlp",
        data={"subject_type": "event", "subject_key": event.id, "level": "purple"},
        follow_redirects=True,
    )

    assert "nivel" in response.get_data(as_text=True).lower()
    assert app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation("op-1") == []


def test_unclassified_event_shows_no_badge(client, app):
    _seed_event(app)

    text = client.get("/telemetry/op-1?view=events").get_data(as_text=True)

    assert "tlp-badge" not in text
    assert "Sin clasificar" in text


def test_tlp_set_by_uses_current_operator_session(client, app):
    event = _seed_event(app)
    client.post("/operator", data={"operator": "ana"}, follow_redirects=True)

    client.post("/telemetry/op-1/tlp", data={"subject_type": "event", "subject_key": event.id, "level": "red"})

    saved = app.config["TLP_CLASSIFICATION_REPOSITORY"].list_for_operation("op-1")
    assert saved[0].set_by == "ana"
