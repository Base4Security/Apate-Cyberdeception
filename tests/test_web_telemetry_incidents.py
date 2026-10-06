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


def test_incidents_tab_appears_in_nav_and_starts_empty(client, app):
    _seed_event(app)

    text = client.get("/telemetry/op-1").get_data(as_text=True)

    assert 'view=incidents' in text
    assert "Sin incidentes todav" in text
    assert "Incidentes <span" in text


def test_create_incident_from_selected_events(client, app):
    first = _seed_event(app, payload={"kind": "scan", "source_ip": "203.0.113.10"})
    _seed_event(app, payload={"kind": "otro"})

    response = client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [first.id], "mode": "new", "name": "Barrido sospechoso", "notes": "Misma IP dos veces."},
        follow_redirects=True,
    )

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "Barrido sospechoso" in text
    assert "Misma IP dos veces." in text
    assert "1 evento(s)" in text


def test_create_incident_requires_at_least_one_known_event(client, app):
    _seed_event(app)

    response = client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [], "mode": "new", "name": "Vacío"},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert "eleg" in text.lower()


def test_create_incident_ignores_unknown_event_ids(client, app):
    _seed_event(app)

    response = client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": ["no-existe"], "mode": "new", "name": "Cualquiera"},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert "eleg" in text.lower()
    assert "Cualquiera" not in text


def test_create_incident_requires_a_name(client, app):
    event = _seed_event(app)

    response = client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [event.id], "mode": "new", "name": "  "},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert "nombre" in text.lower()


def test_add_events_to_existing_incident(client, app):
    first = _seed_event(app, payload={"kind": "a"})
    second = _seed_event(app, payload={"kind": "b"})
    client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [first.id], "mode": "new", "name": "Original"},
    )
    incident_id = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")[0].id

    response = client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [second.id], "mode": "existing", "incident_id": incident_id},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert "2 evento(s)" in text
    incidents = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")
    assert len(incidents) == 1
    assert sorted(incidents[0].event_ids) == sorted([first.id, second.id])


def test_add_events_to_existing_incident_deduplicates(client, app):
    event = _seed_event(app)
    client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [event.id], "mode": "new", "name": "Original"},
    )
    incident_id = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")[0].id

    client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [event.id], "mode": "existing", "incident_id": incident_id},
    )

    incidents = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")
    assert incidents[0].event_ids == [event.id]


def test_add_events_to_unknown_existing_incident_flashes_error(client, app):
    event = _seed_event(app)

    response = client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [event.id], "mode": "existing", "incident_id": "no-existe"},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert "ya no existe" in text.lower()


def test_update_incident_name_and_notes(client, app):
    event = _seed_event(app)
    client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [event.id], "mode": "new", "name": "Original"},
        follow_redirects=True,
    )
    incident_id = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")[0].id

    response = client.post(
        f"/telemetry/op-1/incidents/{incident_id}/update",
        data={"name": "Renombrado", "notes": "Notas nuevas."},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert "Renombrado" in text
    assert "Notas nuevas." in text
    assert "Original" not in text


def test_update_incident_rejects_empty_name(client, app):
    event = _seed_event(app)
    client.post("/telemetry/op-1/incidents", data={"event_ids": [event.id], "mode": "new", "name": "Original"})
    incident_id = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")[0].id

    response = client.post(
        f"/telemetry/op-1/incidents/{incident_id}/update",
        data={"name": "   ", "notes": "x"},
        follow_redirects=True,
    )

    incidents = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")
    assert incidents[0].name == "Original"
    assert "nombre" in response.get_data(as_text=True).lower()


def test_update_unknown_incident_flashes_error(client, app):
    response = client.post(
        "/telemetry/op-1/incidents/no-existe/update",
        data={"name": "x"},
        follow_redirects=True,
    )

    assert "ya no existe" in response.get_data(as_text=True).lower()


def test_remove_event_from_incident(client, app):
    first = _seed_event(app, payload={"kind": "a"})
    second = _seed_event(app, payload={"kind": "b"})
    client.post(
        "/telemetry/op-1/incidents",
        data={"event_ids": [first.id, second.id], "mode": "new", "name": "Grupo"},
    )
    incident_id = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")[0].id

    client.post(f"/telemetry/op-1/incidents/{incident_id}/remove-event", data={"event_id": first.id})

    incidents = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")
    assert incidents[0].event_ids == [second.id]


def test_delete_incident_removes_grouping_not_events(client, app):
    event = _seed_event(app)
    client.post("/telemetry/op-1/incidents", data={"event_ids": [event.id], "mode": "new", "name": "Efímero"})
    incident_id = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")[0].id

    response = client.post(f"/telemetry/op-1/incidents/{incident_id}/delete", follow_redirects=True)

    assert app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1") == []
    assert len(app.config["TELEMETRY_COLLECTOR"].list_events("op-1")) == 1
    assert "eliminado" in response.get_data(as_text=True).lower()


def test_delete_incident_is_idempotent(client, app):
    response = client.post("/telemetry/op-1/incidents/no-existe/delete", follow_redirects=True)
    assert response.status_code == 200


def test_incident_with_missing_event_reports_broken_reference(client, app):
    event = _seed_event(app)
    client.post("/telemetry/op-1/incidents", data={"event_ids": [event.id], "mode": "new", "name": "Grupo"})
    incident_id = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")[0].id
    # Sacar el evento de la telemetria simulando que la fuente ya no lo tiene
    # (el repositorio de incidentes no conoce ni valida contra la telemetria).
    incident = app.config["INCIDENT_REPOSITORY"].list_for_operation("op-1")[0]
    incident.event_ids.append("evento-fantasma")
    app.config["INCIDENT_REPOSITORY"].save(incident)

    text = client.get("/telemetry/op-1?view=incidents").get_data(as_text=True)

    assert "referencia" in text.lower()


def test_incident_group_button_present_in_events_view(client, app):
    _seed_event(app)

    text = client.get("/telemetry/op-1?view=events").get_data(as_text=True)

    assert "data-group-incident" in text
    assert 'id="incident-dialog"' in text
