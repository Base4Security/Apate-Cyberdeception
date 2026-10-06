from datetime import datetime, timedelta, timezone

from apate.core import PluginBinding, Scenario
from apate.plugins import EventType, PluginEvent
from apate.plugins import buda_plugin as buda_module


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
    assert b"No hay eventos persistidos" in response.data


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
    assert b'id="telemetry-events-title">Eventos <span class="summary-count-badge">1</span>' in response.data


def test_telemetry_detail_filters_by_surface(client, app):
    _seed_event(app, surface="network", payload={"kind": "scan"})
    _seed_event(app, surface="identity", payload={"kind": "scan"})

    response = client.get("/telemetry/op-1?surface=identity")

    assert response.status_code == 200
    assert b'id="telemetry-events-title">Eventos <span class="summary-count-badge">1</span>' in response.data


def test_telemetry_event_deep_link_filters_and_opens_exact_inspector(client, app):
    _seed_event(app, resource_id="decoy:srv-1", payload={"kind": "access", "detail": "exacto"})
    _seed_event(app, resource_id="decoy:srv-2", payload={"kind": "access", "detail": "otro"})
    event = app.config["TELEMETRY_COLLECTOR"].list_events("op-1")[0]

    text = client.get(f"/telemetry/op-1?view=events&event_id={event.id}").get_data(as_text=True)

    assert "1 evento(s) coinciden" in text
    assert f"ID de evento: {event.id}" in text
    assert 'id="event_id" name="event_id"' in text
    assert 'const selectedEventId = "' + event.id + '"' in text
    assert "decoy:srv-1" in text
    assert "decoy:srv-2" not in text


def test_telemetry_events_view_marks_inspector_layout_when_event_is_selected(client, app):
    _seed_event(app, payload={"kind": "scan", "source_ip": "203.0.113.10", "detail": "prueba"})

    event = app.config["TELEMETRY_COLLECTOR"].list_events("op-1")[0]
    text = client.get(f"/telemetry/op-1?view=events&event_id={event.id}").get_data(as_text=True)

    assert "setInspectorVisibility(true)" in text
    assert "classList.toggle('has-inspection', !!open)" in text
    assert "telemetry-events-layout" in text


def test_telemetry_detail_shows_kpi_cards_with_correct_counts(client, app):
    _seed_event(app, payload={"kind": "scan", "source_ip": "203.0.113.10"})
    _seed_event(app, event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1078"})

    response = client.get("/telemetry/op-1")
    text = response.data.decode()

    assert response.status_code == 200
    assert 'class="card kpi-card"' in text
    assert '<dd class="kpi-value">2</dd>' in text  # eventos (scan + ttp_observed)
    assert '<dd class="kpi-value">1</dd>' in text  # TTPs observadas


def test_telemetry_detail_shows_ttps_as_tags(client, app):
    _seed_event(app, event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1078"})

    response = client.get("/telemetry/op-1")
    text = response.data.decode()

    assert '>T1078</a>' in text
    assert "ttp_id=T1078" in text


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


def test_telemetry_detail_combines_search_type_ttp_and_date_filters(client, app):
    _seed_event(app, payload={"kind": "scan", "source_ip": "203.0.113.10"})
    _seed_event(
        app,
        event_type=EventType.TTP_OBSERVED,
        plugin_id="identity-1",
        surface="identity",
        payload={"ttp_id": "T1078", "credential": "decoy-user"},
    )
    response = client.get(
        "/telemetry/op-1?event_type=ttp_observed&ttp_id=T1078&q=decoy-user&date_from=2000-01-01&date_to=2999-01-01"
    )
    text = response.data.decode()
    assert "1 evento(s) coinciden" in text
    assert "identity-1" in text
    events_table = text.split('id="telemetry-events-title"', 1)[1]
    assert "honeypot-mock-1" not in events_table
    assert "Limpiar filtros" in text


def test_telemetry_empty_state_links_to_operation_workflow(client):
    text = client.get("/telemetry/no-existe").data.decode()
    assert 'class="empty-state"' in text
    assert "Revisar capacidades y despliegues" in text


def test_telemetry_exports_exactly_the_filtered_events_as_json_and_csv(client, app):
    _seed_event(app, plugin_id="keep", payload={"kind": "scan", "source_ip": "203.0.113.10"})
    _seed_event(app, plugin_id="drop", payload={"kind": "scan", "source_ip": "198.51.100.20"})
    json_response = client.get("/telemetry/op-1?plugin_id=keep&format=json")
    assert [item["plugin_id"] for item in json_response.get_json()] == ["keep"]
    csv_response = client.get("/telemetry/op-1?plugin_id=keep&format=csv")
    assert csv_response.mimetype == "text/csv"
    assert b"203.0.113.10" in csv_response.data
    assert b"198.51.100.20" not in csv_response.data
    assert "attachment" in csv_response.headers["Content-Disposition"]


def test_telemetry_filter_page_preserves_export_query(client, app):
    _seed_event(app, plugin_id="keep", payload={"kind": "scan"})
    text = client.get("/telemetry/op-1?plugin_id=keep&q=scan").get_data(as_text=True)
    assert "Exportar CSV" in text and "Exportar JSON" in text
    assert "plugin_id=keep" in text and "q=scan" in text


def test_telemetry_has_local_saved_views_and_non_disruptive_refresh(client, app):
    _seed_event(app, plugin_id="keep")
    text = client.get("/telemetry/op-1?plugin_id=keep").get_data(as_text=True)
    assert 'id="saved-view-select"' in text
    assert "apate-telemetry-views:op-1" in text
    assert "window.setInterval(checkNewEvents, 30000)" in text
    assert "evento(s) nuevo(s)" in text
    assert "window.location.reload()" in text


def test_telemetry_event_rows_support_non_destructive_selection(client, app):
    _seed_event(app, plugin_id="one")
    _seed_event(app, plugin_id="two")
    text = client.get("/telemetry/op-1").get_data(as_text=True)
    assert text.count("data-select-event") >= 2
    assert "data-select-all" in text
    assert "data-copy-selected" in text
    assert "data-export-selected" in text
    assert "telemetry-selected.tsv" in text


def test_telemetry_events_page_exposes_row_inspector_payloads(client, app):
    _seed_event(app, payload={"kind": "scan", "source_ip": "203.0.113.10", "detail": "prueba de contexto", "ttp_id": "T1078"})
    text = client.get("/telemetry/op-1?view=events").get_data(as_text=True)

    assert 'id="telemetry-events-title"' in text
    assert 'id="telemetry-event-inspector"' in text
    assert 'data-inspect-event' in text
    assert 'id="telemetry-event-data-' in text
    assert "renderInspector" in text


def test_telemetry_index_has_searchable_operation_picker(client):
    client.post(
        "/operations/new",
        data=dict(name="Operacion analizable", adversary_name="APT", narrative_name="Narrativa"),
    )
    text = client.get("/telemetry/?q=analizable").get_data(as_text=True)

    assert 'id="telemetry-operation-search"' in text
    assert 'data-telemetry-operation' in text
    assert 'id="telemetry-operation-count" role="status" aria-live="polite"' in text
    assert "params.get('q')" in text and "history.replaceState" in text


def test_telemetry_filters_use_progressive_disclosure_and_visible_chips(client, app):
    _seed_event(app, plugin_id="identity-1", surface="identity")
    text = client.get("/telemetry/op-1?plugin_id=identity-1&surface=identity").get_data(as_text=True)

    assert 'class="telemetry-filter-disclosure" open' in text
    assert "2 activo(s)" in text
    assert 'aria-label="Filtros activos"' in text
    assert "Capacidad: identity-1" in text and "Superficie: identity" in text
    assert 'class="telemetry-filter-footer"' in text
    assert 'class="panel telemetry-data-section telemetry-events-section"' in text


def test_telemetry_exposes_five_operation_scoped_views(client):
    for view, label in (
        ("summary", "Resumen"),
        ("live", "En vivo"),
        ("events", "Eventos"),
        ("iocs", "IoCs"),
        ("ttps", "TTP observadas"),
    ):
        response = client.get(f"/telemetry/op-1?view={view}")
        assert response.status_code == 200
        assert f'aria-current="page">{label}</a>'.encode() in response.data


def test_live_index_selects_operation_before_showing_activity(client):
    client.post(
        "/operations/new",
        data={"name": "Operación en vivo", "adversary_name": "APT", "narrative_name": "Narrativa"},
    )
    text = client.get("/telemetry/live").get_data(as_text=True)
    assert "Actividad en vivo" in text
    assert "view=live" in text
    assert "La telemetr&iacute;a permanece aislada por operaci&oacute;n" in text


def test_telemetry_filters_provider_scenario_kind_and_period(client, app):
    created = client.post(
        "/operations/new",
        data={"name": "Operación filtrable", "adversary_name": "APT", "narrative_name": "Narrativa"},
    )
    operation_id = created.headers["Location"].rsplit("/", 1)[-1]
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    scenario = Scenario(description="Escenario identidad", id="scenario-identity")
    operation.add_scenario(scenario)
    operation.bind_plugin(
        PluginBinding(
            plugin_id="identity-1",
            plugin_kind="buda",
            surface="identity",
            scenario_id=scenario.id,
            config={"narrative_id": 9},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    _seed_event(
        app,
        operation_id=operation_id,
        plugin_id="identity-1",
        surface="identity",
        payload={"kind": "credential_use", "detail": "reciente"},
    )
    _seed_event(
        app,
        operation_id=operation_id,
        plugin_id="identity-1",
        surface="identity",
        timestamp=datetime.now(timezone.utc) - timedelta(days=2),
        payload={"kind": "other", "detail": "antiguo"},
    )

    response = client.get(
        f"/telemetry/{operation_id}?view=events&provider=APATE&scenario_id={scenario.id}"
        "&event_kind=credential_use&period=24h"
    )
    text = response.get_data(as_text=True)
    assert "1 evento(s) coinciden" in text
    assert "reciente" in text and "antiguo" not in text
    # El chip muestra la etiqueta del proveedor ("Apate"), pero el
    # filtro se pidio con el valor crudo `provider=APATE` y filtro bien -- las
    # dos mitades de la fase 4 del renombre, verificadas juntas.
    assert "Proveedor: Apate" in text and "Escenario: scenario-identity" in text
    assert 'value="APATE"' in text


def test_live_feed_marks_events_already_persisted(client, app, monkeypatch):
    created = client.post(
        "/operations/new",
        data={"name": "Operación BUDA", "adversary_name": "APT", "narrative_name": "Narrativa"},
    )
    operation_id = created.headers["Location"].rsplit("/", 1)[-1]
    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    operation.bind_plugin(
        PluginBinding(
            plugin_id="identity-live",
            plugin_kind="buda",
            surface="identity",
            config={"narrative_id": 77},
        )
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    monkeypatch.setattr(
        buda_module,
        "drain_events",
        lambda narrative_id: [
            {"kind": "narrative_step", "detail": "Paso simulado", "narrative_id": narrative_id}
        ],
    )
    service = app.config["ACTIVITY_INGESTION_SERVICE"]
    service.enabled = True
    service.poll_once()

    payload = client.get(f"/telemetry/{operation_id}/live.json?provider=APATE").get_json()
    assert len(payload["events"]) == 1
    assert payload["events"][0]["provider"] == "APATE"
    assert payload["events"][0]["persisted"] is True
    page = client.get(f"/telemetry/{operation_id}?view=live").get_data(as_text=True)
    assert "Buffer reciente de este proceso" in page
    assert "Persistido" in page
