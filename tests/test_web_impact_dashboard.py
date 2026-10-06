"""Contrato del centro de impacto real y su vista previa de respaldo."""

from __future__ import annotations

from html import unescape
from pathlib import Path
from datetime import datetime, timezone

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.identity import IdentityRole
from apate.plugins import EventType, PluginEvent
from apate.web.access import required_role


_THEME_CSS_PATH = Path(__file__).resolve().parent.parent / "src" / "apate" / "web" / "static" / "theme.css"


def test_impact_dashboard_renders_real_empty_state_without_sidebar(client):
    response = client.get("/impact/")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    visible = unescape(text)
    assert '<body class="impact-dashboard">' in text
    assert '<aside class="sidebar">' not in text
    assert "Impacto de ciberengaño" in visible
    assert "Vista previa" not in visible
    assert "Datos de ejemplo" not in visible
    assert "No hay eventos registrados todavía." in visible
    assert text.count('class="impact-tactic"') == 13
    assert "window.setInterval" not in text


def test_impact_preview_keeps_the_mock_notice_without_querying_repositories(client, app, monkeypatch):
    def unexpected_repository_access():
        raise AssertionError("El dashboard mock no debe consultar operaciones reales.")

    monkeypatch.setattr(app.config["OPERATION_REPOSITORY"], "list", unexpected_repository_access)

    response = client.get("/impact/?preview=1")

    assert response.status_code == 200
    assert b"Datos de ejemplo" in response.data
    assert b"window.setInterval" in response.data


def test_impact_preview_localizes_generated_mock_content(client, app):
    app.config["APATE_LOCALE"] = "en"

    body = unescape(client.get("/impact/?preview=1").get_data(as_text=True))

    assert "Outbound transfer to unauthorized infrastructure" in body
    assert "Updated 12 s ago" in body
    assert "Transferencia saliente hacia infraestructura no autorizada" not in body


def test_impact_dashboard_reads_real_telemetry_once_and_removes_the_mock_notice(client, app, monkeypatch):
    operation = Operation(
        name="Operación con telemetría",
        adversary_profile=AdversaryProfile(name="APT", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        plugins=[PluginBinding(plugin_id="dolost-impact", surface="red", plugin_kind="dolost")],
    )
    app.config["OPERATION_REPOSITORY"].save(operation)
    app.config["TELEMETRY_COLLECTOR"].handle_event(
        PluginEvent(
            event_type=EventType.TTP_OBSERVED,
            plugin_id="dolost-impact",
            surface="red",
            operation_id=operation.id,
            payload={"ttp_id": "T1046", "source_ip": "198.51.100.9", "detail": "Escaneo real"},
            timestamp=datetime.now(timezone.utc),
        )
    )
    collector = app.config["TELEMETRY_COLLECTOR"]
    original = collector.list_events_by_operation
    calls = []

    def tracked(operation_ids):
        calls.append(operation_ids)
        return original(operation_ids)

    monkeypatch.setattr(collector, "list_events_by_operation", tracked)
    response = client.get("/impact/")

    body = unescape(response.get_data(as_text=True))
    assert response.status_code == 200
    assert calls == [[operation.id]]
    assert "Datos de ejemplo" not in body
    assert "REGISTRADO" in body
    assert "Escaneo real" in body
    assert ">1<" in body


def test_landing_links_to_impact_without_claiming_real_data_is_a_preview(client):
    text = client.get("/").get_data(as_text=True)

    assert 'href="/impact/"' in text
    # El dashboard usa datos registrados; solo ?preview=1 muestra el fixture.
    plano = unescape(text)
    assert "Vista de impacto" in plano and "datos de ejemplo" not in plano


def test_impact_dashboard_is_read_only_for_the_existing_access_policy():
    assert required_role("impact.dashboard", "GET") is IdentityRole.READ


def test_impact_dashboard_css_keeps_the_projector_layout_and_mock_notice_visible():
    css = _THEME_CSS_PATH.read_text(encoding="utf-8")

    # Se assertan las propiedades, no la línea literal: al corregir el
    # scroll de proyector hubo que sumarle `padding: 0` a esa misma regla,
    # y un assert por string exacto rompe ante cualquier ajuste de estilo.
    import re

    regla = re.search(r"body\.impact-dashboard main \{([^}]*)\}", css)
    assert regla and "max-width: none" in regla.group(1)
    assert ".impact-screen { min-height: 100vh;" in css
    assert ".impact-heatmap-grid { display: grid; grid-template-columns: repeat(13, minmax(0, 1fr));" in css
    assert ".impact-preview-notice" in css


def test_the_impact_screen_does_not_inherit_the_main_padding():
    """`.impact-screen` ocupa `100vh`. Si `main` conserva su padding
    (28px arriba, 64px abajo) el documento mide 100vh+92px y la pantalla
    scrollea — medido a 1920x1080: documento 1172px contra viewport 1080px.
    Para una vista pensada para proyector, ese scroll es el criterio de
    aceptación fallado, así que la regla que lo anula se fija acá.
    """

    import pathlib
    import re

    css = (
        pathlib.Path(__file__).resolve().parent.parent
        / "src" / "apate" / "web" / "static" / "theme.css"
    ).read_text(encoding="utf-8")

    regla = re.search(r"body\.impact-dashboard main \{([^}]*)\}", css)

    assert regla, "falta la regla body.impact-dashboard main"
    assert "padding: 0" in regla.group(1)


def test_the_impact_view_offers_a_way_back(client):
    """La vista vacía la barra lateral: sin un enlace propio, la única salida
    es el botón atrás del navegador. Encontrado usándola."""

    body = client.get("/impact/").get_data(as_text=True)
    cabecera = body[body.index("impact-header") : body.index("impact-heatmap")]

    assert 'href="/"' in cabecera
