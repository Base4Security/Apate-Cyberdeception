from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from apate.plugins import EventType, PluginEvent


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._current = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._current = {**dict(attrs), "text": ""}

    def handle_data(self, data):
        if self._current is not None:
            self._current["text"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self._current is not None:
            self._current["text"] = self._current["text"].strip()
            self.links.append(self._current)
            self._current = None


def _seed_event(app, *, plugin_id, surface, kind, detail, ttp_id=None):
    payload = {"kind": kind, "detail": detail}
    if ttp_id:
        payload["ttp_id"] = ttp_id
    app.config["TELEMETRY_COLLECTOR"].handle_event(
        PluginEvent(
            event_type=EventType.INTERACTION,
            plugin_id=plugin_id,
            surface=surface,
            operation_id="op-1",
            payload=payload,
        )
    )


def _links(text):
    parser = _LinkParser()
    parser.feed(text)
    return parser.links


def _link(text, *, label=None, aria_label=None):
    return next(
        link
        for link in _links(text)
        if (label is None or link["text"] == label)
        and (aria_label is None or link.get("aria-label") == aria_label)
    )


def _query(link):
    return parse_qs(urlsplit(link["href"]).query)


def test_table_value_adds_drilldown_filter_without_losing_active_filters(client, app):
    _seed_event(
        app,
        plugin_id="honeypot-mock-1",
        surface="network",
        kind="scan",
        detail="coincide",
        ttp_id="T1078",
    )

    text = client.get("/telemetry/op-1?view=events&surface=network&q=coincide").get_data(as_text=True)
    query = _query(_link(text, label="honeypot-mock-1"))

    assert query == {
        "view": ["events"],
        "surface": ["network"],
        "q": ["coincide"],
        "plugin_id": ["honeypot-mock-1"],
    }


def test_removable_filter_tag_drops_only_itself(client, app):
    _seed_event(app, plugin_id="honeypot-mock-1", surface="network", kind="scan", detail="coincide")

    text = client.get(
        "/telemetry/op-1?view=events&provider=APATE&surface=network&q=coincide"
    ).get_data(as_text=True)
    query = _query(_link(text, aria_label="Quitar filtro Superficie: network"))

    assert "surface" not in query
    assert query == {"view": ["events"], "provider": ["APATE"], "q": ["coincide"]}


def test_two_filter_drilldown_matches_manual_filter_combination(client, app):
    _seed_event(app, plugin_id="alpha", surface="network", kind="scan", detail="objetivo")
    _seed_event(app, plugin_id="alpha", surface="identity", kind="scan", detail="otra superficie")
    _seed_event(app, plugin_id="beta", surface="network", kind="scan", detail="otra capacidad")

    first_page = client.get("/telemetry/op-1?view=events&surface=network").get_data(as_text=True)
    drilldown_href = _link(first_page, label="alpha")["href"]
    drilldown_page = client.get(drilldown_href).get_data(as_text=True)
    manual_page = client.get(
        "/telemetry/op-1?view=events&surface=network&plugin_id=alpha"
    ).get_data(as_text=True)

    assert "1 evento(s) coinciden" in drilldown_page
    assert "objetivo" in drilldown_page
    assert "otra superficie" not in drilldown_page and "otra capacidad" not in drilldown_page
    assert 'id="telemetry-events-title">Eventos <span class="summary-count-badge">1</span>' in manual_page


def test_event_kind_and_ttp_are_available_as_drilldown_links(client, app):
    _seed_event(
        app,
        plugin_id="alpha",
        surface="network",
        kind="credential_use",
        detail="objetivo",
        ttp_id="T1078",
    )

    text = client.get("/telemetry/op-1?view=events&provider=APATE").get_data(as_text=True)

    assert _query(_link(text, label="credential_use"))["event_kind"] == ["credential_use"]
    assert _query(_link(text, label="T1078"))["ttp_id"] == ["T1078"]
