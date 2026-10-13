"""Contrato neutro de extensión y proyecciones recuperables de community."""
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime, timezone

import pytest
from flask import Flask
from apate.extensions import configure_extensions, initialize_extensions
from apate.plugins import PluginEvent, EventType
from apate.telemetry.models import TelemetryRecord
from apate.telemetry.sqlite_repository import SQLiteTelemetryRepository


def test_extension_is_explicit_and_initialized_in_order(monkeypatch):
    calls = []
    class Extension:
        contract_version = 1
        def configure_app(self, app):
            calls.append("configure")
            app.config["CUSTOM_READY"] = True
        def init_app(self, app):
            assert app.config["CUSTOM_READY"]
            calls.append("initialize")
    monkeypatch.setattr("apate.extensions.entry_points", lambda **_: [SimpleNamespace(name="test", load=lambda: Extension)])
    app = Flask(__name__)
    configure_extensions(app)
    assert calls == []
    app.config["APATE_EXTENSIONS"] = "test"
    configure_extensions(app)
    initialize_extensions(app)
    assert calls == ["configure", "initialize"]


@pytest.mark.parametrize("points,selected,error", [([], "missing", "missing_or_ambiguous"),
    (["test", "test"], "test", "missing_or_ambiguous"), (["test"], ["test", "test"], "duplicate_extension")])
def test_extension_missing_or_ambiguous_fails_closed(monkeypatch, points, selected, error):
    monkeypatch.setattr("apate.extensions.entry_points", lambda **_: [SimpleNamespace(name=name) for name in points])
    app = Flask(__name__)
    app.config["APATE_EXTENSIONS"] = selected
    with pytest.raises(ValueError, match=error):
        configure_extensions(app)


def test_recovery_and_pagination_preserve_insertion_cursor(tmp_path):
    repository = SQLiteTelemetryRepository(tmp_path / "telemetry.db")
    first = TelemetryRecord.from_event(PluginEvent(EventType.INTERACTION, "p1", "network", "op-1", payload={"src_ip": "192.0.2.1"}))
    other = TelemetryRecord.from_event(PluginEvent(EventType.INTERACTION, "p1", "network", "op-2"))
    second = TelemetryRecord.from_event(PluginEvent(EventType.INTERACTION, "p1", "network", "op-1"))
    assert repository.append_recovered(first)
    assert not repository.append_recovered(first)
    repository.append_many([other, second])
    page = repository.page("op-1", limit=1)
    assert page["items"][0].id == first.id and page["next_cursor"] is not None
    next_page = repository.page("op-1", limit=1, after=page["next_cursor"])
    assert next_page["items"][0].id == second.id and next_page["next_cursor"] is None


@pytest.mark.parametrize("arguments", [{"after": True}, {"after": -1}, {"limit": 0}, {"limit": 501}, {"limit": True}])
def test_pagination_rejects_invalid_cursor_or_limit(tmp_path, arguments):
    with pytest.raises(ValueError):
        SQLiteTelemetryRepository(tmp_path / "telemetry.db").page("op", **arguments)
