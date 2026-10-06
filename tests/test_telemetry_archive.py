"""El archivo conserva evidencia y detecta alteraciones."""

from datetime import datetime, timezone
import io
import zipfile

import pytest

from apate.plugins.base import EventType
from apate.telemetry.archive import export_operation_evidence, verify_operation_evidence
from apate.telemetry.models import TelemetryRecord
from apate.telemetry.sqlite_repository import SQLiteTelemetryRepository


def test_evidence_round_trip_and_tamper(tmp_path):
    repo = SQLiteTelemetryRepository(tmp_path / "events.db")
    event = TelemetryRecord(
        event_type=EventType.INTERACTION, operation_id="op-1", plugin_id="p-1",
        surface="network", timestamp=datetime.now(timezone.utc), source_event_id="source-1",
        payload={"kind": "test"},
    )
    repo.append(event)
    manifest = export_operation_evidence(repo, "op-1", tmp_path / "archive")
    name = manifest["file"] + ".manifest.json"
    assert verify_operation_evidence(tmp_path / "archive", name)[0].id == event.id
    assert repo.list_for_operation("op-1")[0].id == event.id
    path = tmp_path / "archive" / manifest["file"]
    path.write_text(path.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash"):
        verify_operation_evidence(tmp_path / "archive", name)


def test_evidence_refuses_path_traversal(tmp_path):
    repo = SQLiteTelemetryRepository(tmp_path / "events.db")
    with pytest.raises(ValueError):
        export_operation_evidence(repo, "../other", tmp_path)
    with pytest.raises(ValueError):
        verify_operation_evidence(tmp_path, "../manifest.json")


def test_web_download_contains_verifiable_manifest(app, client):
    response = client.post("/operations/new", data={"name": "Archivo", "adversary_name": "APT", "narrative_name": "Historia"})
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]
    repository = app.config["TELEMETRY_COLLECTOR"].repository
    repository.append(TelemetryRecord(
        event_type=EventType.INTERACTION, operation_id=operation_id, plugin_id="p",
        surface="network", timestamp=datetime.now(timezone.utc), source_event_id="source-1",
    ))
    downloaded = client.get(f"/telemetry/{operation_id}/evidence.zip")
    assert downloaded.status_code == 200
    with zipfile.ZipFile(io.BytesIO(downloaded.data)) as package:
        package.extractall(app.config["APATE_DATA_DIR"] / "test-extract")
        manifest_name = next(name for name in package.namelist() if name.endswith(".manifest.json"))
    records = verify_operation_evidence(app.config["APATE_DATA_DIR"] / "test-extract", manifest_name)
    assert len(records) == 1
