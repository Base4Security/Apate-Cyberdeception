"""Inventario de capacidad local sin cargas ni escrituras."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from apate.ops import inspect_storage
from apate.plugins.base import EventType
from apate.telemetry.models import TelemetryRecord


def test_inventario_cuenta_proyecciones_sin_filtrar_identificadores(app):
    data_dir = app.config["APATE_DATA_DIR"]
    repository = app.config["TELEMETRY_COLLECTOR"].repository
    repository.append(TelemetryRecord(event_type=EventType.INTERACTION,
        operation_id="secreto-operacion", plugin_id="secreto-capacidad", surface="test",
        timestamp=datetime.now(timezone.utc), source_event_id="secreto-evento"))
    telemetry_file = next(data_dir.rglob("telemetry.db"))
    before = hashlib.sha256(telemetry_file.read_bytes()).hexdigest()

    result = inspect_storage(data_dir)

    assert result["telemetry_records"] == 1
    assert result["database_count"] >= 1
    assert result["network_used"] is False
    assert result["snapshot_consistency"] == "per_database_read_transaction"
    assert result["cross_database_consistency"] == "not_atomic"
    assert "secreto" not in json.dumps(result)
    assert hashlib.sha256(telemetry_file.read_bytes()).hexdigest() == before


def test_inventario_lee_filas_confirmadas_en_wal_con_un_escritor_activo(app):
    """La lectura no omite eventos pendientes de checkpoint en SQLite."""

    data_dir = app.config["APATE_DATA_DIR"]
    database = next(data_dir.rglob("telemetry.db"))
    with sqlite3.connect(database) as writer:
        assert writer.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        writer.execute("""INSERT INTO telemetry_records
            (id, operation_id, event_type, plugin_id, surface, timestamp,
             source_event_id, resource_id, ttp_id, iocs_json, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("wal-event", "op-wal", "interaction", "decoy", "synthetic",
             datetime.now(timezone.utc).isoformat(), "wal-1", None, None, "[]", "{}"))
        writer.commit()
        assert (data_dir / "telemetry.db-wal").stat().st_size > 0

        inventory = inspect_storage(data_dir)

        assert inventory["telemetry_records"] == 1
        assert inventory["wal_file_bytes"] > 0
        assert inventory["snapshot_consistency"] == "per_database_read_transaction"
