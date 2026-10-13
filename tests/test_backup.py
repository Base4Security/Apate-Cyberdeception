"""La restauración conserva datos mixtos y rechaza copias alteradas."""

import sqlite3

import pytest

from apate.backup import create_backup, restore_backup, verify_backup


def test_backup_roundtrip_json_sqlite_and_secret_key(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / ".apate-secret-key").write_bytes(b"clave-cifrada-de-prueba")
    (data / "operations").mkdir()
    (data / "operations" / "op.json").write_text('{"name":"Operación"}', encoding="utf-8")
    with sqlite3.connect(data / "telemetry.db") as connection:
        connection.execute("CREATE TABLE events (detail TEXT)")
        connection.execute("INSERT INTO events VALUES ('observado')")

    copy = tmp_path / "copy"
    manifest = create_backup(data, copy)
    assert len(manifest["files"]) == 3
    assert verify_backup(copy) == manifest

    restored = tmp_path / "restored"
    restore_backup(copy, restored)
    assert (restored / ".apate-secret-key").read_bytes() == b"clave-cifrada-de-prueba"
    assert (restored / "operations" / "op.json").read_text(encoding="utf-8") == '{"name":"Operación"}'
    with sqlite3.connect(restored / "telemetry.db") as connection:
        assert connection.execute("SELECT detail FROM events").fetchone()[0] == "observado"


def test_backup_detects_tampering_and_never_overwrites_live_data(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "item.json").write_text("original", encoding="utf-8")
    copy = tmp_path / "copy"
    create_backup(data, copy)
    destination = tmp_path / "live"
    destination.mkdir()
    (destination / "item.json").write_text("vigente", encoding="utf-8")

    with pytest.raises(ValueError, match="vacío"):
        restore_backup(copy, destination)
    assert (destination / "item.json").read_text(encoding="utf-8") == "vigente"
    (copy / "item.json").write_text("alterado", encoding="utf-8")
    with pytest.raises(ValueError, match="manifiesto"):
        verify_backup(copy)
