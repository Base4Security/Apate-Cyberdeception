"""El diagnóstico local informa fallos sin filtrar datos operativos."""

import json
import sqlite3

from apate.doctor import diagnose, main
from apate.schema_version import SCHEMA_VERSION, SQLITE_SCHEMA_VERSION, write_version


def test_diagnostico_sanitizado_con_copia_y_estado(tmp_path, monkeypatch, capsys):
    data = tmp_path / "datos-sensibles"
    data.mkdir()
    write_version(data)
    (data / "secret_encryption.key").write_text("clave-super-secreta", encoding="utf-8")
    database = data / "telemetry.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE prueba (secreto TEXT)")
        connection.execute("INSERT INTO prueba VALUES ('token-super-secreto')")
        connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
    connection.close()
    from apate.backup import create_backup
    backup = tmp_path / "copia"
    create_backup(data, backup)
    status = tmp_path / "estado.json"
    status.write_text(json.dumps({"unknown_receipts": 0, "outbox": {"states": {
        "pending": 0, "sending": 0, "retry": 0, "unknown": 0,
        "awaiting_ack": 0, "delivered": 0, "dead": 0},
        "oldest_undelivered_seconds": 0}}), encoding="utf-8")

    monkeypatch.setenv("APATE_SECRET_ENCRYPTION_KEY", "otro-secreto")
    report = diagnose(data, backup=backup, status=status)
    assert report["state"] == "ok"
    assert report["checks"]["sqlite"]["count"] == 1
    assert report["checks"]["backup"]["code"] == "backup_verified"
    assert report["raw_data_included"] is False
    rendered = json.dumps(report)
    assert all(value not in rendered for value in (
        "datos-sensibles", "clave-super-secreta", "token-super-secreto", "otro-secreto"))

    output = tmp_path / "support.json"
    monkeypatch.setattr("sys.argv", ["apate.doctor", "--data-dir", str(data), "--output", str(output)])
    main()
    assert not capsys.readouterr().out
    assert json.loads(output.read_text(encoding="utf-8"))["state"] == "ok"


def test_diagnostico_falla_cerrado_en_version_futura_y_base_danada(tmp_path):
    data = tmp_path / "datos"
    data.mkdir()
    write_version(data, SCHEMA_VERSION + 1)
    (data / "telemetry.db").write_bytes(b"esto no es SQLite")
    report = diagnose(data)
    assert report["state"] == "critical"
    assert report["checks"]["schema"]["code"] == "schema_future"
    assert report["checks"]["sqlite"]["code"] == "sqlite_integrity_failed"


def test_diagnostico_no_declara_saludable_estado_invalido(tmp_path):
    data = tmp_path / "datos"
    data.mkdir()
    status = tmp_path / "estado.json"
    status.write_text("{}", encoding="utf-8")
    report = diagnose(data, status=status)
    assert report["state"] == "critical"
    assert report["checks"]["status"]["code"] == "status_invalid"


def test_diagnostico_distingue_esquema_sqlite_legacy_y_futuro(tmp_path):
    data = tmp_path / "datos"
    data.mkdir()
    write_version(data)
    database = data / "telemetry.db"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE prueba (id INTEGER)")
    connection.close()
    assert diagnose(data)["checks"]["sqlite"]["code"] == "sqlite_legacy_schema"
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION + 1}")
    connection.close()
    assert diagnose(data)["checks"]["sqlite"]["code"] == "sqlite_future_schema"
