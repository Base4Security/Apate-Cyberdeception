"""Compatibilidad sintética de datos pre-sello, actuales y futuros.

No existe una release pública anterior al esquema 1; la variante pre-sello
representa el formato histórico de idéntico contenido, no una migración nueva.
"""

import gc
import hashlib
import sqlite3

import pytest

from apate.backup import create_backup, restore_backup
from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.schema_version import ARCHIVO, SCHEMA_VERSION, SQLITE_SCHEMA_VERSION, SchemaTooNewError, read_version, write_version
from apate.web import create_app


def _app(data):
    return create_app({"TESTING": True, "APATE_DATA_DIR": data,
                       "APATE_RULES_PATH": data / "rules.yaml",
                       "APATE_MOUNT_EXTERNAL_TOOLS": False,
                       "APATE_HONEYUSER_MONITORING_ENABLED": False})


def _fixture(data):
    app = _app(data)
    operation = Operation(name="Compatibilidad sintética", adversary_profile=AdversaryProfile("Hipótesis"),
                          roe=RulesOfEngagement(), narrative=Narrative("Sin efectos externos"))
    app.config["OPERATION_REPOSITORY"].save(operation)
    identifier = operation.id
    del app
    gc.collect()
    return identifier


@pytest.mark.parametrize("format_version", ["pre_sello", "actual"])
def test_restauracion_de_formato_compatible_conserva_operacion(tmp_path, format_version):
    source = tmp_path / "origen"
    identifier = _fixture(source)
    if format_version == "pre_sello":
        (source / ARCHIVO).unlink()
        # Solo estas bases usan el sello aditivo de apate.schema_version.
        # El ledger tiene contrato propio y nunca tuvo un esquema 0 con tablas.
        for name in ("telemetry.db", "rule_decisions.db"):
            with sqlite3.connect(source / name) as connection:
                connection.execute("PRAGMA user_version = 0")
            connection.close()
    backup = tmp_path / "copia"
    create_backup(source, backup)
    destination = tmp_path / "restaurado"
    restore_backup(backup, destination)
    app = _app(destination)
    assert app.config["OPERATION_REPOSITORY"].get(identifier).name == "Compatibilidad sintética"
    assert read_version(destination) == SCHEMA_VERSION
    with sqlite3.connect(destination / "telemetry.db") as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SQLITE_SCHEMA_VERSION
    connection.close()
    del app
    gc.collect()


def test_restauracion_rechaza_directorio_de_version_futura_sin_reescribirlo(tmp_path):
    source = tmp_path / "origen"
    _fixture(source)
    write_version(source, SCHEMA_VERSION + 1)
    backup = tmp_path / "copia"
    create_backup(source, backup)
    destination = tmp_path / "restaurado"
    restore_backup(backup, destination)
    before = hashlib.sha256((destination / ARCHIVO).read_bytes()).hexdigest()
    with pytest.raises(SchemaTooNewError):
        _app(destination)
    assert hashlib.sha256((destination / ARCHIVO).read_bytes()).hexdigest() == before


def test_restauracion_rechaza_sqlite_futuro_sin_reescribirlo(tmp_path):
    source = tmp_path / "origen"
    _fixture(source)
    database = source / "telemetry.db"
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION + 1}")
    connection.close()
    backup = tmp_path / "copia"
    create_backup(source, backup)
    destination = tmp_path / "restaurado"
    restore_backup(backup, destination)
    before = hashlib.sha256((destination / "telemetry.db").read_bytes()).hexdigest()
    with pytest.raises(SchemaTooNewError):
        _app(destination)
    assert hashlib.sha256((destination / "telemetry.db").read_bytes()).hexdigest() == before
