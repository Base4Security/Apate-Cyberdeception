"""El sello de versión del formato, y qué hace APATE cuando no coincide.

**Por qué existe un número.** Agregar un campo es seguro —los deserializadores
usan `.get()` con defaults— pero renombrar uno pierde el dato en silencio,
cambiar el valor de un enum rompe la lectura de golpe, y cambiar un tipo es
peor que silencioso. En los tres casos el código no puede saber con qué versión
se escribió lo que está leyendo. Con un sello, una migración futura sabe de
dónde parte; sin él, esa primera migración es la que no se puede escribir.

**Y por qué el sello es del directorio y no de cada documento.** Varios
documentos de APATE son listas en la raíz, y una lista no tiene dónde llevar
una clave. El directorio de datos es lo que se copia, se restaura y se
actualiza como una unidad: la pregunta real nunca es de qué versión es un
archivo, sino de qué versión es la instalación.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import apate.schema_version as schema_version

from apate.schema_version import (
    ARCHIVO,
    SCHEMA_VERSION,
    SQLITE_SCHEMA_VERSION,
    SchemaTooNewError,
    SchemaInvalidError,
    SchemaMigrationRequiredError,
    apply_sqlite_version,
    ensure_compatible,
    read_version,
    write_version,
)
from apate.web import create_app


def _app(tmp_path):
    return create_app({
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "datos",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
    })


# -- El sello ----------------------------------------------------------


def test_un_directorio_nuevo_queda_sellado(tmp_path):
    _app(tmp_path)

    assert read_version(tmp_path / "datos") == SCHEMA_VERSION


def test_un_directorio_sin_sello_se_adopta(tmp_path):
    """Un directorio escrito antes de que el sello existiera tiene exactamente
    el formato de la versión 1: adoptarlo es correcto, no una suposición."""

    datos = tmp_path / "datos"
    datos.mkdir()
    (datos / "algo.json").write_text("{}", encoding="utf-8")

    assert ensure_compatible(datos) == 0
    assert read_version(datos) == SCHEMA_VERSION


def test_un_sello_ilegible_se_rechaza_sin_reescribirlo(tmp_path):
    datos = tmp_path / "datos"
    datos.mkdir()
    (datos / ARCHIVO).write_text("no es json", encoding="utf-8")

    before = (datos / ARCHIVO).read_bytes()
    with pytest.raises(SchemaInvalidError):
        ensure_compatible(datos)
    assert (datos / ARCHIVO).read_bytes() == before


def test_una_version_json_anterior_exige_migracion_explicita(tmp_path, monkeypatch):
    datos = tmp_path / "datos"
    datos.mkdir()
    write_version(datos, 1)
    before = (datos / ARCHIVO).read_bytes()
    monkeypatch.setattr(schema_version, "SCHEMA_VERSION", 2)

    with pytest.raises(SchemaMigrationRequiredError):
        ensure_compatible(datos)
    assert (datos / ARCHIVO).read_bytes() == before


def test_directorio_sin_sello_no_se_asume_version_dos(tmp_path, monkeypatch):
    datos = tmp_path / "datos"
    datos.mkdir()
    monkeypatch.setattr(schema_version, "SCHEMA_VERSION", 2)

    with pytest.raises(SchemaMigrationRequiredError):
        ensure_compatible(datos)
    assert not (datos / ARCHIVO).exists()


def test_un_directorio_ya_sellado_no_se_reescribe(tmp_path):
    datos = tmp_path / "datos"
    datos.mkdir()
    write_version(datos)
    antes = (datos / ARCHIVO).stat().st_mtime_ns

    ensure_compatible(datos)

    assert (datos / ARCHIVO).stat().st_mtime_ns == antes


# -- Datos de una versión más nueva ------------------------------------


def test_datos_mas_nuevos_impiden_arrancar(tmp_path):
    """**La garantía que importa.**

    Leer datos de una versión más nueva no es un error de lectura: lo que
    sigue a leerlos es un `save()` que los reescribe en el formato viejo. O
    sea que continuar sería destruir datos, no sólo malinterpretarlos.
    """

    datos = tmp_path / "datos"
    datos.mkdir()
    write_version(datos, SCHEMA_VERSION + 1)

    with pytest.raises(SchemaTooNewError):
        _app(tmp_path)


def test_el_mensaje_dice_que_hacer(tmp_path):
    datos = tmp_path / "datos"
    datos.mkdir()
    write_version(datos, SCHEMA_VERSION + 5)

    with pytest.raises(SchemaTooNewError) as fallo:
        ensure_compatible(datos)

    mensaje = str(fallo.value)
    assert str(SCHEMA_VERSION + 5) in mensaje
    assert "APATE_DATA_DIR" in mensaje


# -- SQLite ------------------------------------------------------------


def test_una_base_nueva_queda_sellada(tmp_path):
    conexion = sqlite3.connect(tmp_path / "b.db")

    anterior = apply_sqlite_version(conexion)

    assert anterior == 0
    assert conexion.execute("PRAGMA user_version").fetchone()[0] == SQLITE_SCHEMA_VERSION


def test_una_base_mas_nueva_se_rechaza(tmp_path):
    conexion = sqlite3.connect(tmp_path / "b.db")
    conexion.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION + 1}")

    with pytest.raises(SchemaTooNewError):
        apply_sqlite_version(conexion)


def test_una_base_anterior_no_se_resella_como_version_dos(tmp_path, monkeypatch):
    conexion = sqlite3.connect(tmp_path / "b.db")
    conexion.execute("PRAGMA user_version = 1")
    monkeypatch.setattr(schema_version, "SQLITE_SCHEMA_VERSION", 2)

    with pytest.raises(SchemaMigrationRequiredError):
        apply_sqlite_version(conexion)
    assert conexion.execute("PRAGMA user_version").fetchone()[0] == 1


def test_las_dos_bases_reales_quedan_selladas(tmp_path):
    """`telemetry.db` y `rule_decisions.db`, por las rutas que las crean."""

    app = _app(tmp_path)
    datos = Path(app.config["APATE_DATA_DIR"])

    for nombre in ("telemetry.db", "rule_decisions.db"):
        archivo = next(datos.rglob(nombre), None)
        assert archivo is not None, f"no se creó {nombre}"
        conexion = sqlite3.connect(archivo)
        assert conexion.execute("PRAGMA user_version").fetchone()[0] == SQLITE_SCHEMA_VERSION
        conexion.close()


# -- Que el número no se quede atrás -----------------------------------


def test_el_sello_del_directorio_y_el_de_sqlite_son_independientes():
    """Van por separado a propósito: son formatos distintos. Este test existe
    para que nadie los unifique sin pensarlo."""

    assert isinstance(SCHEMA_VERSION, int) and SCHEMA_VERSION >= 1
    assert isinstance(SQLITE_SCHEMA_VERSION, int) and SQLITE_SCHEMA_VERSION >= 1
