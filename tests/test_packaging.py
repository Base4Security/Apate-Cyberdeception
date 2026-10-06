"""Todo archivo que no sea codigo tiene que viajar en el paquete instalado.

Motivo real, no hipotetico: `apate/web/static/` (la hoja de estilos y los dos
scripts) quedo fuera de `[tool.setuptools.package-data]`, y el fallo no aparece
en desarrollo. `pip install -e .` deja los modulos apuntando al arbol de
fuentes, donde los archivos estan siempre; recien en una instalacion real
--como la de la imagen de la demo, que usa `pip install .` para publicar los
entry points-- el paquete llega sin ellos. La aplicacion instala, arranca y
sirve todas sus rutas: solo que sin estilos.

Este test compara lo declarado contra lo que existe de verdad bajo `src/apate/`,
asi que falla al agregar un tipo de archivo nuevo sin declararlo.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - solo en 3.10
    tomllib = pytest.importorskip("tomli", reason="hace falta tomllib (3.11+) o tomli")

RAIZ = Path(__file__).resolve().parent.parent
SRC = RAIZ / "src"

# Lo que no es contenido a distribuir: fuentes, compilados, y los `.pot`, que
# son la plantilla para traducir y no los lee nadie en tiempo de ejecucion.
IGNORADOS = {".py", ".pyc", ".pyo", ".pot"}
DIRECTORIOS_IGNORADOS = {"__pycache__", ".pytest_cache"}


def _package_data() -> dict[str, list[str]]:
    with (RAIZ / "pyproject.toml").open("rb") as fh:
        config = tomllib.load(fh)
    return config["tool"]["setuptools"]["package-data"]


def _archivos_de_datos() -> list[Path]:
    archivos = []
    for ruta in (SRC / "apate").rglob("*"):
        if not ruta.is_file() or ruta.suffix in IGNORADOS:
            continue
        if DIRECTORIOS_IGNORADOS & set(ruta.parts):
            continue
        archivos.append(ruta)
    return archivos


def _archivos_declarados(package_data: dict[str, list[str]]) -> set[Path]:
    """Los que el patron alcanza de verdad.

    Se resuelven con `Path.glob`, el mismo mecanismo recursivo que aplica
    setuptools, en vez de con `fnmatch`: ahi `**` no significa "cero o mas
    directorios" y `templates/**/*.html` dejaria afuera `templates/base.html`,
    que si se instala. Reimplementar la semantica del patron es justamente
    como este test daria un resultado que no se parece al paquete real.
    """
    declarados: set[Path] = set()
    for paquete, patrones in package_data.items():
        base = SRC / Path(paquete.replace(".", "/"))
        for patron in patrones:
            declarados.update(ruta for ruta in base.glob(patron) if ruta.is_file())
    return declarados


def test_hay_archivos_de_datos_que_comprobar():
    """Red de seguridad: si el descubrimiento se rompe, el test de abajo pasaria vacio."""
    assert len(_archivos_de_datos()) > 5


def test_todo_archivo_de_datos_esta_declarado_en_package_data():
    declarados = _archivos_declarados(_package_data())
    sin_declarar = sorted(
        archivo.relative_to(SRC).as_posix()
        for archivo in _archivos_de_datos()
        if archivo not in declarados
    )
    assert not sin_declarar, (
        "Estos archivos no viajan en el paquete instalado; declaralos en "
        "[tool.setuptools.package-data] de pyproject.toml: " + ", ".join(sin_declarar)
    )


def test_la_hoja_de_estilos_y_los_scripts_estan_cubiertos():
    """El caso concreto que motivo el test, fijado aparte para que no se pierda."""
    declarados = _archivos_declarados(_package_data())
    for nombre in ("theme.css", "loading.js", "ui.js"):
        archivo = SRC / "apate" / "web" / "static" / nombre
        assert archivo.is_file(), f"falta {nombre} en el arbol de fuentes"
        assert archivo in declarados, f"{nombre} no viajaria en el paquete"
