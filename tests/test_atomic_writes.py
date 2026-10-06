"""Ninguna escritura puede dejar el archivo a medias, y un archivo roto no tumba todo.

**Los dos modos de falla que esto cierra**, y son distintos:

1. `Path.write_text()` **trunca antes de escribir**. Un corte, un reinicio del
   servicio o un disco lleno en el medio dejan un archivo vacío o un JSON
   cortado — no el contenido viejo. En los repositorios que guardan la lista
   completa de una operación, eso no pierde un registro: pierde el historial
   entero de esa operación.

2. Y el daño no quedaba contenido. El context processor de la navegación
   consume `list()` de operaciones en **cada render de plantilla**, sin
   `try/except` por archivo: un solo JSON ilegible devolvía 500 en *todas* las
   rutas, incluida la que se usaría para arreglarlo.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from apate.atomic_write import write_json_atomically, write_text_atomically
from apate.core import (
    AdversaryProfile,
    JSONFileOperationRepository,
    Narrative,
    Operation,
    RulesOfEngagement,
)


# -- La escritura ------------------------------------------------------


def test_escribe_el_contenido(tmp_path):
    destino = tmp_path / "archivo.txt"

    write_text_atomically(destino, "hola")

    assert destino.read_text(encoding="utf-8") == "hola"


def test_crea_el_directorio_si_falta(tmp_path):
    destino = tmp_path / "sub" / "dir" / "archivo.txt"

    write_text_atomically(destino, "hola")

    assert destino.read_text(encoding="utf-8") == "hola"


def test_un_fallo_a_mitad_conserva_el_contenido_anterior(tmp_path, monkeypatch):
    """**La garantía que da nombre al módulo.**

    Con `write_text()` el archivo ya estaría truncado en este punto.
    """

    destino = tmp_path / "archivo.txt"
    write_text_atomically(destino, "contenido viejo y completo")

    def _explota(*args, **kwargs):
        raise OSError("No space left on device")

    monkeypatch.setattr("os.replace", _explota)

    with pytest.raises(OSError):
        write_text_atomically(destino, "contenido nuevo")

    assert destino.read_text(encoding="utf-8") == "contenido viejo y completo"


def test_no_deja_temporales_huerfanos(tmp_path, monkeypatch):
    """Un `.tmp` suelto en el directorio de datos confunde a cualquiera."""

    destino = tmp_path / "archivo.txt"
    monkeypatch.setattr("os.replace", lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))

    with pytest.raises(OSError):
        write_text_atomically(destino, "x")

    assert list(tmp_path.glob("*.tmp")) == []


def test_el_temporal_vive_en_el_mismo_directorio(tmp_path, monkeypatch):
    """Tiene que ser el mismo sistema de archivos, o `os.replace` no es atómico."""

    vistos = []
    original = __import__("os").replace

    def _espia(origen, destino):
        vistos.append(Path(origen).parent)
        return original(origen, destino)

    monkeypatch.setattr("os.replace", _espia)
    write_text_atomically(tmp_path / "sub" / "archivo.txt", "x")

    assert vistos == [tmp_path / "sub"]


def test_el_json_conserva_los_acentos(tmp_path):
    destino = tmp_path / "datos.json"

    write_json_atomically(destino, {"nombre": "operación señuelo"})

    assert json.loads(destino.read_text(encoding="utf-8"))["nombre"] == "operación señuelo"
    assert "\\u" not in destino.read_text(encoding="utf-8")


def test_escribe_siempre_con_saltos_de_linea_unix(tmp_path):
    """`.gitattributes` fija `eol=lf`; el guardado de reglas dependía de esto
    para no duplicar el retorno de carro en cada ciclo editar-guardar."""

    destino = tmp_path / "archivo.txt"

    write_text_atomically(destino, "una\notra\n")

    assert destino.read_bytes() == b"una\notra\n"


# -- Que ningún repositorio haya quedado afuera ------------------------


def test_ningun_repositorio_escribe_sin_atomicidad():
    """El barrido: si alguien agrega un repositorio con `write_text()`, falla acá.

    Se recorre el **AST** y no el texto: buscar la cadena marcaría también los
    comentarios y docstrings que hablan del tema, que son varios justamente
    porque la decisión está documentada donde se tomó.

    Se excluyen los sitios que no guardan estado de APATE: el señuelo que
    `honeytoken` deja en el destino, el documento de reglas vacío del primer
    arranque, la sonda del preflight, y el propio módulo atómico.
    """

    import ast

    raiz = Path(__file__).resolve().parents[1] / "src" / "apate"
    modulos_exentos = {"atomic_write.py", "honeytoken.py"}
    destinos_exentos = {"temporary", "prueba", "rules_path"}
    ofensores = []

    for ruta in sorted(raiz.rglob("*.py")):
        if ruta.name in modulos_exentos:
            continue
        arbol = ast.parse(ruta.read_text(encoding="utf-8"))
        for nodo in ast.walk(arbol):
            if not isinstance(nodo, ast.Call) or not isinstance(nodo.func, ast.Attribute):
                continue
            if nodo.func.attr != "write_text":
                continue
            objetivo = nodo.func.value
            nombre = getattr(objetivo, "id", None) or getattr(objetivo, "attr", None)
            if nombre in destinos_exentos:
                continue
            ofensores.append(f"{ruta.relative_to(raiz)}:{nodo.lineno}")

    assert not ofensores, (
        "Estas escrituras no son atómicas. Usá "
        f"apate.atomic_write.write_text_atomically(): {ofensores}"
    )


# -- El fallo aislado --------------------------------------------------


def _operacion(nombre: str) -> Operation:
    return Operation(
        name=nombre,
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


def test_una_operacion_ilegible_no_rompe_el_listado(tmp_path):
    repositorio = JSONFileOperationRepository(tmp_path)
    repositorio.save(_operacion("Buena"))
    (tmp_path / "rota.json").write_text("{ esto no es json", encoding="utf-8")

    operaciones = list(repositorio.list())

    assert [operacion.name for operacion in operaciones] == ["Buena"]


def test_la_operacion_ilegible_queda_anotada(tmp_path):
    """Saltear en silencio sería peor que fallar: el operador vería
    desaparecer una operación sin ninguna explicación."""

    repositorio = JSONFileOperationRepository(tmp_path)
    (tmp_path / "rota.json").write_text("{ esto no es json", encoding="utf-8")

    list(repositorio.list())

    assert [nombre for nombre, _motivo in repositorio.unreadable] == ["rota.json"]


def test_un_enum_desconocido_tambien_se_saltea(tmp_path):
    """El caso real de una actualización: un valor que dejó de existir."""

    repositorio = JSONFileOperationRepository(tmp_path)
    repositorio.save(_operacion("Buena"))
    datos = json.loads((tmp_path / f"{next(repositorio.list()).id}.json").read_text(encoding="utf-8"))
    datos["status"] = "un-estado-que-ya-no-existe"
    (tmp_path / "vieja.json").write_text(json.dumps(datos), encoding="utf-8")

    assert len(list(repositorio.list())) == 1


def test_la_aplicacion_sigue_respondiendo_con_una_operacion_rota(tmp_path):
    """**La regresión que importa.**

    El context processor de navegación consume `list()` en cada render, así que
    antes esto devolvía 500 en todas las rutas — incluida la que se usaría para
    arreglar el archivo.
    """

    from apate.web import create_app

    app = create_app({
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "datos",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
    })
    (Path(app.config["APATE_DATA_DIR"]) / "operations").mkdir(parents=True, exist_ok=True)
    (Path(app.config["APATE_DATA_DIR"]) / "operations" / "rota.json").write_text(
        "{ cortado a la mitad", encoding="utf-8"
    )

    cliente = app.test_client()

    for ruta in ("/", "/operations/", "/about"):
        assert cliente.get(ruta).status_code == 200, ruta
