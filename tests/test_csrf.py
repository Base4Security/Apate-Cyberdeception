"""Verificación CSRF: toda mutación exige un testigo de sesión.

**Qué protege.** Cada cambio en APATE es un POST de formulario —desplegar y
retirar decoys, guardar el YAML de reglas, crear usuarios, cerrar operaciones—
y sin testigo cualquier página que el operador visite con la sesión abierta
puede dispararlos desde su navegador. En una herramienta que corre dentro de la
red de un cliente, eso es engaño desplegado o retirado por alguien de afuera.

**Estos tests corren con la protección real.** El resto de la suite la
neutraliza (fixture `csrf_neutralizado` en `conftest.py`), así que el marcador
`csrf` es lo que distingue este archivo: sin él, todo esto pasaría sin probar
nada.

Dos frentes que tienen que valer juntos: que el servidor rechace, y que **cada
formulario de cada plantilla** lleve su campo — un formulario sin campo no
falla en los tests, falla en la cara del operador.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from apate.web import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]
PLANTILLAS = REPO_ROOT / "src" / "apate" / "web" / "templates"

FORM_POST = re.compile(r'<form\b[^>]*\bmethod\s*=\s*"post"[^>]*>', re.IGNORECASE | re.DOTALL)


@pytest.fixture
def app_csrf(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
            "SECRET_KEY": "clave-fija-para-el-test",
        }
    )


@pytest.fixture
def cliente(app_csrf):
    return app_csrf.test_client()


def _testigo(cliente) -> str:
    """El testigo que la aplicación le dio a esta sesión."""

    cuerpo = cliente.get("/").get_data(as_text=True)
    encontrado = re.search(r'name="csrf-token" content="([^"]+)"', cuerpo)
    assert encontrado, "La página no publicó el testigo en su <meta>"
    return encontrado.group(1)


# -- Las plantillas ----------------------------------------------------


def test_cada_formulario_post_lleva_su_campo_oculto():
    """**El test que importa para no romper la interfaz.**

    Un formulario sin campo no falla en ningún test de comportamiento: falla
    cuando el operador aprieta el botón. Esto recorre las plantillas reales,
    así que un formulario nuevo sin testigo se detecta al escribirlo.
    """

    sin_testigo = []
    for ruta in sorted(PLANTILLAS.rglob("*.html")):
        texto = ruta.read_text(encoding="utf-8")
        for encontrado in FORM_POST.finditer(texto):
            siguiente = texto[encontrado.end() : encontrado.end() + 120]
            if "_csrf_token" not in siguiente:
                sin_testigo.append(f"{ruta.relative_to(PLANTILLAS)}: {encontrado.group(0)[:80]}")

    assert not sin_testigo, (
        "Estos formularios POST no llevan el campo del testigo CSRF. Agregá "
        '<input type="hidden" name="_csrf_token" value="{{ csrf_token() }}"> '
        f"justo después de la etiqueta <form>:\n" + "\n".join(sin_testigo)
    )


def test_hay_formularios_para_revisar():
    """Si el barrido deja de encontrar formularios, el test de arriba se
    vuelve una tautología verde. Esto lo impide."""

    total = sum(
        len(FORM_POST.findall(ruta.read_text(encoding="utf-8")))
        for ruta in PLANTILLAS.rglob("*.html")
    )

    assert total > 50, total


def test_cada_fetch_post_lleva_el_testigo():
    """Un `fetch` que arma su propio cuerpo no arrastra el campo oculto.

    Los que mandan `new FormData(form)` sí lo arrastran, porque el campo está
    dentro del formulario; el resto tiene que poner la cabecera a mano.
    """

    sin_testigo = []
    for ruta in sorted(PLANTILLAS.rglob("*.html")):
        texto = ruta.read_text(encoding="utf-8")
        for encontrado in re.finditer(r"method:\s*['\"]POST['\"]", texto):
            llamada = texto[max(0, encontrado.start() - 200) : encontrado.end() + 300]
            if "new FormData(" in llamada or "apateCsrfHeaders" in llamada:
                continue
            sin_testigo.append(f"{ruta.relative_to(PLANTILLAS)}")

    assert not sin_testigo, (
        "Estos fetch POST no mandan el testigo. Agregá window.apateCsrfHeaders() "
        f"a sus cabeceras: {sin_testigo}"
    )


# -- El servidor -------------------------------------------------------


@pytest.mark.csrf
def test_una_mutacion_sin_testigo_se_rechaza(cliente):
    respuesta = cliente.post("/operator", data={"operator": "Ana"})

    assert respuesta.status_code == 400


@pytest.mark.csrf
def test_una_mutacion_con_testigo_ajeno_se_rechaza(cliente):
    _testigo(cliente)

    respuesta = cliente.post(
        "/operator", data={"operator": "Ana", "_csrf_token": "el-de-otra-sesion"}
    )

    assert respuesta.status_code == 400


@pytest.mark.csrf
def test_una_mutacion_con_su_testigo_pasa(cliente):
    testigo = _testigo(cliente)

    respuesta = cliente.post(
        "/operator", data={"operator": "Ana", "_csrf_token": testigo}, follow_redirects=False
    )

    assert respuesta.status_code in (302, 303)


@pytest.mark.csrf
def test_el_testigo_tambien_vale_por_cabecera(cliente):
    """Para el JavaScript de la interfaz, que llama por `fetch()`."""

    testigo = _testigo(cliente)

    respuesta = cliente.post(
        "/operator", data={"operator": "Ana"}, headers={"X-CSRF-Token": testigo}
    )

    assert respuesta.status_code in (302, 303)


@pytest.mark.csrf
def test_las_lecturas_no_se_ven_afectadas(cliente):
    for ruta in ("/", "/about", "/operations/"):
        assert cliente.get(ruta).status_code == 200


@pytest.mark.csrf
def test_dos_sesiones_reciben_testigos_distintos(app_csrf):
    uno = _testigo(app_csrf.test_client())
    otro = _testigo(app_csrf.test_client())

    assert uno != otro


@pytest.mark.csrf
def test_el_testigo_de_una_sesion_no_sirve_en_otra(app_csrf):
    """La clave de sesión es la misma; lo que no se comparte es el testigo."""

    ajeno = _testigo(app_csrf.test_client())
    victima = app_csrf.test_client()
    _testigo(victima)

    respuesta = victima.post("/operator", data={"operator": "Ana", "_csrf_token": ajeno})

    assert respuesta.status_code == 400


@pytest.mark.csrf
def test_la_instalacion_sin_usuarios_tambien_esta_protegida(cliente):
    """**El caso que se olvida.**

    APATE arranca en modo abierto hasta que se crea la primera identidad, y en
    esa ventana *todo* es escribible. Si la verificación dependiera de haber
    iniciado sesión, justo ahí no protegería nada.
    """

    assert cliente.post("/operator", data={"operator": "Ana"}).status_code == 400


@pytest.mark.csrf
def test_el_login_tambien_exige_testigo(cliente, app_csrf):
    """Un login forzado desde otro sitio mete al operador en una cuenta ajena."""

    app_csrf.config["IDENTITY_PROVIDER"].create("admin", "secreta")

    respuesta = cliente.post("/login", data={"display_name": "admin", "password": "secreta"})

    assert respuesta.status_code == 400


@pytest.mark.csrf
def test_el_rechazo_explica_que_pasó(cliente):
    cuerpo = cliente.post("/operator", data={"operator": "Ana"}).get_data(as_text=True)

    assert "testigo de sesión" in cuerpo or "iniciaste vos" in cuerpo
