"""SBOM en CycloneDX 1.6: forma del documento, sincronia y control de acceso.

Tres niveles, con proposito distinto:

* **Forma** -- el documento tiene que ser CycloneDX valido y, sobre todo,
  *util*: un SBOM sintacticamente correcto pero sin `purl` no se puede cruzar
  contra ninguna base de vulnerabilidades, que es la unica razon por la que el
  cliente lo pidio.

* **Sincronizacion** -- `THIRD_PARTY_COMPONENTS` es la fuente de verdad de
  `NOTICE`, de `/about` y ahora tambien del SBOM. Mismo criterio que
  `test_provenance.py`: agregar una dependencia no puede dejar un documento
  mintiendo en silencio.

* **Acceso** -- que `/about/sbom.json` exija sesion es una decision, no un
  descuido, y una decision sin test se revierte sola en el primer refactor.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from apate.provenance import THIRD_PARTY_COMPONENTS, BuildInfo, build_info
from apate.sbom import (
    CYCLONEDX_MEDIA_TYPE,
    CYCLONEDX_SPEC_VERSION,
    build_document,
    build_json,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

BUILD_DE_PRUEBA = BuildInfo(
    version="1.2.3",
    commit="0123456789abcdef0123456789abcdef01234567",
    source_url="https://ejemplo.invalid/apate.tar.gz",
)


@pytest.fixture(autouse=True)
def _limpiar_cache_de_build_info():
    build_info.cache_clear()
    yield
    build_info.cache_clear()


# -- Forma del documento -----------------------------------------------


def test_el_documento_declara_formato_y_version_del_esquema():
    documento = build_document(build=BUILD_DE_PRUEBA)

    assert documento["bomFormat"] == "CycloneDX"
    assert documento["specVersion"] == CYCLONEDX_SPEC_VERSION == "1.6"
    assert documento["version"] == 1


def test_el_serial_number_es_un_urn_uuid_valido():
    serial = build_document(build=BUILD_DE_PRUEBA)["serialNumber"]

    assert re.fullmatch(
        r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", serial
    ), serial


def test_el_documento_describe_la_aplicacion_que_lo_genero():
    metadata = build_document(build=BUILD_DE_PRUEBA)["metadata"]["component"]

    assert metadata["type"] == "application"
    assert metadata["name"] == "apate"
    assert metadata["version"] == "1.2.3"
    assert metadata["licenses"] == [{"license": {"id": "AGPL-3.0-or-later"}}]


def test_el_commit_viaja_como_propiedad_con_espacio_de_nombres_propio():
    # CycloneDX pide que toda extension vaya en `properties` con prefijo
    # propio, para que un consumidor generico pueda ignorarla sin romperse.
    propiedades = build_document(build=BUILD_DE_PRUEBA)["metadata"]["component"]["properties"]

    assert {"name": "apate:build:commit", "value": BUILD_DE_PRUEBA.commit} in propiedades


def test_la_url_del_fuente_correspondiente_viaja_en_el_sbom():
    # El area legal del cliente suele recibir el SBOM y no visitar /about.
    referencias = build_document(build=BUILD_DE_PRUEBA)["metadata"]["component"][
        "externalReferences"
    ]

    assert {"type": "distribution-source", "url": BUILD_DE_PRUEBA.source_url} in referencias


def test_sin_url_declarada_no_se_inventa_una_referencia():
    sin_url = BuildInfo(version="1.2.3", commit=None, source_url=None)

    metadata = build_document(build=sin_url)["metadata"]["component"]

    assert "externalReferences" not in metadata
    assert "properties" not in metadata


# -- Utilidad real: identificadores de paquete -------------------------


def test_cada_dependencia_de_pypi_lleva_purl_con_su_version_instalada():
    """Sin `purl` el SBOM se lee pero no se cruza contra ningun CVE."""

    documento = build_document(build=BUILD_DE_PRUEBA)
    por_nombre = {c["name"]: c for c in documento["components"]}

    for componente in THIRD_PARTY_COMPONENTS:
        if not componente.distribution:
            continue
        entrada = por_nombre[componente.name]
        version = componente.installed_version()
        assert entrada["purl"].startswith("pkg:pypi/")
        if version:
            assert entrada["purl"].endswith(f"@{version}")
            assert entrada["version"] == version


def test_el_nombre_del_purl_esta_normalizado_como_exige_la_especificacion():
    # El tipo `pypi` de purl exige minusculas y guiones: `pkg:pypi/Flask` no
    # matchea contra las bases de datos, `pkg:pypi/flask` si.
    purls = {
        c["name"]: c.get("purl", "") for c in build_document(build=BUILD_DE_PRUEBA)["components"]
    }

    assert purls["Flask"].startswith("pkg:pypi/flask@")
    assert purls["PyJWT"].startswith("pkg:pypi/pyjwt@")
    assert purls["Flask-SocketIO"].startswith("pkg:pypi/flask-socketio@")


def test_los_vendorizados_llevan_coordenada_de_repositorio_y_ninguna_version():
    # La copia esta congelada al vendorizarla: no se corresponde con ningun
    # tag del origen, asi que declarar una version seria inventarla.
    por_nombre = {c["name"]: c for c in build_document(build=BUILD_DE_PRUEBA)["components"]}

    for nombre in ("DOLOS-T", "BUDA", "Cyber Deception Playground"):
        entrada = por_nombre[nombre]
        assert entrada["purl"].startswith("pkg:github/base4security/")
        assert "@" not in entrada["purl"]
        assert "version" not in entrada


def test_los_componentes_de_cdn_se_listan_sin_coordenada_de_paquete():
    # No los empaqueta este proyecto, pero el navegador los recibe igual:
    # omitirlos seria un inventario incompleto.
    por_nombre = {c["name"]: c for c in build_document(build=BUILD_DE_PRUEBA)["components"]}

    for nombre in ("CodeMirror 5", "Socket.IO"):
        assert "purl" not in por_nombre[nombre]
        assert {"name": "apate:entrega", "value": "cdn"} in por_nombre[nombre]["properties"]


# -- Licencias ---------------------------------------------------------


def test_una_expresion_spdx_no_se_emite_como_identificador():
    """`Apache-2.0 OR BSD-3-Clause` en `license.id` valida y no sirve.

    El esquema lo acepta, pero el escaner no lo reconoce como licencia
    conocida y lo reporta como desconocida: hay que usar `expression`.
    """

    por_nombre = {c["name"]: c for c in build_document(build=BUILD_DE_PRUEBA)["components"]}

    assert por_nombre["cryptography"]["licenses"] == [
        {"expression": "Apache-2.0 OR BSD-3-Clause"}
    ]
    assert por_nombre["fpdf2"]["licenses"] == [{"license": {"id": "LGPL-3.0-only"}}]


def test_cada_componente_declara_su_licencia():
    for componente in build_document(build=BUILD_DE_PRUEBA)["components"]:
        licencias = componente["licenses"]
        assert len(licencias) == 1
        assert "license" in licencias[0] or "expression" in licencias[0]


# -- Sincronizacion con el inventario ----------------------------------


def test_el_sbom_incluye_cada_componente_del_inventario():
    """Misma garantia que da `test_provenance.py` sobre `NOTICE`."""

    documento = build_document(build=BUILD_DE_PRUEBA)
    nombres = {c["name"] for c in documento["components"]}

    faltantes = [c.name for c in THIRD_PARTY_COMPONENTS if c.name not in nombres]
    assert not faltantes, f"El SBOM no incluye: {faltantes}"
    assert len(documento["components"]) == len(THIRD_PARTY_COMPONENTS)


def test_las_referencias_internas_son_unicas():
    # `bom-ref` es la clave con la que el resto del documento apunta a un
    # componente; repetida, un consumidor no sabe a cual de los dos se refiere.
    referencias = [c["bom-ref"] for c in build_document(build=BUILD_DE_PRUEBA)["components"]]

    assert len(referencias) == len(set(referencias))


def test_la_descripcion_no_depende_del_idioma_del_operador(app):
    """El SBOM tiene que ser identico lo pida quien lo pida.

    `role` es un `LazyString` que en `/about` sigue el idioma de la sesion.
    Si el SBOM lo resolviera igual, dos clientes con distinto idioma
    recibirian documentos distintos del mismo build.
    """

    with app.test_request_context("/", headers={"Accept-Language": "en"}):
        en_ingles = build_json(build=BUILD_DE_PRUEBA)
    with app.test_request_context("/", headers={"Accept-Language": "es"}):
        en_castellano = build_json(build=BUILD_DE_PRUEBA)

    assert en_ingles == en_castellano


# -- Determinismo ------------------------------------------------------


def test_dos_generaciones_del_mismo_build_son_identicas():
    """Sin esto, cualquier diff entre dos SBOM miente."""

    assert build_json(build=BUILD_DE_PRUEBA) == build_json(build=BUILD_DE_PRUEBA)


def test_builds_distintos_producen_seriales_distintos():
    otro = BuildInfo(version="9.9.9", commit=BUILD_DE_PRUEBA.commit, source_url=None)

    assert (
        build_document(build=BUILD_DE_PRUEBA)["serialNumber"]
        != build_document(build=otro)["serialNumber"]
    )


def test_la_marca_de_tiempo_queda_fuera_salvo_que_se_la_pida():
    # Un timestamp por corrida haria que dos SBOM del mismo build difieran.
    assert "timestamp" not in build_document(build=BUILD_DE_PRUEBA)["metadata"]

    con_fecha = build_document(build=BUILD_DE_PRUEBA, timestamp="2026-09-12T00:00:00Z")
    assert con_fecha["metadata"]["timestamp"] == "2026-09-12T00:00:00Z"


# -- La ruta HTTP ------------------------------------------------------


def test_el_sbom_se_sirve_con_su_tipo_de_medio(client):
    respuesta = client.get("/about/sbom.json")

    assert respuesta.status_code == 200
    assert respuesta.mimetype == CYCLONEDX_MEDIA_TYPE == "application/vnd.cyclonedx+json"
    assert json.loads(respuesta.get_data(as_text=True))["bomFormat"] == "CycloneDX"


def test_el_sbom_exige_sesion_a_diferencia_de_about(client, app):
    """La decision de acceso, como regresion explicita.

    `/about` es publico porque el articulo 13 obliga a ofrecer el fuente a
    cualquier usuario remoto. El SBOM dice otra cosa -- que version exacta de
    cada dependencia corre -- y servirlo sin autenticar desde una herramienta
    que vive dentro de la red que protege regala un mapa de superficie de
    ataque.

    Lo que esto fija es la allowlist *previa a la sesion* de
    `_require_authenticated_identity`, que es la que decide quien pasa sin
    identidad. La clasificacion de rol en `apate.web.access` es una segunda
    puerta y la cubre el test siguiente: son dos listas distintas, y hay que
    quedarse afuera de las dos.
    """

    app.config["IDENTITY_PROVIDER"].create("admin", "secreta")

    assert client.get("/about").status_code == 200

    respuesta = client.get("/about/sbom.json")
    assert respuesta.status_code in (302, 401, 403)
    if respuesta.status_code == 302:
        assert "/login" in respuesta.headers["Location"]


def test_el_sbom_no_esta_entre_los_endpoints_publicos():
    """La otra puerta, la de roles.

    Sin esto, mover `sbom` a `_PUBLIC_ENDPOINTS` no rompe nada visible: la
    allowlist previa a la sesion lo sigue frenando, asi que el descuido queda
    latente hasta que alguien toque *esa* lista y recien ahi el inventario se
    vuelva publico, lejos del cambio que lo causo.
    """

    from apate.web.access import _PUBLIC_ENDPOINTS

    assert "sbom" not in _PUBLIC_ENDPOINTS
    assert "about" in _PUBLIC_ENDPOINTS


def test_cualquier_rol_autenticado_puede_leer_el_sbom(app):
    """Lo que se cierra es el acceso anonimo, no el del equipo.

    `required_role()` deniega por defecto todo endpoint sin clasificar: si
    alguien agrega la ruta y se olvida de `_READ_ENDPOINTS`, el rol mas bajo
    recibe un 403 y este test lo dice.
    """

    app.config["IDENTITY_PROVIDER"].create(
        "Ana Lectora", "secreta", role="read", team_id="demo"
    )
    cliente = app.test_client()
    cliente.post("/login", data={"display_name": "Ana Lectora", "password": "secreta"})

    respuesta = cliente.get("/about/sbom.json")

    assert respuesta.status_code == 200
    assert json.loads(respuesta.get_data(as_text=True))["bomFormat"] == "CycloneDX"


# -- La linea de comandos ----------------------------------------------


def test_el_modulo_se_puede_ejecutar_para_generar_el_archivo():
    """Es el camino del build: `python -m apate.sbom > apate.cdx.json`."""

    resultado = subprocess.run(
        [sys.executable, "-m", "apate.sbom"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )

    assert resultado.returncode == 0, resultado.stderr
    documento = json.loads(resultado.stdout)
    assert documento["bomFormat"] == "CycloneDX"
    assert len(documento["components"]) == len(THIRD_PARTY_COMPONENTS)
