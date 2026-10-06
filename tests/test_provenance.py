"""Aviso de licencia y oferta de fuente correspondiente (AGPLv3, art. 13).

Dos niveles, con proposito distinto:

* **Comportamiento** -- `build_info()` resuelve version, commit y URL del
  fuente con la precedencia declarada, y **no inventa una URL cuando no se
  declaro ninguna**. Ese ultimo punto es el que evita el peor resultado
  posible: un enlace que aparenta cumplimiento y devuelve 404.

* **Sincronizacion** -- `NOTICE` y `THIRD_PARTY_COMPONENTS` no pueden
  divergir, y `/about` tiene que seguir siendo alcanzable sin sesion. Un
  aviso de licencia detras del login es inalcanzable justo para quien no
  tiene cuenta, que es parte de "todos los usuarios que interactuan
  remotamente".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apate.provenance import (
    LICENSE_SPDX,
    THIRD_PARTY_COMPONENTS,
    BuildInfo,
    build_info,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _limpiar_cache_de_build_info():
    """`build_info()` esta memoizada por proceso; cada test parte de cero."""

    build_info.cache_clear()
    yield
    build_info.cache_clear()


# -- Comportamiento de build_info() ------------------------------------


def test_sin_variable_no_se_declara_ninguna_url_de_fuente(monkeypatch):
    # El repositorio de referencia es privado: apuntar ahi por defecto le
    # daria al visitante un 404 en vez de un fuente, que es peor que no
    # ofrecer nada porque aparenta cumplimiento.
    monkeypatch.delenv("APATE_SOURCE_URL", raising=False)

    info = build_info()

    assert info.source_url is None
    assert info.declares_source is False


def test_la_url_declarada_se_expone_tal_cual(monkeypatch):
    monkeypatch.setenv("APATE_SOURCE_URL", "https://ejemplo.invalid/fuente.tar.gz")

    info = build_info()

    assert info.source_url == "https://ejemplo.invalid/fuente.tar.gz"
    assert info.declares_source is True


def test_una_url_en_blanco_cuenta_como_no_declarada(monkeypatch):
    # Un valor vacio en el entorno es un descuido de configuracion, no una
    # declaracion: tratarlo como URL valida mostraria un enlace a ninguna parte.
    monkeypatch.setenv("APATE_SOURCE_URL", "   ")

    assert build_info().declares_source is False


def test_el_commit_del_build_gana_sobre_el_del_checkout(monkeypatch):
    monkeypatch.setenv("APATE_BUILD_COMMIT", "0123456789abcdef0123456789abcdef01234567")

    info = build_info()

    assert info.commit == "0123456789abcdef0123456789abcdef01234567"
    assert info.short_commit == "0123456789ab"


def test_sin_commit_declarado_se_resuelve_o_queda_en_none(monkeypatch):
    # En un checkout de git se lee `.git`; en una imagen sin `.git` queda
    # `None`. Las dos son respuestas correctas: lo que no puede pasar es que
    # falte el atributo o que reviente el arranque.
    monkeypatch.delenv("APATE_BUILD_COMMIT", raising=False)

    info = build_info()

    assert info.commit is None or len(info.commit) >= 7


def test_la_licencia_declarada_es_la_del_archivo_license():
    info = build_info()

    assert info.license_spdx == LICENSE_SPDX == "AGPL-3.0-or-later"
    # El texto oficial de la FSF dice "GNU AFFERO GENERAL PUBLIC LICENSE";
    # la sigla "AGPL" no aparece literalmente en el encabezado.
    encabezado = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8", errors="ignore")[:4000].upper()
    assert "AFFERO GENERAL PUBLIC LICENSE" in encabezado
    assert "VERSION 3" in encabezado


def test_short_commit_es_none_cuando_no_hay_commit():
    info = BuildInfo(version="1.2.3", commit=None, source_url=None)

    assert info.short_commit is None


# -- Sincronizacion de NOTICE ------------------------------------------


def test_notice_menciona_cada_componente_del_inventario():
    """Sin esto, agregar una dependencia deja `NOTICE` mintiendo en silencio."""

    notice = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")

    faltantes = [c.name for c in THIRD_PARTY_COMPONENTS if c.name not in notice]
    assert not faltantes, (
        "NOTICE no menciona estos componentes de THIRD_PARTY_COMPONENTS: "
        f"{faltantes}. Regeneralo desde src/apate/provenance.py."
    )


def test_notice_declara_la_licencia_de_cada_componente():
    notice = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")

    for componente in THIRD_PARTY_COMPONENTS:
        assert componente.license_spdx in notice, (
            f"NOTICE no declara la licencia de {componente.name} "
            f"({componente.license_spdx})."
        )


def test_el_inventario_no_tiene_entradas_incompletas():
    for componente in THIRD_PARTY_COMPONENTS:
        assert componente.name.strip()
        assert componente.license_spdx.strip()
        assert componente.role.strip()


def test_los_componentes_vendorizados_conservan_su_texto_de_licencia():
    # Distribuir codigo de terceros sin su licencia es incumplir la de ellos,
    # no la propia. Estas tres rutas estan citadas en NOTICE.
    for ruta in ("src/DOLOST/LICENSE", "src/BUDA/LICENSE", "playground-stack/LICENSE"):
        assert (REPO_ROOT / ruta).is_file(), f"Falta el texto de licencia de {ruta}"


# -- La ruta /about ----------------------------------------------------


def test_about_responde_sin_sesion_con_autenticacion_activa(client, app):
    """El aviso no puede quedar detras del login.

    El articulo 13 habla de "todos los usuarios que interactuan remotamente":
    alguien detenido en la pantalla de login ya esta interactuando. Este test
    es la regresion de que `about` siga en las dos allowlists.
    """

    app.config["IDENTITY_PROVIDER"].create("admin", "secreta")

    respuesta = client.get("/about")

    assert respuesta.status_code == 200
    cuerpo = respuesta.get_data(as_text=True)
    assert "AGPL-3.0-or-later" in cuerpo


def test_about_muestra_version_licencia_y_componentes(client):
    cuerpo = client.get("/about").get_data(as_text=True)

    assert "AGPL-3.0-or-later" in cuerpo
    for componente in ("DOLOS-T", "BUDA", "Flask", "fpdf2"):
        assert componente in cuerpo


def test_about_dice_que_falta_declarar_el_fuente_cuando_no_hay_url(client, monkeypatch):
    monkeypatch.delenv("APATE_SOURCE_URL", raising=False)
    build_info.cache_clear()

    cuerpo = client.get("/about").get_data(as_text=True)

    assert "no declar" in cuerpo
    assert "APATE_SOURCE_URL" in cuerpo


def test_about_publica_la_url_declarada(client, monkeypatch):
    monkeypatch.setenv("APATE_SOURCE_URL", "https://ejemplo.invalid/apate.tar.gz")
    build_info.cache_clear()

    cuerpo = client.get("/about").get_data(as_text=True)

    assert "https://ejemplo.invalid/apate.tar.gz" in cuerpo


# -- El aviso del pie --------------------------------------------------


@pytest.mark.parametrize("ruta", ["/", "/operations/", "/rules/", "/capabilities/"])
def test_el_pie_lleva_el_aviso_a_toda_la_aplicacion(client, ruta):
    cuerpo = client.get(ruta).get_data(as_text=True)

    assert 'class="app-footer"' in cuerpo
    assert "/about" in cuerpo
    assert "AGPL-3.0-or-later" in cuerpo


def test_el_pie_aparece_tambien_en_la_pantalla_de_login(client, app):
    app.config["IDENTITY_PROVIDER"].create("admin", "secreta")

    cuerpo = client.get("/login").get_data(as_text=True)

    assert 'class="app-footer"' in cuerpo
    assert "/about" in cuerpo
