"""Vida de la sesión, freno a la fuerza bruta y auditoría de inicios de sesión.

Tres huecos distintos, y ninguno se tapa con los otros dos:

* **La sesión no expiraba nunca.** Una cookie capturada —de un backup, de un
  log de proxy, de un puesto sin bloquear— valía indefinidamente mientras no
  rotara `APATE_SECRET_KEY` ni cambiara esa contraseña.
* **No había ningún freno a los intentos.** `authenticate()` se podía llamar en
  un bucle, sin contador ni espera.
* **Los inicios de sesión no quedaban en ninguna parte.** Había auditoría de
  alta, baja y cambio de contraseña, pero no de quién entró ni de quién lo
  intentó y falló: la fuerza bruta era libre *e* invisible.
"""

from __future__ import annotations

import time

import pytest

from apate.web import create_app
from apate.web._sessions import (
    INACTIVIDAD_MAXIMA_SEGUNDOS,
    VIDA_MAXIMA_SEGUNDOS,
    ControlDeIntentos,
    marcar_inicio,
    vencida,
)

CLAVE = "Clave-de-prueba"


@pytest.fixture
def app(tmp_path):
    return create_app({
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "datos",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
        "SECRET_KEY": "fija-para-el-test",
    })


@pytest.fixture
def cliente(app):
    app.config["IDENTITY_PROVIDER"].create("Ana", CLAVE)
    return app.test_client()


# -- Los dos relojes ---------------------------------------------------


def test_una_sesion_recien_iniciada_vale():
    sesion = {}
    marcar_inicio(sesion)

    assert vencida(sesion) is False


def test_vence_por_antiguedad_aunque_se_haya_usado_todo_el_tiempo():
    """El máximo absoluto acota el daño de una credencial robada: sin él, una
    sesión muy usada no vencería nunca."""

    ahora = time.time()
    sesion = {"_iniciada_en": ahora - VIDA_MAXIMA_SEGUNDOS - 1, "_ultima_actividad": ahora}

    assert vencida(sesion) is True


def test_vence_por_inactividad_aunque_sea_reciente():
    """El reloj de inactividad cierra el puesto que alguien dejó abierto: sin
    él, una sesión iniciada hace un rato viviría hasta el máximo."""

    ahora = time.time()
    sesion = {
        "_iniciada_en": ahora - 60,
        "_ultima_actividad": ahora - INACTIVIDAD_MAXIMA_SEGUNDOS - 1,
    }

    assert vencida(sesion) is True


def test_una_sesion_sin_sello_se_considera_vencida():
    """Es una cookie anterior a esta verificación. Darle vida indefinida sería
    dejar abierta justo la puerta que esto viene a cerrar."""

    assert vencida({"identity_id": "x"}) is True


def test_un_sello_corrupto_tambien(monkeypatch):
    assert vencida({"_iniciada_en": "ayer", "_ultima_actividad": "hoy"}) is True


def test_la_sesion_vencida_manda_al_login(app, cliente):
    identidad = app.config["IDENTITY_PROVIDER"].list()[0]
    with cliente.session_transaction() as sesion:
        sesion["identity_id"] = identidad.id
        sesion["credential_version"] = identidad.credential_version
        sesion["_iniciada_en"] = time.time() - VIDA_MAXIMA_SEGUNDOS - 1
        sesion["_ultima_actividad"] = time.time()

    respuesta = cliente.get("/operations/")

    assert respuesta.status_code == 302
    assert "/login" in respuesta.headers["Location"]


def test_usar_la_aplicacion_corre_el_reloj_de_inactividad(app, cliente):
    identidad = app.config["IDENTITY_PROVIDER"].list()[0]
    with cliente.session_transaction() as sesion:
        sesion["identity_id"] = identidad.id
        sesion["credential_version"] = identidad.credential_version
        marcar_inicio(sesion)
        sesion["_ultima_actividad"] = time.time() - 120

    cliente.get("/operations/")

    with cliente.session_transaction() as sesion:
        assert time.time() - sesion["_ultima_actividad"] < 5


def test_usar_la_aplicacion_no_corre_el_maximo_absoluto(app, cliente):
    """Si refrescar la actividad moviera también el inicio, el máximo no
    existiría: bastaría con usar la sesión para hacerla eterna."""

    identidad = app.config["IDENTITY_PROVIDER"].list()[0]
    inicio = time.time() - 3600
    with cliente.session_transaction() as sesion:
        sesion["identity_id"] = identidad.id
        sesion["credential_version"] = identidad.credential_version
        sesion["_iniciada_en"] = inicio
        sesion["_ultima_actividad"] = time.time()

    cliente.get("/operations/")

    with cliente.session_transaction() as sesion:
        assert abs(sesion["_iniciada_en"] - inicio) < 1


def test_el_login_sella_la_sesion(cliente):
    cliente.post("/login", data={"display_name": "Ana", "password": CLAVE})

    with cliente.session_transaction() as sesion:
        assert "_iniciada_en" in sesion and "_ultima_actividad" in sesion


# -- El freno ----------------------------------------------------------


def test_frena_despues_del_limite():
    control = ControlDeIntentos(limite=3, freno=60)

    for _ in range(3):
        control.registrar_fallo("ana", "10.0.0.1")

    assert control.segundos_de_espera("ana", "10.0.0.1") > 0


def test_no_frena_antes_del_limite():
    control = ControlDeIntentos(limite=3, freno=60)

    for _ in range(2):
        control.registrar_fallo("ana", "10.0.0.1")

    assert control.segundos_de_espera("ana", "10.0.0.1") == 0


def test_el_freno_es_por_nombre_y_origen():
    """**Por qué no alcanza con frenar por nombre.**

    Frenar sólo por nombre le da a cualquiera una forma trivial de bloquearle
    la cuenta a otro: basta con fallar adrede cinco veces.
    """

    control = ControlDeIntentos(limite=3, freno=60)

    for _ in range(3):
        control.registrar_fallo("ana", "10.0.0.1")

    assert control.segundos_de_espera("ana", "10.0.0.1") > 0
    assert control.segundos_de_espera("ana", "10.0.0.2") == 0


def test_entrar_limpia_el_contador():
    control = ControlDeIntentos(limite=3, freno=60)
    control.registrar_fallo("ana", "10.0.0.1")
    control.registrar_fallo("ana", "10.0.0.1")

    control.registrar_exito("ana", "10.0.0.1")
    control.registrar_fallo("ana", "10.0.0.1")

    assert control.segundos_de_espera("ana", "10.0.0.1") == 0


def test_insistir_durante_el_freno_no_acorta_la_espera():
    control = ControlDeIntentos(limite=2, freno=60)
    control.registrar_fallo("ana", "10.0.0.1")
    control.registrar_fallo("ana", "10.0.0.1")
    primera = control.segundos_de_espera("ana", "10.0.0.1")

    control.registrar_fallo("ana", "10.0.0.1")

    assert control.segundos_de_espera("ana", "10.0.0.1") >= primera - 1


def test_los_contadores_viejos_se_descartan():
    """Sin esto la tabla crece sola mientras el proceso viva."""

    ahora = [100.0]
    control = ControlDeIntentos(
        limite=3,
        freno=60,
        memoria=10,
        reloj_monotonic=lambda: ahora[0],
    )
    control.registrar_fallo("ana", "10.0.0.1")

    ahora[0] += 10
    control.registrar_fallo("otra", "10.0.0.2")

    assert ("ana", "10.0.0.1") not in control._por_clave


def test_el_login_real_frena_y_lo_dice(app, cliente):
    for _ in range(6):
        cliente.post("/login", data={"display_name": "Ana", "password": "incorrecta"})

    respuesta = cliente.post(
        "/login", data={"display_name": "Ana", "password": CLAVE}, follow_redirects=True
    )

    # Ni siquiera con la clave correcta: el freno es anterior a comprobarla.
    assert "intentos fallidos" in respuesta.get_data(as_text=True)


# -- La auditoría ------------------------------------------------------


def _acciones(app):
    with app.app_context():
        return app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation("identity-management")


def test_un_login_exitoso_queda_registrado(app, cliente):
    cliente.post("/login", data={"display_name": "Ana", "password": CLAVE})

    assert any(a.action == "login" and a.outcome == "success" for a in _acciones(app))


def test_un_login_fallido_tambien(app, cliente):
    """Un intento fallido es tan informativo como uno exitoso. Muchas veces, más."""

    cliente.post("/login", data={"display_name": "Ana", "password": "incorrecta"})

    assert any(a.action == "login" and a.outcome == "error" for a in _acciones(app))


def test_se_registra_el_nombre_tal_como_lo_escribieron(app, cliente):
    """Un intento contra una cuenta inexistente es justamente lo que se quiere
    poder ver: si sólo se registraran los nombres válidos, un barrido de
    usuarios sería invisible."""

    cliente.post("/login", data={"display_name": "root", "password": "x"})

    assert any(a.operator == "root" for a in _acciones(app))


def test_un_fallo_de_auditoria_no_impide_entrar(app, cliente, monkeypatch):
    """La auditoría es importante; dejar a alguien afuera de su propia consola
    porque no se pudo escribir un registro, no."""

    class _Rota:
        def append(self, _accion):
            raise OSError("disco lleno")

    app.config["OPERATOR_ACTION_REPOSITORY"] = _Rota()

    respuesta = cliente.post("/login", data={"display_name": "Ana", "password": CLAVE})

    assert respuesta.status_code == 302
