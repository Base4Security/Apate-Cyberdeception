"""Proteccion contra falsificacion de peticiones entre sitios (CSRF).

**Por que existe.** Toda mutacion de APATE es un POST de formulario: crear y
cerrar operaciones, desplegar y retirar decoys, guardar el YAML de reglas,
crear usuarios, cambiar contrasenias. Sin un testigo por sesion, cualquier
pagina que el operador visite con la sesion abierta puede disparar esas
acciones desde su navegador -- y en esta aplicacion eso significa desplegar o
retirar engano dentro de la red de un cliente. `SameSite=Lax` ayuda pero no
alcanza: no cubre todos los casos, y se debilita detras de un reverse proxy
que comparta origen con otra aplicacion.

**Deniega por defecto, en un solo lugar.** La verificacion vive en un
`before_request` global y no en cada vista, por el mismo criterio que la
allowlist de `apate.web.access`: una ruta nueva nace protegida sin que su
autor tenga que acordarse. No hay lista de exenciones -- si alguna hiciera
falta algun dia, tiene que ser explicita y estar escrita aca.

**Tambien con la instalacion sin usuarios.** APATE arranca en modo abierto
hasta que se crea la primera identidad, y en esa ventana *todo* es escribible,
incluida la creacion del primer administrador. Por eso la verificacion no
depende de que haya sesion iniciada: corre siempre.

**El testigo vive en la sesion**, que es una cookie firmada por Flask, asi que
no hace falta almacenamiento del lado del servidor ni que exista un usuario.
Se emite en la primera peticion que lo necesite y sobrevive al login: quien
inicia sesion no pierde el testigo que ya tenia, y `session.clear()` en el
camino de expulsion genera uno nuevo en la peticion siguiente.
"""

from __future__ import annotations

import secrets

from flask import abort, current_app, render_template, request, session

from ..i18n import gettext as _

#: Nombre del campo oculto en los formularios y de la cabecera para `fetch()`.
CAMPO = "_csrf_token"
CABECERA = "X-CSRF-Token"

#: Clave en la sesion. Con guion bajo adelante para que se distinga de los
#: datos de identidad que guarda `apate.web`.
_CLAVE_DE_SESION = "_csrf_token"

#: Los metodos que no cambian estado. Son los del RFC 9110: una peticion que
#: se declara segura y muta datos ya es un problema aparte (y el test de
#: `access.py` verifica que no haya ninguna).
METODOS_SEGUROS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def issue_token() -> str:
    """Devuelve el testigo de esta sesion, creandolo la primera vez."""

    testigo = session.get(_CLAVE_DE_SESION)
    if not testigo:
        testigo = secrets.token_urlsafe(32)
        session[_CLAVE_DE_SESION] = testigo
    return testigo


def _testigo_de_la_peticion() -> str:
    """El testigo que trajo la peticion, del formulario o de la cabecera.

    La cabecera existe para el JavaScript de la interfaz, que llama por
    `fetch()` y no tiene un formulario donde poner un campo oculto.
    """

    return request.form.get(CAMPO) or request.headers.get(CABECERA) or ""


def validate_request() -> None:
    """Rechaza una mutacion sin testigo valido. Pensado como `before_request`.

    Compara con `compare_digest` y no con `==`: la diferencia es irrelevante
    para un testigo de 32 bytes aleatorios, pero es la forma correcta de
    comparar un secreto y no cuesta nada.
    """

    if request.method in METODOS_SEGUROS:
        return
    # La API solo admite Authorization: Bearer, validado por su guarda de
    # máquina antes de ejecutar una vista. Nunca acepta una cookie web.
    if request.blueprint == "api":
        return
    if request.blueprint in current_app.extensions.get("apate.machine_transports", {}):
        # La guarda de transporte exige autenticación bearer antes de la vista.
        return
    esperado = session.get(_CLAVE_DE_SESION)
    recibido = _testigo_de_la_peticion()
    if esperado and recibido and secrets.compare_digest(esperado, recibido):
        return
    abort(400, description="csrf")


def register(app) -> None:
    """Instala la verificacion, el global de plantillas y la pagina de error.

    El `before_request` se registra **antes** que el de identidad para que una
    peticion falsificada se rechace sin llegar a tocar ningun repositorio.
    Flask los corre en orden de registro, asi que este modulo se engancha
    temprano en `create_app()` a proposito.

    **No hay interruptor para apagarlo.** Una opcion de configuracion que
    desactive CSRF termina activada en la instalacion de alguien, siempre, y
    ninguna razon legitima la justifica. La suite lo neutraliza reemplazando
    esta funcion (ver `tests/conftest.py`), que es un gesto deliberado del
    banco de pruebas y no una configuracion que un operador pueda tocar por
    accidente; `tests/test_csrf.py` corre con la real.
    """

    app.before_request(validate_request)
    app.jinja_env.globals["csrf_token"] = issue_token

    @app.errorhandler(400)
    def _peticion_invalida(error):
        if getattr(error, "description", "") != "csrf":
            return render_template("errors/400.html", csrf=False), 400
        return render_template("errors/400.html", csrf=True), 400
