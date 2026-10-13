"""Flujo web de identidad local y atribución autenticada."""

import pytest

from apate.web._sessions import marcar_inicio
from flask import session

from apate.audit import OperatorAction
from apate.web.blueprints.operations import _log_operator_action


_PASSWORD = "Clave-local-de-prueba"


def _create_user(app, name="Ana Operadora"):
    return app.config["IDENTITY_PROVIDER"].create(name, _PASSWORD)


def test_without_users_the_application_remains_open_and_warns_about_authentication(client):
    response = client.get("/operations/")

    assert response.status_code == 200
    assert b"La instancia est" in response.data
    assert b"create-user" in response.data
    assert b'placeholder="sin especificar"' in response.data


def test_first_user_activates_global_login_guard(app, client):
    _create_user(app)

    response = client.get("/operations/", follow_redirects=False)

    assert response.status_code == 302
    assert "/login?next=/operations/" in response.headers["Location"]


def test_login_accepts_valid_credentials_and_rejects_invalid_ones_without_exposing_password(app, client):
    _create_user(app)

    invalid = client.post("/login", data={"display_name": "Ana Operadora", "password": "incorrecta"})
    assert invalid.status_code == 200
    assert b"Credenciales inv" in invalid.data
    assert b"incorrecta" not in invalid.data

    valid = client.post(
        "/login",
        data={"display_name": "Ana Operadora", "password": _PASSWORD, "next": "/operations/"},
        follow_redirects=False,
    )

    assert valid.status_code == 302
    assert valid.headers["Location"].endswith("/operations/")
    page = client.get("/operations/")
    assert b"Ana Operadora" in page.data
    assert _PASSWORD.encode() not in page.data
    assert b"operator-input" not in page.data


def test_login_rejects_backslash_redirect_that_browsers_can_treat_as_external(app, client):
    _create_user(app)

    response = client.post(
        "/login",
        data={
            "display_name": "Ana Operadora",
            "password": _PASSWORD,
            "next": r"/\evil.example/path",
        },
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/")
    assert "evil.example" not in response.headers["Location"]


def test_request_bodies_have_a_global_size_limit(app, client):
    app.config["MAX_CONTENT_LENGTH"] = 64
    _create_user(app)

    response = client.post(
        "/login",
        data={"display_name": "x" * 200, "password": "y" * 200},
    )

    assert response.status_code == 413


def test_authenticated_display_name_is_used_for_manual_audit_actions(app):
    identity = _create_user(app)

    with app.test_request_context("/"):
        session["identity_id"] = identity.id
        marcar_inicio(session)
        session["operator"] = "Nombre libre que no debe prevalecer"
        _log_operator_action(
            "op-identity", action="prueba_manual", outcome="success", detail="Acción de prueba."
        )

    actions = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation("op-identity")
    assert actions[0].operator == "Ana Operadora"


def test_local_user_cli_creates_lists_and_deactivates_without_echoing_password(app):
    runner = app.test_cli_runner()

    # Beto no puede ser el unico administrador: la guarda del ultimo admin
    # impediria darlo de baja al final de este test.
    runner.invoke(args=["create-user", "Titular", "--role", "administration"], input=f"{_PASSWORD}\n{_PASSWORD}\n")

    created = runner.invoke(args=["create-user", "Beto", "--role", "operation", "--team", "demo"], input=f"{_PASSWORD}\n{_PASSWORD}\n")
    assert created.exit_code == 0
    assert _PASSWORD not in created.output

    listed = runner.invoke(args=["list-users"])
    assert "Beto" in listed.output
    identity = next(item for item in app.config["IDENTITY_PROVIDER"].list() if item.display_name == "Beto")

    deactivated = runner.invoke(args=["deactivate-user", identity.id])
    assert deactivated.exit_code == 0
    assert not next(item for item in app.config["IDENTITY_PROVIDER"].list() if item.id == identity.id).active


def test_generated_secret_key_is_not_the_old_fixed_value(app):
    assert app.config["SECRET_KEY"] != "dev"


def test_create_user_command_supports_unattended_password(app, monkeypatch):
    """`click.prompt(hide_input=True)` usa getpass, que lee de la consola y se
    cuelga sin terminal: exactamente el caso de una instalación desatendida
    (contenedor, Ansible), que es como se instala un producto on-premise.
    Confirmado colgándose de verdad al intentar crear el primer usuario por un
    pipe. La variable de entorno es la válvula de escape, y el modo
    interactivo sigue siendo el default.
    """

    monkeypatch.setenv("APATE_INITIAL_PASSWORD", "clave-desatendida-de-prueba")

    resultado = app.test_cli_runner().invoke(args=["create-user", "Operadora"])

    assert resultado.exit_code == 0, resultado.output
    assert "Usuario creado" in resultado.output
    # La contraseña no se imprime en ningún momento.
    assert "clave-desatendida-de-prueba" not in resultado.output
    assert app.config["IDENTITY_PROVIDER"].authenticate("Operadora", "clave-desatendida-de-prueba")


# -- Administracion de usuarios desde la web -------------------------------
# La pantalla da de alta y de baja identidades: es la superficie donde un
# error de permisos escala privilegios. Estos tests fijan lo que se verifico
# a mano contra las rutas reales.

def _crear(app, nombre, clave, rol, equipo=None):
    return app.config["IDENTITY_PROVIDER"].create(nombre, clave, role=rol, team_id=equipo)


def _sesion(app, nombre, clave):
    cliente = app.test_client()
    cliente.post("/login", data={"display_name": nombre, "password": clave})
    return cliente


@pytest.mark.parametrize("rol,equipo", [("read", "demo"), ("operation", "demo")])
def test_non_administrators_cannot_reach_any_user_administration_route(app, rol, equipo):
    """Ni ven la pantalla ni pueden mutar identidades por POST directo.

    Ocultar el enlace no alcanza: lo que protege es la verificacion del
    servidor, y es la que se prueba acá.
    """

    _crear(app, "Titular", "clave-admin", "administration")
    victima = _crear(app, "Victima", "clave-victima", "operation", "demo")
    intruso = _crear(app, "Intruso", "clave-intruso", rol, equipo)
    cliente = _sesion(app, "Intruso", "clave-intruso")

    assert cliente.get("/health/administration/users").status_code == 403
    for ruta, datos in (
        ("/health/administration/users/create",
         {"display_name": "Colado", "password": "x", "role": "administration"}),
        (f"/health/administration/users/{victima.id}/change-password",
         {"new_password": "otra", "new_password_confirmation": "otra"}),
        (f"/health/administration/users/{victima.id}/deactivate", {}),
    ):
        assert cliente.post(ruta, data=datos).status_code == 403, ruta

    proveedor = app.config["IDENTITY_PROVIDER"]
    assert [i.display_name for i in proveedor.list()] == ["Titular", "Victima", "Intruso"]
    assert proveedor.authenticate("Victima", "clave-victima") is not None
    assert next(i for i in proveedor.list() if i.id == victima.id).active
    assert intruso.role.value == rol


def test_the_web_screen_refuses_to_deactivate_the_last_administrator(app):
    """Misma guarda que el proveedor, ejercida por la ruta real."""

    admin = _crear(app, "Titular", "clave-admin", "administration")
    _crear(app, "Lector", "clave-lector", "read", "demo")
    cliente = _sesion(app, "Titular", "clave-admin")

    cliente.post(f"/health/administration/users/{admin.id}/deactivate")

    assert next(i for i in app.config["IDENTITY_PROVIDER"].list() if i.id == admin.id).active
    assert cliente.get("/operations/").status_code == 200


def test_the_user_screen_never_renders_a_hash_or_a_password(app):
    _crear(app, "Titular", "clave-admin-secreta", "administration")
    _crear(app, "Lector", "clave-lector-secreta", "read", "demo")
    cliente = _sesion(app, "Titular", "clave-admin-secreta")

    html = cliente.get("/health/administration/users").get_data(as_text=True)

    assert "Lector" in html
    for prohibido in ("clave-admin-secreta", "clave-lector-secreta", "password_hash", "pbkdf2", "scrypt"):
        assert prohibido not in html, prohibido


def test_each_user_mutation_leaves_an_operator_action(app):
    """Dar de alta o de baja a alguien es exactamente lo que ese log atribuye."""

    _crear(app, "Titular", "clave-admin", "administration")
    cliente = _sesion(app, "Titular", "clave-admin")
    from apate.web.blueprints.health import _IDENTITY_OPERATION_ID

    repo = app.config["OPERATOR_ACTION_REPOSITORY"]
    antes = len(repo.list_for_operation(_IDENTITY_OPERATION_ID))

    cliente.post(
        "/health/administration/users/create",
        data={"display_name": "Nueva", "password": "clave-nueva", "password_confirmation": "clave-nueva", "role": "read", "team_id": "demo"},
    )
    nueva = next(i for i in app.config["IDENTITY_PROVIDER"].list() if i.display_name == "Nueva")
    cliente.post(
        f"/health/administration/users/{nueva.id}/change-password",
        data={"new_password": "otra-clave", "new_password_confirmation": "otra-clave"},
    )
    cliente.post(f"/health/administration/users/{nueva.id}/deactivate")

    acciones = repo.list_for_operation(_IDENTITY_OPERATION_ID)
    assert len(acciones) >= antes + 3
    assert app.config["IDENTITY_PROVIDER"].authenticate("Nueva", "otra-clave") is None  # ya inactiva


# -- Reseteo de contrasena y sesiones abiertas -----------------------------
# El caso real es una cuenta comprometida: bloquear el proximo login no sirve
# de nada si el intruso ya esta adentro. Ver Identity.credential_version.

def test_resetting_someone_password_kicks_their_open_session(app):
    _crear(app, "Titular", "clave-admin", "administration")
    victima = _crear(app, "Comprometido", "vieja", "operation", "demo")
    admin = _sesion(app, "Titular", "clave-admin")
    intruso = _sesion(app, "Comprometido", "vieja")

    assert intruso.get("/operations/").status_code == 200

    admin.post(
        f"/health/administration/users/{victima.id}/change-password",
        data={"new_password": "nueva", "new_password_confirmation": "nueva"},
    )

    assert intruso.get("/operations/", follow_redirects=False).status_code == 302
    assert _sesion(app, "Comprometido", "nueva").get("/operations/").status_code == 200


def test_changing_your_own_password_does_not_log_you_out(app):
    """Quien acaba de cambiar su clave ya demostro que controla la cuenta."""

    admin_identity = _crear(app, "Titular", "clave-admin", "administration")
    admin = _sesion(app, "Titular", "clave-admin")

    admin.post(
        f"/health/administration/users/{admin_identity.id}/change-password",
        data={"new_password": "mi-nueva", "new_password_confirmation": "mi-nueva"},
    )

    assert admin.get("/operations/").status_code == 200


def test_an_unrelated_session_survives_a_password_reset(app):
    """Versionar la credencial no puede desloguear a terceros."""

    _crear(app, "Titular", "clave-admin", "administration")
    otro = _crear(app, "Ajeno", "suya", "operation", "demo")
    victima = _crear(app, "Comprometido", "vieja", "operation", "demo")
    admin = _sesion(app, "Titular", "clave-admin")
    ajeno = _sesion(app, "Ajeno", "suya")

    admin.post(
        f"/health/administration/users/{victima.id}/change-password",
        data={"new_password": "nueva", "new_password_confirmation": "nueva"},
    )

    assert ajeno.get("/operations/").status_code == 200
    assert otro.credential_version == 0


def test_sessions_created_before_credential_versioning_stay_valid(app):
    """Actualizar no puede desloguear a nadie.

    Un store escrito antes de este campo no lo tiene, y una cookie de sesion
    anterior tampoco: los dos se leen como version 0, que es la de una
    identidad a la que nunca le cambiaron la clave.
    """

    identidad = _crear(app, "Titular", "clave-admin", "administration")
    cliente = app.test_client()
    with cliente.session_transaction() as sesion_previa:
        sesion_previa["identity_id"] = identidad.id  # sin credential_version
        marcar_inicio(sesion_previa)

    assert cliente.get("/operations/").status_code == 200


def _menu_lateral(cliente) -> list[str]:
    import re

    html = cliente.get("/operations/").get_data(as_text=True)
    nav = re.search(r'<nav id="sidebar-navigation">(.*?)</nav>', html, re.S)
    return re.findall(r">([^<>]{3,40})</a>", nav.group(1)) if nav else []


def test_user_administration_has_its_own_entry_only_for_administrators(app):
    """Estaba solo en la paleta de comandos y en el submenu de Salud.

    El usuario no la encontraba, que es el sintoma de una tarea de primer
    nivel escondida en un submenu. El gateo del enlace es cosmetico: la ruta
    verifica el rol por su cuenta (403), y eso lo cubre otro test.
    """

    _crear(app, "Titular", "clave-admin", "administration")
    _crear(app, "Lector", "clave-lector", "read", "demo")

    assert "Usuarios y acceso" in _menu_lateral(_sesion(app, "Titular", "clave-admin"))
    assert "Usuarios y acceso" not in _menu_lateral(_sesion(app, "Lector", "clave-lector"))


def test_the_entry_is_visible_before_the_first_user_exists(app):
    """Sin este caso no habria por donde crear el primer usuario desde la web."""

    assert "Usuarios y acceso" in _menu_lateral(app.test_client())
