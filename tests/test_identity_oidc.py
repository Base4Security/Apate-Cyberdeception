"""Flujo de inicio de sesión corporativo (OIDC).

Estos tests levantan un proveedor de identidad **simulado**: generan un par de
claves RSA, firman un `id_token` como lo haría el IdP y sustituyen la llamada
al endpoint de token y al JWKS. Es lo que permite verificar el flujo entero
—ida, vuelta y los cuatro rechazos que lo hacen seguro— sin depender de un
Okta o un Azure AD real, que este entorno no tiene.

Lo que se prueba no es "que el código corra", sino que **rechace**: un `state`
que no coincide, una firma ajena, un token vencido y un sujeto que el IdP
autenticó pero que nadie aprovisionó en APATE. Un flujo OIDC que acepta
cualquiera de esos cuatro es peor que no tener inicio de sesión corporativo,
porque parece seguro.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from werkzeug.security import generate_password_hash

_EMISOR = "https://idp.prueba.test"
_CLIENTE = "apate-cliente"
_SUJETO = "usuario-123"
_CLAVE_RESCATE = "clave-de-rescate-larga"


def _pem(clave: rsa.RSAPrivateKey) -> bytes:
    return clave.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


@pytest.fixture
def idp():
    """Par de claves del IdP simulado, y un emisor de tokens firmados por él."""

    clave = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def emitir(**extra) -> str:
        claims = {
            "iss": _EMISOR,
            "aud": _CLIENTE,
            "sub": _SUJETO,
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
        }
        claims.update(extra)
        return jwt.encode(claims, _pem(clave), algorithm="RS256")

    return clave, emitir


@pytest.fixture
def app_oidc(tmp_path, monkeypatch, idp):
    clave, _ = idp
    for nombre, valor in {
        "APATE_IDENTITY_PROVIDER": "oidc",
        "APATE_OIDC_ISSUER": _EMISOR,
        "APATE_OIDC_CLIENT_ID": _CLIENTE,
        "APATE_OIDC_CLIENT_SECRET": "secreto",
        "APATE_OIDC_AUTHORIZATION_ENDPOINT": f"{_EMISOR}/auth",
        "APATE_OIDC_TOKEN_ENDPOINT": f"{_EMISOR}/token",
        "APATE_OIDC_JWKS_URI": f"{_EMISOR}/jwks",
        "APATE_OIDC_EMERGENCY_USERNAME": "rescate",
        "APATE_OIDC_EMERGENCY_PASSWORD_HASH": generate_password_hash(_CLAVE_RESCATE),
        # El vencimiento es obligatorio desde que el acceso de emergencia dejo
        # de ser permanente: ver el docstring de apate.identity.oidc y
        # tests/test_identity_emergency_access.py.
        "APATE_OIDC_EMERGENCY_EXPIRES_AT": "2099-01-01T00:00:00+00:00",
    }.items():
        monkeypatch.setenv(nombre, valor)

    from apate.web import create_app

    aplicacion = create_app({"APATE_DATA_DIR": tmp_path})
    aplicacion.config["IDENTITY_PROVIDER"].provision(
        subject=_SUJETO, display_name="Ana OIDC", role="operation", team_id="rojo"
    )
    return aplicacion


def _retorno(app_oidc, clave, id_token: str, *, state: str | None = None):
    """Recorre inicio y retorno del flujo, sustituyendo IdP y JWKS."""

    class _RespuestaDeToken:
        def raise_for_status(self):
            return None

        def json(self):
            return {"id_token": id_token}

    class _ClienteJWKS:
        def __init__(self, *args, **kwargs):
            pass

        def get_signing_key_from_jwt(self, token):
            class _Clave:
                key = clave.public_key()

            return _Clave()

    cliente = app_oidc.test_client()
    cliente.get("/login/oidc/start")
    with cliente.session_transaction() as sesion:
        esperado = sesion["oidc_state"]

    with patch("apate.identity.oidc.requests.post", return_value=_RespuestaDeToken()), patch(
        "apate.identity.oidc.jwt.PyJWKClient", _ClienteJWKS
    ):
        respuesta = cliente.get(
            f"/login/oidc/callback?code=abc&state={state if state is not None else esperado}",
            follow_redirects=False,
        )
    return cliente, respuesta


def test_redirect_provider_sends_the_user_to_the_identity_provider(app_oidc):
    cliente = app_oidc.test_client()

    respuesta = cliente.get("/login/oidc/start", follow_redirects=False)

    assert respuesta.status_code == 302
    assert _EMISOR in respuesta.headers["Location"]
    with cliente.session_transaction() as sesion:
        assert sesion["oidc_state"]


def test_valid_return_creates_the_session(app_oidc, idp):
    clave, emitir = idp

    cliente, respuesta = _retorno(app_oidc, clave, emitir())

    assert respuesta.status_code == 302
    assert cliente.get("/operations/").status_code == 200


def test_mismatched_state_is_rejected(app_oidc, idp):
    """Sin esto el retorno es falsificable: cualquiera puede provocar un inicio
    de sesión enviando a la víctima a la ruta de retorno con su propio código."""

    clave, emitir = idp

    _, respuesta = _retorno(app_oidc, clave, emitir(), state="no-es-el-de-la-sesion")

    assert respuesta.status_code == 400


def test_token_signed_by_another_key_is_rejected(app_oidc, idp):
    clave, _ = idp
    intrusa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ajeno = jwt.encode(
        {"iss": _EMISOR, "aud": _CLIENTE, "sub": _SUJETO, "exp": int(time.time()) + 300},
        _pem(intrusa),
        algorithm="RS256",
    )

    _, respuesta = _retorno(app_oidc, clave, ajeno)

    assert respuesta.status_code == 401


def test_expired_token_is_rejected(app_oidc, idp):
    clave, emitir = idp

    _, respuesta = _retorno(app_oidc, clave, emitir(exp=int(time.time()) - 10))

    assert respuesta.status_code == 401


def test_subject_the_idp_authenticated_but_apate_never_provisioned_is_rejected(app_oidc, idp):
    """Decisión de aprovisionamiento: la identidad tiene que existir antes en
    APATE. Que el IdP autentique a alguien no alcanza — si alcanzara, cualquier
    cuenta del directorio corporativo entraría, y con qué rol y qué equipo sería
    una decisión tomada por omisión."""

    clave, emitir = idp

    _, respuesta = _retorno(app_oidc, clave, emitir(sub="alguien-que-nadie-dio-de-alta"))

    assert respuesta.status_code == 403


def test_emergency_account_works_when_the_provider_is_unreachable(app_oidc):
    """Si el IdP se cae y no hay salida local, nadie entra ni para arreglarlo.
    El proveedor OIDC exige configurar esta cuenta —su constructor falla sin
    ella—, así que la salida de emergencia no puede olvidarse."""

    cliente = app_oidc.test_client()

    respuesta = cliente.post(
        "/login",
        data={"display_name": "rescate", "password": _CLAVE_RESCATE},
        follow_redirects=False,
    )

    assert respuesta.status_code == 302
    assert cliente.get("/operations/").status_code == 200


def test_emergency_account_rejects_a_wrong_password(app_oidc):
    cliente = app_oidc.test_client()

    respuesta = cliente.post(
        "/login",
        data={"display_name": "rescate", "password": "no-es-la-clave"},
        follow_redirects=False,
    )

    assert respuesta.status_code != 302
    assert cliente.get("/operations/", follow_redirects=False).status_code == 302


def test_oidc_provisioning_cli_is_non_interactive(app_oidc):
    result = app_oidc.test_cli_runner().invoke(args=["provision-oidc-user", "sujeto-nuevo", "Beto OIDC", "--role", "read", "--team", "azul"])
    assert result.exit_code == 0, result.output
    assert "sujeto-nuevo" in result.output
    assert app_oidc.config["IDENTITY_PROVIDER"].get("sujeto-nuevo").team_id == "azul"
