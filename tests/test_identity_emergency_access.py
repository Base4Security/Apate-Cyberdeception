"""El acceso de emergencia de OIDC: opcional, con vencimiento y expulsable.

**Qué es y por qué está acotado.** Existe para no quedarse afuera si el IdP se
cae, que es una necesidad real. Pero es también una contraseña local que evita
el inicio de sesión corporativo, con su MFA y su revocación. Antes era
permanente, obligatoria, invisible en la pantalla de usuarios, sin equipo, con
`credential_version` fija en 0 —así que ninguna rotación expulsaba su sesión— y
sin dejar rastro al usarse.

Cada test de acá fija una de esas correcciones.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from werkzeug.security import generate_password_hash

from apate.identity.oidc import EMERGENCY_IDENTITY_ID, OIDCIdentityProvider

CLAVE = "clave-de-rescate"

BASE = {
    "APATE_OIDC_ISSUER": "https://idp.invalid",
    "APATE_OIDC_CLIENT_ID": "apate",
    "APATE_OIDC_CLIENT_SECRET": "secreto",
    "APATE_OIDC_AUTHORIZATION_ENDPOINT": "https://idp.invalid/auth",
    "APATE_OIDC_TOKEN_ENDPOINT": "https://idp.invalid/token",
    "APATE_OIDC_JWKS_URI": "https://idp.invalid/jwks",
}


def _entorno(monkeypatch, **extra):
    for clave, valor in {**BASE, **extra}.items():
        if valor is None:
            monkeypatch.delenv(clave, raising=False)
        else:
            monkeypatch.setenv(clave, valor)


def _dentro_de(dias: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=dias)).isoformat()


def _proveedor(tmp_path) -> OIDCIdentityProvider:
    return OIDCIdentityProvider(tmp_path / "identities.json")


# -- Opcional ----------------------------------------------------------


def test_sin_hash_no_hay_cuenta_de_emergencia(tmp_path, monkeypatch):
    """Antes era obligatorio: toda instalación con SSO estaba forzada a tener
    además una contraseña local que lo evita."""

    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=None,
             APATE_OIDC_EMERGENCY_EXPIRES_AT=None)

    proveedor = _proveedor(tmp_path)

    assert proveedor.emergency_enabled is False
    assert proveedor.authenticate("emergency", CLAVE) is None
    assert proveedor.get(EMERGENCY_IDENTITY_ID) is None


# -- Con vencimiento obligatorio ---------------------------------------


def test_un_hash_sin_vencimiento_no_deja_arrancar(tmp_path, monkeypatch):
    """Falla al construirse, no en silencio: una credencial que evita el SSO
    no puede ser válida para siempre."""

    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=None)

    with pytest.raises(ValueError, match="EXPIRES_AT"):
        _proveedor(tmp_path)


def test_un_vencimiento_ilegible_cuenta_como_ausente(tmp_path, monkeypatch):
    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT="el martes que viene")

    with pytest.raises(ValueError, match="EXPIRES_AT"):
        _proveedor(tmp_path)


def test_dentro_de_la_ventana_la_cuenta_funciona(tmp_path, monkeypatch):
    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(1))

    identidad = _proveedor(tmp_path).authenticate("emergency", CLAVE)

    assert identidad is not None
    assert identidad.id == EMERGENCY_IDENTITY_ID


def test_vencida_no_autentica_a_nadie(tmp_path, monkeypatch):
    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(-1))

    proveedor = _proveedor(tmp_path)

    assert proveedor.emergency_enabled is False
    assert proveedor.authenticate("emergency", CLAVE) is None


def test_una_sesion_abierta_se_corta_cuando_vence(tmp_path, monkeypatch):
    """El vencimiento se revalida en cada pedido, no solo al entrar: si solo
    se mirara en el login, una sesión abierta sobreviviría a la ventana."""

    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(1))
    proveedor = _proveedor(tmp_path)
    assert proveedor.get(EMERGENCY_IDENTITY_ID) is not None

    proveedor.emergency_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    assert proveedor.get(EMERGENCY_IDENTITY_ID) is None


def test_un_vencimiento_sin_zona_horaria_se_toma_como_utc(tmp_path, monkeypatch):
    # Equivocarse hacia UTC acorta la ventana en vez de alargarla.
    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT="2099-01-01T00:00:00")

    assert _proveedor(tmp_path).emergency_expires_at.tzinfo is not None


# -- Expulsable --------------------------------------------------------


def test_rotar_el_hash_expulsa_la_sesion_abierta(tmp_path, monkeypatch):
    """`credential_version` se deriva de la credencial, no de un contador.

    Antes quedaba fija en 0 y el mecanismo de expulsión —que sí funciona para
    las identidades locales— nunca alcanzaba a esta cuenta.
    """

    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(1))
    antes = _proveedor(tmp_path).authenticate("emergency", CLAVE).credential_version

    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash("otra-clave"),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(1))
    despues = _proveedor(tmp_path).authenticate("emergency", "otra-clave").credential_version

    assert antes != despues


def test_la_version_es_estable_mientras_la_credencial_no_cambie(tmp_path, monkeypatch):
    """Si cambiara sola, cada reinicio expulsaría a quien estuviera dentro."""

    hash_fijo = generate_password_hash(CLAVE)
    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=hash_fijo,
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(1))

    uno = _proveedor(tmp_path).get(EMERGENCY_IDENTITY_ID).credential_version
    otro = _proveedor(tmp_path).get(EMERGENCY_IDENTITY_ID).credential_version

    assert uno == otro


def test_una_clave_equivocada_sigue_sin_entrar(tmp_path, monkeypatch):
    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(1))

    assert _proveedor(tmp_path).authenticate("emergency", "no-es") is None


# -- Visible y auditada ------------------------------------------------


@pytest.mark.csrf
def test_la_interfaz_avisa_mientras_la_puerta_este_abierta(tmp_path, monkeypatch):
    """Una puerta que evita el SSO no puede ser invisible."""

    from apate.web import create_app

    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(1))
    monkeypatch.setenv("APATE_IDENTITY_PROVIDER", "oidc")
    app = create_app({
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "data",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
    })

    cuerpo = app.test_client().get("/login").get_data(as_text=True)

    assert "acceso de emergencia" in cuerpo.lower()


def test_el_uso_queda_en_la_auditoria(tmp_path, monkeypatch):
    from apate.web import create_app

    _entorno(monkeypatch, APATE_OIDC_EMERGENCY_PASSWORD_HASH=generate_password_hash(CLAVE),
             APATE_OIDC_EMERGENCY_EXPIRES_AT=_dentro_de(1))
    monkeypatch.setenv("APATE_IDENTITY_PROVIDER", "oidc")
    monkeypatch.setenv("APATE_OIDC_EMERGENCY_USERNAME", "rescate")
    app = create_app({
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "data",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
    })

    app.test_client().post("/login", data={"display_name": "rescate", "password": CLAVE})

    with app.app_context():
        acciones = list(app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation("identity-management"))

    assert any(accion.action == "emergency_login" for accion in acciones), acciones
