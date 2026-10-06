"""El contrato opcional de inicio de sesión por redirección.

Hasta la formalización, `apate.web` llamaba a `authorization_url()` y a
`complete_authorization()` por duck typing: no existían declarados en ninguna
clase base, así que la única forma de saber qué tenía que implementar un
proveedor de directorio corporativo era leer `create_app()`. Estos tests fijan
las tres cosas que la formalización tiene que garantizar: que el contrato
distinga a un proveedor del otro, que la aplicación decida en un solo lugar, y
que un proveedor mal declarado falle **al construirse** y no a mitad del login.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from apate.identity import (
    IdentityProviderRegistry,
    LocalIdentityProvider,
    OIDCIdentityProvider,
    RedirectIdentityProvider,
    supports_redirect_login,
)
from apate.identity.models import Identity


# -- El contrato distingue a los dos proveedores de fábrica -----------------


def test_el_proveedor_oidc_declara_el_contrato_explicitamente():
    """No alcanza con satisfacerlo estructuralmente: la implementación de
    referencia lo hereda para que la intención quede escrita en el código."""

    assert issubclass(OIDCIdentityProvider, RedirectIdentityProvider)
    assert RedirectIdentityProvider in OIDCIdentityProvider.__mro__


def test_el_proveedor_local_no_satisface_el_contrato(tmp_path):
    provider = LocalIdentityProvider(tmp_path / "identities.json")

    assert not isinstance(provider, RedirectIdentityProvider)
    assert not supports_redirect_login(provider)


def test_un_proveedor_ajeno_lo_satisface_sin_heredarlo():
    """El `Protocol` es estructural a propósito: un proveedor de terceros no
    tiene por qué heredar nada de APATE para ofrecer este camino."""

    class ProveedorDeDirectorio:
        authentication_mode = "redirect"

        def authorization_url(self, redirect_uri: str, state: str) -> str:
            return f"https://idp.example/auth?state={state}"

        def complete_authorization(self, code: str, redirect_uri: str) -> Identity | None:
            return None

    provider = ProveedorDeDirectorio()

    assert isinstance(provider, RedirectIdentityProvider)
    assert supports_redirect_login(provider)


# -- `supports_redirect_login()` exige las dos condiciones ------------------


def test_implementar_los_metodos_no_alcanza_si_el_modo_dice_credenciales():
    """El modo declarado dice que el proveedor *quiere* ese camino y el
    contrato dice que *puede*. Quien implementa los métodos pero declara
    `credentials` está pidiendo que no se ofrezca el botón, y se respeta."""

    class ProveedorQueNoLoOfrece:
        authentication_mode = "credentials"

        def authorization_url(self, redirect_uri: str, state: str) -> str:  # pragma: no cover
            raise AssertionError("no debería llamarse")

        def complete_authorization(self, code: str, redirect_uri: str):  # pragma: no cover
            raise AssertionError("no debería llamarse")

    provider = ProveedorQueNoLoOfrece()

    assert isinstance(provider, RedirectIdentityProvider)
    assert not supports_redirect_login(provider)


def test_declarar_el_modo_no_alcanza_sin_los_metodos():
    class ProveedorIncompleto:
        authentication_mode = "redirect"

    assert not supports_redirect_login(ProveedorIncompleto())


# -- Un proveedor mal declarado falla al construirse ------------------------


def test_el_registro_rechaza_un_proveedor_que_declara_redireccion_sin_implementarla(monkeypatch, tmp_path):
    """Sin esta verificación la aplicación arranca igual y revienta con un
    `AttributeError` recién cuando alguien hace clic en "iniciar con el
    proveedor corporativo" -- el peor momento para descubrir el error."""

    class ProveedorMalDeclarado:
        authentication_mode = "redirect"

        def __init__(self, path: Path) -> None:
            self._path = path

        def get(self, identity_id: str):  # pragma: no cover - no se llega
            return None

    monkeypatch.setattr(
        "apate.identity.registry._BUILTIN_PROVIDERS",
        {"mal-declarado": ProveedorMalDeclarado},
    )

    with pytest.raises(ValueError) as error:
        IdentityProviderRegistry.create("mal-declarado", tmp_path / "identities.json")

    assert "authorization_url" in str(error.value)
    assert "mal-declarado" in str(error.value)


def test_el_registro_construye_normalmente_un_proveedor_coherente(tmp_path):
    provider = IdentityProviderRegistry.create("local", tmp_path / "identities.json")

    assert isinstance(provider, LocalIdentityProvider)
    assert not supports_redirect_login(provider)


# -- La aplicación decide en un solo lugar ----------------------------------


def test_las_rutas_de_redireccion_responden_404_con_el_proveedor_local(client):
    """Las rutas se registran siempre; lo que decide si existen para esta
    instalación es el contrato, no el nombre del proveedor."""

    assert client.get("/login/oidc/start").status_code == 404
    assert client.get("/login/oidc/callback?code=x&state=y").status_code == 404


def test_la_pantalla_de_login_no_ofrece_el_camino_corporativo_sin_contrato(client, app):
    from apate.identity import LocalIdentityProvider as _Local

    assert isinstance(app.config["IDENTITY_PROVIDER"], _Local)
    cuerpo = client.get("/login").get_data(as_text=True)

    assert "/login/oidc/start" not in cuerpo
