"""Identidad local y descubrimiento de proveedores intercambiables."""

import json
from importlib.metadata import EntryPoint

import pytest

from apate.identity import Identity, IdentityProvider, IdentityProviderRegistry, LocalIdentityProvider


def test_local_provider_hashes_password_and_never_returns_it(tmp_path):
    provider = LocalIdentityProvider(tmp_path / "identities.json")
    identity = provider.create("  Ana Operadora  ", "secreto-no-visible")

    stored = (tmp_path / "identities.json").read_text(encoding="utf-8")

    assert identity.display_name == "Ana Operadora"
    assert "secreto-no-visible" not in stored
    assert "password_hash" in stored
    assert provider.list() == [identity]
    assert not hasattr(provider.list()[0], "password_hash")


def test_local_provider_authenticates_active_users_and_rejects_invalid_credentials(tmp_path):
    provider = LocalIdentityProvider(tmp_path / "identities.json")
    identity = provider.create("Ana", "clave-correcta")

    assert provider.authenticate("ana", "clave-correcta") == identity
    assert provider.authenticate("Ana", "otra-clave") is None
    assert provider.authenticate("No existe", "clave-correcta") is None


def test_deactivation_invalidates_identity_but_keeps_the_store_protected(tmp_path):
    provider = LocalIdentityProvider(tmp_path / "identities.json")
    identity = provider.create("Ana", "clave")
    # El primer usuario es administrador, y desde la guarda del ultimo admin no
    # se lo puede desactivar. Hace falta un segundo para poder dar de baja a
    # Ana sin dejar la instancia sin nadie que administre.
    provider.create("Suplente", "otra", role="administration")

    deactivated = provider.deactivate(identity.id)

    assert not deactivated.active
    assert provider.get(identity.id) is None
    assert provider.authenticate("Ana", "clave") is None
    assert provider.has_identities()


def test_duplicate_display_names_are_rejected_without_comparing_case(tmp_path):
    provider = LocalIdentityProvider(tmp_path / "identities.json")
    provider.create("Ana", "clave")

    with pytest.raises(ValueError, match="Ya existe"):
        provider.create(" ana ", "otra-clave")


class _ThirdPartyProvider(IdentityProvider):
    def __init__(self, _data_dir):
        pass

    def authenticate(self, display_name: str, password: str) -> Identity | None:
        return None

    def get(self, identity_id: str) -> Identity | None:
        return None


def test_registry_discovers_a_third_party_provider_via_entry_point(monkeypatch, tmp_path):
    entry_point = EntryPoint(
        name="empresa", value=f"{__name__}:_ThirdPartyProvider", group="apate.identity_providers"
    )
    monkeypatch.setattr(
        "apate.identity.registry.entry_points", lambda group: [entry_point] if group == entry_point.group else []
    )

    assert IdentityProviderRegistry.get("empresa") is _ThirdPartyProvider
    assert isinstance(IdentityProviderRegistry.create("empresa", tmp_path), _ThirdPartyProvider)


def test_legacy_operator_action_document_remains_readable(tmp_path):
    """El nombre histórico de texto libre sigue teniendo forma compatible."""

    from apate.audit import JSONFileOperatorActionRepository

    action_path = tmp_path / "operator_actions" / "op-legacy.json"
    action_path.parent.mkdir()
    action_path.write_text(
        json.dumps(
            [
                {
                    "id": "old-1",
                    "operation_id": "op-legacy",
                    "action": "deploy",
                    "operator": "Nombre libre antiguo",
                    "outcome": "success",
                    "detail": "Acción histórica.",
                    "plugin_id": None,
                    "target": None,
                    "timestamp": "2025-01-01T00:00:00+00:00",
                }
            ]
        ),
        encoding="utf-8",
    )

    actions = JSONFileOperatorActionRepository(action_path.parent).list_for_operation("op-legacy")

    assert actions[0].operator == "Nombre libre antiguo"


# -- Robustez del registro ante un paquete sin reinstalar -------------------


def test_builtin_provider_resolves_without_entry_points(monkeypatch):
    """La app entera deja de arrancar si el proveedor de identidad no se
    resuelve, y `entry_points()` lee la metadata *instalada*: un `git pull`
    sin reinstalar el paquete basta para que el entry point no aparezca.

    Encontrado verificando la Fase 02, con `create_app()` reventando en un
    entorno real. Distinto de los plugins, donde un kind ausente solo quita
    una tarjeta del catálogo: acá no hay aplicación.
    """

    from apate.identity import registry
    from apate.identity.providers import LocalIdentityProvider

    monkeypatch.setattr(registry, "_discover", dict)

    assert registry.IdentityProviderRegistry.get("local") is LocalIdentityProvider
    assert "local" in registry.IdentityProviderRegistry.list_kinds()


def test_entry_point_wins_over_builtin(monkeypatch):
    """El fallback no debilita el punto de extensión: un proveedor declarado
    por entry point tiene prioridad, incluso bajo el mismo nombre."""

    from apate.identity import registry

    class _ProveedorDeTerceros:
        pass

    class _FakeEntryPoint:
        def load(self):
            return _ProveedorDeTerceros

    monkeypatch.setattr(registry, "_discover", lambda: {"local": _FakeEntryPoint()})

    assert registry.IdentityProviderRegistry.get("local") is _ProveedorDeTerceros


def test_the_last_active_administrator_cannot_be_deactivated(tmp_path):
    """Sin esta guarda la instancia queda inaccesible y sin vuelta desde la app.

    `has_identities()` cuenta tambien los registros desactivados -- a proposito,
    para que la aplicacion no vuelva sola a modo abierto. Consecuencia: con cero
    administradores activos la autenticacion sigue exigida y no entra nadie; la
    unica salida es `flask create-user` desde el servidor.
    """

    provider = LocalIdentityProvider(tmp_path / "identities.json")
    solo_admin = provider.create("Ana", "clave", role="administration")
    provider.create("Lector", "otra", role="read", team_id="demo")

    with pytest.raises(ValueError, match="ultimo administrador|último administrador"):
        provider.deactivate(solo_admin.id)

    assert provider.get(solo_admin.id) is not None
    assert provider.authenticate("Ana", "clave") is not None


def test_a_second_administrator_makes_the_first_deactivatable(tmp_path):
    """La guarda protege al ultimo, no impide rotar administradores."""

    provider = LocalIdentityProvider(tmp_path / "identities.json")
    saliente = provider.create("Ana", "clave", role="administration")
    provider.create("Nuevo", "otra", role="administration")

    provider.deactivate(saliente.id)

    assert provider.get(saliente.id) is None
