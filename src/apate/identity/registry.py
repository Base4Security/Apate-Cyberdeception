"""Descubrimiento de proveedores de identidad mediante entry points."""

from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points
from pathlib import Path

from ..i18n import gettext as _
from .providers import IdentityProvider, LocalIdentityProvider, RedirectIdentityProvider
from .oidc import OIDCIdentityProvider

_ENTRY_POINT_GROUP = "apate.identity_providers"

# El proveedor de fabrica se declara igual que uno de terceros en
# pyproject.toml (mismo criterio que PluginRegistry desde la Fase 5), pero
# ademas se resuelve sin pasar por el descubrimiento. La diferencia con los
# plugins importa: si un plugin no aparece en el registro, el catalogo muestra
# una capacidad menos y la app sigue andando; si el proveedor de identidad no
# aparece, `create_app()` no puede construirse y **la aplicacion entera deja de
# arrancar**. Eso pasa con solo hacer `git pull` sin reinstalar el paquete
# --`entry_points()` lee la metadata instalada, no el pyproject del checkout--
# y el error resultante no sugiere en ningun lado que haya que reinstalar.
# Encontrado al verificar la Fase 02, con la app real sin poder levantar.
#
# El fallback no debilita el punto de extension: el descubrimiento se consulta
# primero, asi que un proveedor externo declarado por entry point sigue
# teniendo prioridad, incluso bajo el mismo nombre.
_BUILTIN_PROVIDERS: dict[str, type[IdentityProvider]] = {
    "local": LocalIdentityProvider,
    "oidc": OIDCIdentityProvider,
}


def _discover() -> dict[str, EntryPoint]:
    """Devuelve proveedores instalados sin cachear, igual que PluginRegistry."""

    return {entry_point.name: entry_point for entry_point in entry_points(group=_ENTRY_POINT_GROUP)}


class IdentityProviderRegistry:
    """Fachada de descubrimiento para proveedores locales o externos."""

    @staticmethod
    def list_kinds() -> list[str]:
        """Proveedores disponibles: los instalados mas los de fabrica."""

        return sorted(set(_discover()) | set(_BUILTIN_PROVIDERS))

    @staticmethod
    def get(kind: str) -> type[IdentityProvider]:
        entry_point = _discover().get(kind)
        if entry_point is not None:
            return entry_point.load()
        builtin = _BUILTIN_PROVIDERS.get(kind)
        if builtin is not None:
            return builtin
        raise ValueError(
            _(
                "'%(kind)s' no es un proveedor de identidad registrado "
                "(disponibles: %(kinds)s).",
                kind=kind,
                kinds=IdentityProviderRegistry.list_kinds(),
            )
        )

    @staticmethod
    def create(kind: str, store_path: Path) -> IdentityProvider:
        """Construye el proveedor con la ruta de su almacen local.

        Es una ruta de **archivo**, no de directorio: `create_app()` pasa
        `<APATE_DATA_DIR>/identities`. El docstring decia "directorio" y el
        parametro se llamaba `data_dir`, contradiciendo lo que la app pasa de
        verdad -- una ambiguedad barata de arreglar ahora y cara despues, en
        la API publica justamente del punto de extension: quien implemente un
        proveedor de terceros la lee para saber que recibe.

        Un proveedor cuya identidad vive fuera de APATE (LDAP, SSO) puede
        ignorar la ruta, pero la firma comun evita que la app conozca clases
        concretas.

        **Verifica ademas que el modo declarado y el contrato implementado
        coincidan**, y falla aca si no. Un proveedor que declara
        `authentication_mode = "redirect"` sin implementar
        `RedirectIdentityProvider` arranca igual y recien revienta cuando
        alguien hace clic en "iniciar con el proveedor corporativo": un
        `AttributeError` a mitad del flujo de login, que es el peor momento
        posible para descubrir un error de integracion. Mismo criterio que
        `PlaygroundConfig.from_path()`: fallar antes, con un mensaje que dice
        que falta.
        """

        provider = IdentityProviderRegistry.get(kind)(Path(store_path))
        if getattr(provider, "authentication_mode", "credentials") == "redirect" and not isinstance(
            provider, RedirectIdentityProvider
        ):
            raise ValueError(
                _(
                    "El proveedor de identidad '%(kind)s' declara authentication_mode='redirect' "
                    "pero no implementa el contrato de inicio por redirección: faltan "
                    "authorization_url() y/o complete_authorization().",
                    kind=kind,
                )
            )
        return provider
