"""Identidad de operadores y proveedores autenticables de APATE."""

from .models import Identity, IdentityRole
from .providers import (
    IdentityProvider,
    LocalIdentityProvider,
    RedirectIdentityProvider,
    supports_redirect_login,
)
from .oidc import OIDCIdentityProvider
from .registry import IdentityProviderRegistry

__all__ = [
    "Identity",
    "IdentityProvider",
    "IdentityProviderRegistry",
    "IdentityRole",
    "LocalIdentityProvider",
    "OIDCIdentityProvider",
    "RedirectIdentityProvider",
    "supports_redirect_login",
]
