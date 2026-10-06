"""Excepciones de la capa de integracion por plugins (M2)."""

from __future__ import annotations

from apate.core.exceptions import ApateError


class PluginStateError(ApateError):
    """Se invoco deploy()/rotate()/retire() en un estado del ciclo de
    vida del plugin que no lo permite (por ejemplo, desplegar dos
    veces, o retirar sin haber desplegado antes)."""
