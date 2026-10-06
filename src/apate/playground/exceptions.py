"""Excepciones del modo Playground (M5)."""

from __future__ import annotations

from ..core.exceptions import ApateError


class PlaygroundError(ApateError):
    """Base de las excepciones propias del modo Playground."""


class PlaygroundConfigError(PlaygroundError):
    """No hay una ruta valida configurada hacia un checkout local del
    repositorio Cyber Deception Playground (ver PlaygroundConfig)."""


class PlaygroundCommandError(PlaygroundError):
    """El comando docker compose invocado sobre el checkout configurado
    termino con un codigo de salida distinto de cero."""
