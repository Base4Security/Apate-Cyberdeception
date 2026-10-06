"""Excepciones del Nucleo de Operacion (M1)."""

from __future__ import annotations


class ApateError(Exception):
    """Base de todas las excepciones propias de APATE."""


class InvalidTransitionError(ApateError):
    """Se intento una transicion de estado no permitida sobre una
    Operacion. Mantener esto como excepcion explicita es lo que evita
    que el motor de reglas (M3) deje una operacion en un estado
    inconsistente."""


class OperationNotFoundError(ApateError, KeyError):
    """No existe una operacion con el id solicitado en el repositorio."""
