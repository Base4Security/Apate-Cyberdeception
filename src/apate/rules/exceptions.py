"""Excepciones del motor de decision (M3)."""

from __future__ import annotations

from apate.core.exceptions import ApateError


class RuleError(ApateError):
    """Base de las excepciones propias del motor de reglas."""


class RuleDefinitionError(RuleError):
    """Una regla (cargada desde YAML o construida a mano) tiene una
    forma invalida: falta un campo obligatorio, mezcla un tipo de
    condicion con otro, o define una transicion hacia un estado no
    soportado como destino de una accion."""


class UnknownPluginError(RuleError):
    """Una accion de una regla referencia un plugin_id que no esta
    registrado en el motor para la operacion actual."""
