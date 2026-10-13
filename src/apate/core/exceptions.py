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


class InvalidClosureCriteriaError(ApateError):
    """ClosureCriteria.trigger_conditions (M12f) recibio una Condition con
    forma invalida: closure_due=True (o event_type=None) no tiene sentido
    ahi, esa semantica de cierre por vencimiento ya la cubre
    end_date/Operation.is_past_due() por un camino completamente aparte."""


class InvalidPluginBindingError(ApateError):
    """PluginBinding.leads_to_plugin_id (breadcrumb -> recurso, referencia
    declarada CounterCraft) apunta a si mismo -- invariante local, no
    necesita visibilidad de la Operacion que contiene el binding (a
    diferencia de "el destino no existe"/"hay un ciclo", que si la
    necesitan y por eso NO se validan aca, ver docstring de
    PluginBinding)."""
