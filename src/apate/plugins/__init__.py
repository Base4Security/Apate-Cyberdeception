"""Capa de integracion por plugins (M2) - ver documento de diseno, seccion 4.3."""

from .base import DeceptionPlugin, EventBus, EventType, PluginEvent, PluginLifecycleState
from .exceptions import PluginStateError
from .mock import MockHoneypotPlugin

__all__ = [
    "DeceptionPlugin",
    "EventBus",
    "EventType",
    "MockHoneypotPlugin",
    "PluginEvent",
    "PluginLifecycleState",
    "PluginStateError",
]
