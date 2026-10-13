"""Capa de integracion por plugins (M2) - ver documento de diseno, seccion 4.3.

`DolosTPlugin`/`BudaPlugin` (M8c) importan los paquetes reales `DOLOST`/
`BUDA` al nivel de modulo -- dependencias editables obligatorias desde
M8c (ver pyproject.toml), no opcionales: importar `apate.plugins`
requiere tenerlas instaladas."""

from .base import DeceptionPlugin, EventBus, EventType, PluginEvent, PluginLifecycleState, sanitize_payload_text
from .buda_plugin import BudaPlugin
from .canarytoken_plugin import CanarytokenPlugin
from .dolost_plugin import DolosTPlugin
from .exceptions import CanarytokenAPIError, HoneytokenFileError, OpenCanaryError, PluginConfigError, PluginStateError
from .honeytoken import HoneytokenPlugin
from .mock import MockHoneypotPlugin
from .opencanary_plugin import OpenCanaryPlugin
from .registry import PluginDescription, PluginRegistry

__all__ = [
    "BudaPlugin",
    "CanarytokenAPIError",
    "CanarytokenPlugin",
    "DeceptionPlugin",
    "DolosTPlugin",
    "EventBus",
    "EventType",
    "HoneytokenFileError",
    "HoneytokenPlugin",
    "MockHoneypotPlugin",
    "OpenCanaryError",
    "OpenCanaryPlugin",
    "PluginConfigError",
    "PluginDescription",
    "PluginEvent",
    "PluginLifecycleState",
    "PluginRegistry",
    "PluginStateError",
    "sanitize_payload_text",
]
