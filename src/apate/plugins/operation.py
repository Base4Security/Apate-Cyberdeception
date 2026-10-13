"""Construcción del registro efímero de plugins de una operación.

Playground y una acción manual HTTP necesitan el mismo registro para que el
motor de reglas pueda resolver las capacidades vinculadas sin depender de la
capa web. Este módulo conserva esa construcción en la capa de plugins.
"""

from __future__ import annotations

import logging
from typing import Mapping

from ..core.models import Operation
from .base import DeceptionPlugin, EventBus
from .registry import PluginRegistry


logger = logging.getLogger(__name__)


def build_operation_plugins(
    operation: Operation,
    bus: EventBus,
    *,
    supplied: Mapping[str, DeceptionPlugin] | None = None,
) -> dict[str, DeceptionPlugin]:
    """Construye el registro efímero de capacidades de una operación.

    ``supplied`` permite que una acción manual entregue su propia instancia:
    el motor y la acción operan entonces sobre el mismo objeto y comparten su
    estado local. Los bindings inválidos no impiden trabajar con los válidos;
    se omiten dejando una advertencia identificable.
    """

    plugins = dict(supplied or {})
    seen_binding_ids: set[str] = set()
    for binding in operation.plugins:
        if binding.plugin_id in seen_binding_ids:
            logger.warning(
                "Binding '%s' omitido del registro de operación: hay otro binding con el mismo plugin_id.",
                binding.plugin_id,
            )
            continue
        seen_binding_ids.add(binding.plugin_id)
        if binding.plugin_id in plugins:
            continue

        kind = PluginRegistry.resolve_binding_kind(binding)
        if kind is None:
            logger.warning(
                "Binding '%s' omitido del registro de operación: plugin_kind no registrado o no resoluble.",
                binding.plugin_id,
            )
            continue

        try:
            plugin = PluginRegistry.get(kind).from_binding(
                binding,
                operation_id=operation.id,
                bus=bus,
            )
        except Exception as exc:
            logger.warning(
                "Binding '%s' omitido del registro de operación: no se pudo instanciar (%s: %s).",
                binding.plugin_id,
                type(exc).__name__,
                exc,
            )
            continue

        _restore_verified_state(plugin)
        plugins[binding.plugin_id] = plugin
    return plugins


def _restore_verified_state(plugin: DeceptionPlugin) -> None:
    """Rehidrata estado solo si la implementación puede verificarlo."""

    restore = getattr(plugin, "restore_deployed_state", None)
    if not callable(restore):
        return
    try:
        restore()
    except Exception as exc:
        logger.warning(
            "No se pudo verificar el despliegue de '%s'; queda en CREATED (%s: %s).",
            plugin.plugin_id,
            type(exc).__name__,
            exc,
        )
