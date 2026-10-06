"""Capacidad Playground explícita; solo ejecutable con descriptor aprobado."""

from ..i18n import lazy_gettext
from .base import DeceptionPlugin
from .registry import PluginDescription


class PlaygroundPlugin(DeceptionPlugin):
    plugin_description = PluginDescription(kind="playground",
        display_name=lazy_gettext("Entorno Playground"),
        description=lazy_gettext("Entorno de laboratorio con imágenes y configuración aprobadas por operación."),
        surface="Laboratorio")

    def deploy(self):
        from ..ledger.repository import LedgerError
        raise LedgerError("execution_service_required")

    def rotate(self):
        self.deploy()

    def retire(self):
        self.deploy()
