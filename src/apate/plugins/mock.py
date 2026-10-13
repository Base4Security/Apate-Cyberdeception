"""Plugin de referencia puramente simulado - roadmap M2.

Implementa DeceptionPlugin sin desplegar nada real: genera eventos
sinteticos de escaneo (deploy()) y de acceso (simulate_access()) para
poder validar el motor de reglas (M3), la telemetria (M4) y el modo
Playground (M5) sin depender de DOLOS-T ni de BUDA, que hoy no emiten
eventos estructurados (interaction/ttp_observed) pese a exponer
endpoints HTTP propios (ver M8 del roadmap).
"""

from __future__ import annotations

from typing import Optional

from ..i18n import lazy_gettext
from .base import DeceptionPlugin, EventType, PluginLifecycleState
from .registry import PluginDescription


class MockHoneypotPlugin(DeceptionPlugin):
    """Honeypot simulado: no abre puertos ni levanta infraestructura
    real, solo emite eventos sinteticos plausibles."""

    plugin_description = PluginDescription(
        kind="mock",
        display_name=lazy_gettext("Honeypot simulado (mock)"),
        description=lazy_gettext(
            "Plugin de referencia sin infraestructura real: emite eventos sinteticos de "
            "escaneo y acceso para poder ejercitar el resto del sistema (reglas, telemetria, "
            "Playground) sin depender de capacidades externas."
        ),
        surface="Red (simulada)",
    )

    # 203.0.113.0/24 es TEST-NET-3 (RFC 5737): rango reservado para
    # documentacion y ejemplos, nunca enrutable en produccion.
    _DEFAULT_SOURCE_IP = "203.0.113.10"

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "scan",
                "source_ip": self.config.get("source_ip", self._DEFAULT_SOURCE_IP),
                "detail": "Escaneo de puertos simulado contra el honeypot mock.",
            },
            resource_id=f"mock:{self.plugin_id}",
        )
        self.state = PluginLifecycleState.DEPLOYED

    def simulate_access(self, *, ttp_id: str = "T1078", source_ip: Optional[str] = None) -> None:
        """Dispara manualmente un acceso simulado al honeypot (uso
        pensado para tests, demos, o para que el motor de reglas de
        M3 lo ejercite). No forma parte del contrato de
        DeceptionPlugin: es especifico del mock, ya que un plugin
        real dispara esto por trafico real, no por una llamada
        explicita."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="simulate_access")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "access",
                "source_ip": source_ip or self.config.get("source_ip", self._DEFAULT_SOURCE_IP),
                "detail": "Acceso simulado al honeypot mock.",
            },
            resource_id=f"mock:{self.plugin_id}",
        )
        self._publish(
            EventType.TTP_OBSERVED,
            {
                "ttp_id": ttp_id,
                "detail": "TTP observada durante el acceso simulado al honeypot mock.",
            },
            resource_id=f"mock:{self.plugin_id}",
        )

    def rotate(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "rotate",
                "detail": "Honeypot mock rotado: nueva identidad simulada.",
            },
            resource_id=f"mock:{self.plugin_id}",
        )
        # rotate() no cambia el estado del ciclo de vida: sigue DEPLOYED.

    def retire(self) -> None:
        """Retira el honeypot simulado. Los "procedimientos de retirada
        verificables" que pide la seccion 8 del documento de diseno
        (M9) no aplican aca en el sentido literal (no hay nada externo
        que confirmar, a diferencia de HoneytokenPlugin.retire() en
        M7, que si borra archivos reales y verifica cada borrado):
        este plugin nunca administro un recurso real -- ni contenedor,
        ni archivo, ni conexion -- solo un flag de estado en memoria y
        eventos sinteticos. Cambiar `self.state` a RETIRED es en si
        mismo la totalidad de lo que hay para "verificar", y ese
        cambio ya es sincronico e inmediato."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "retire",
                "detail": "Honeypot mock retirado.",
            },
            resource_id=f"mock:{self.plugin_id}",
        )
        self.state = PluginLifecycleState.RETIRED
