"""Plugin de referencia puramente simulado.

Genera eventos sintéticos para ejecutar el motor y la telemetría sin
desplegar señuelos ni conectarse a infraestructura externa.
"""

from __future__ import annotations

from typing import Optional

from .base import DeceptionPlugin, EventType, PluginLifecycleState


class MockHoneypotPlugin(DeceptionPlugin):
    """Honeypot simulado: no abre puertos ni levanta infraestructura
    real, solo emite eventos sinteticos plausibles."""

    # 203.0.113.0/24 es TEST-NET-3 (RFC 5737): rango reservado para
    # documentacion y ejemplos, nunca enrutable en produccion.
    _DEFAULT_SOURCE_IP = "203.0.113.10"

    def _detail(self, spanish: str, english: str) -> str:
        """El idioma de la demo afecta sólo la descripción del evento."""

        return english if self.config.get("language") == "en" else spanish

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "scan",
                "source_ip": self.config.get("source_ip", self._DEFAULT_SOURCE_IP),
                "detail": self._detail(
                    "Escaneo de puertos simulado contra el honeypot mock.",
                    "Simulated port scan against the mock honeypot.",
                ),
            },
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
                "detail": self._detail(
                    "Acceso simulado al honeypot mock.",
                    "Simulated access to the mock honeypot.",
                ),
            },
        )
        self._publish(
            EventType.TTP_OBSERVED,
            {
                "ttp_id": ttp_id,
                "detail": self._detail(
                    "TTP observada durante el acceso simulado al honeypot mock.",
                    "TTP observed during simulated access to the mock honeypot.",
                ),
            },
        )

    def rotate(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "rotate",
                "detail": self._detail(
                    "Honeypot mock rotado: nueva identidad simulada.",
                    "Mock honeypot rotated: new simulated identity.",
                ),
            },
        )
        # rotate() no cambia el estado del ciclo de vida: sigue DEPLOYED.

    def retire(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "retire",
                "detail": self._detail(
                    "Honeypot mock retirado.",
                    "Mock honeypot retired.",
                ),
            },
        )
        self.state = PluginLifecycleState.RETIRED
