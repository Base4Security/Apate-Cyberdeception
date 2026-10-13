"""Excepciones de telemetria (M4) - puente de telemetria externo
configurable (ver apate.telemetry.external_bridge)."""

from __future__ import annotations

from ..core.exceptions import ApateError


class ExternalTelemetryError(ApateError):
    """Fallo al consultar o traducir una fuente de telemetria externa
    (`ExternalTelemetrySource`, `apate.core.models`) -- ej. el
    Elasticsearch configurado no responde. Envuelve la excepcion real
    del cliente HTTP compartido (`apate.playground.elastic.
    fetch_recent_hits()`, que sigue lanzando su propio
    `PlaygroundCommandError` por compatibilidad con el modo Playground
    -- ver docstring de `apate.telemetry.external_bridge`) para que
    quien use el puente de telemetria configurable no tenga que conocer
    ni importar excepciones de `apate.playground`."""
