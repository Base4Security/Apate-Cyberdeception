"""Correlación HTTP con registros estructurados que no exponen datos operativos."""

from __future__ import annotations

import json
import secrets
from time import perf_counter

from flask import g, request


def register_observability(app) -> None:
    """Asigna un ID propio incluso a peticiones rechazadas por las guardas."""

    @app.before_request
    def begin_request():
        g.apate_request_id = secrets.token_hex(16)
        g.apate_request_started = perf_counter()

    @app.after_request
    def finish_request(response):
        identifier = getattr(g, "apate_request_id", None)
        if identifier is None:
            return response
        response.headers["X-Request-ID"] = identifier
        if app.config.get("APATE_STRUCTURED_ACCESS_LOG", False):
            event = {
                "event": "apate.http.request",
                "request_id": identifier,
                "method": request.method,
                "endpoint": request.endpoint or "unmatched",
                "status": response.status_code,
                "duration_ms": round((perf_counter() - g.apate_request_started) * 1000, 3),
            }
            app.logger.info(json.dumps(event, sort_keys=True, separators=(",", ":")))
        return response
