"""Adaptadores de salida manual para Splunk HEC y OTLP/HTTP JSON."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

import requests

from .models import TelemetryRecord


def _https_endpoint(url: str, suffix: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("El destino de exportación debe ser HTTPS sin credenciales en la URL.")
    if not parsed.path.endswith(suffix):
        raise ValueError(f"El destino debe terminar en {suffix}.")
    return url


def _post(url: str, body, headers: dict[str, str], *, http=requests):
    response = http.post(url, json=body, headers=headers, timeout=8.0, allow_redirects=False)
    if 300 <= response.status_code < 400:
        raise ValueError("El destino intentó redirigir la exportación.")
    response.raise_for_status()
    return response


def export_to_splunk_hec(records: list[TelemetryRecord], url: str, token: str, *, http=requests) -> int:
    """Entrega eventos normalizados al endpoint JSON HEC, por lotes limitados."""
    _https_endpoint(url, "/services/collector/event")
    if not token.strip():
        raise ValueError("Splunk HEC requiere un token.")
    for start in range(0, len(records), 100):
        batch = records[start:start + 100]
        # Splunk HEC admite objetos JSON concatenados, uno por evento.
        body = "".join(
            json.dumps({
                "time": record.timestamp.timestamp(), "source": "apate",
                "sourcetype": "apate:telemetry", "event": record.to_dict(),
            }, ensure_ascii=False) for record in batch
        )
        response = http.post(
            url, data=body.encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Splunk {token}"},
            timeout=8.0, allow_redirects=False,
        )
        if 300 <= response.status_code < 400:
            raise ValueError("Splunk HEC intentó redirigir la exportación.")
        response.raise_for_status()
        if response.json().get("code") != 0:
            raise ValueError("Splunk HEC rechazó el lote.")
    return len(records)


def build_otlp_logs(records: list[TelemetryRecord]) -> dict:
    """Codifica el subconjunto JSON Protobuf de ExportLogsServiceRequest."""
    log_records = []
    for record in records:
        attributes = {
            "apate.operation.id": record.operation_id,
            "apate.telemetry.id": record.id,
            "apate.plugin.id": record.plugin_id,
            "apate.source_event.id": record.source_event_id,
            "apate.event.type": record.event_type.value,
        }
        if record.ttp_id:
            attributes["apate.ttp.id"] = record.ttp_id
        log_records.append({
            "timeUnixNano": str(int(record.timestamp.timestamp() * 1_000_000_000)),
            "severityNumber": 9, "severityText": "INFO",
            "body": {"stringValue": json.dumps(record.to_dict(), ensure_ascii=False)},
            "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in attributes.items()],
        })
    return {"resourceLogs": [{
        "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "apate"}}]},
        "scopeLogs": [{"scope": {"name": "apate.telemetry"}, "logRecords": log_records}],
    }]}


def export_to_otlp_http(records: list[TelemetryRecord], url: str, *, bearer_token: str = "", http=requests) -> int:
    """Entrega logs OTLP/HTTP JSON; la exportación nunca decide despliegues."""
    _https_endpoint(url, "/v1/logs")
    headers = {"Content-Type": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    for start in range(0, len(records), 100):
        response = _post(url, build_otlp_logs(records[start:start + 100]), headers, http=http)
        try:
            result = response.json()
        except ValueError:
            result = {}
        if result.get("partialSuccess", {}).get("rejectedLogRecords", 0):
            raise ValueError("OTLP rechazó parte del lote.")
    return len(records)
