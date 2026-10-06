"""Las alertas priorizan efectos inciertos y declaran cobertura parcial."""

from datetime import datetime, timedelta, timezone

import pytest

from apate.ops import benchmark_local, evaluate_alerts


def _status():
    return {"unknown_receipts": 0, "outbox": {
        "states": {name: 0 for name in ("pending", "sending", "retry", "unknown", "awaiting_ack", "delivered", "dead")},
        "oldest_undelivered_seconds": 0}}


def test_alertas_separan_estado_sano_de_cobertura_no_observada():
    result = evaluate_alerts(_status())
    assert result["state"] == "ok"
    assert result["coverage"]["connectors"] is False


def test_alertas_escalan_efecto_incierto_carta_muerta_y_conector_vencido():
    now = datetime(2026, 10, 1, tzinfo=timezone.utc)
    status = _status()
    status["unknown_receipts"] = 1
    status["outbox"]["states"]["dead"] = 1
    status["outbox"]["oldest_undelivered_seconds"] = 4000
    result = evaluate_alerts(status, connectors=[{
        "status": "degraded", "last_success_at": (now - timedelta(minutes=20)).isoformat(),
    }], now=now)
    assert result["state"] == "critical"
    assert {item["code"] for item in result["alerts"]} == {
        "external_effect_unknown", "outbox_dead_letters", "outbox_delivery_stale",
        "connector_degraded", "connector_observation_stale",
    }
    assert result["coverage"]["connectors"] is True


def test_estado_malformado_no_declara_salud():
    status = _status()
    status["outbox"]["states"]["dead"] = -1
    with pytest.raises(ValueError, match="invalid_outbox_states"):
        evaluate_alerts(status)


def test_benchmark_sintetico_usa_api_sin_efectos_externos(tmp_path):
    result = benchmark_local(scratch=tmp_path, operations=3, events=5, requests=4, workers=2)
    assert result["synthetic"] is True
    assert result["external_services"] == "not_used"
    assert result["latency_ms"]["operations"]["p95"] >= 0
    assert result["latency_ms"]["telemetry"]["p95"] >= 0
    assert not list(tmp_path.glob("apate-benchmark-*"))
