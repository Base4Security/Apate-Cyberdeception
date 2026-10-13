"""Los adaptadores solo entregan evidencia al destino explícito."""

from datetime import datetime, timezone

import pytest

from apate.plugins.base import EventType
from apate.telemetry.exporters import build_otlp_logs, export_to_otlp_http, export_to_splunk_hec
from apate.telemetry.models import TelemetryRecord


class FakeResponse:
    status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return {"code": 0}


class FakeHTTP:
    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


def _record():
    return TelemetryRecord(
        event_type=EventType.INTERACTION, operation_id="op-1", plugin_id="p",
        surface="network", timestamp=datetime(2026, 9, 15, tzinfo=timezone.utc),
        source_event_id="source-1", ttp_id="T1078", payload={"kind": "test"},
    )


def test_splunk_hec_uses_native_format_and_bounds_batches():
    fake = FakeHTTP()
    records = [_record()] * 101
    assert export_to_splunk_hec(records, "https://hec.example/services/collector/event", "test-token", http=fake) == 101
    assert len(fake.calls) == 2
    assert fake.calls[0][1]["headers"]["Authorization"] == "Splunk test-token"
    assert b'"sourcetype": "apate:telemetry"' in fake.calls[0][1]["data"]
    assert fake.calls[0][1]["allow_redirects"] is False


def test_otlp_encodes_log_service_request():
    fake = FakeHTTP()
    record = _record()
    assert export_to_otlp_http([record], "https://collector.example/v1/logs", http=fake) == 1
    body = fake.calls[0][1]["json"]
    log = body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]
    assert log["timeUnixNano"] == str(int(record.timestamp.timestamp() * 1_000_000_000))
    assert record.id in log["body"]["stringValue"]
    assert fake.calls[0][1]["headers"]["Content-Type"] == "application/json"


@pytest.mark.parametrize("url", ["http://hec.example/services/collector/event",
                                 "https://user:pw@hec.example/services/collector/event",
                                 "https://hec.example/other"])
def test_splunk_refuses_unsafe_destination(url):
    with pytest.raises(ValueError):
        export_to_splunk_hec([_record()], url, "test-token", http=FakeHTTP())
