from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from apate.telemetry import (
    JSONFileVirusTotalEnrichmentRepository,
    VirusTotalConfigRepository,
    VirusTotalEnrichment,
    query_virustotal,
)


def _enrichment(**overrides):
    values = dict(
        operation_id="op-1",
        subject_key="ip:203.0.113.10",
        ioc_type="ip",
        ioc_value="203.0.113.10",
        malicious=2,
        suspicious=1,
        total=90,
        result_url="https://www.virustotal.com/gui/ip-address/203.0.113.10",
        queried_at=datetime(2026, 8, 24, tzinfo=timezone.utc),
    )
    values.update(overrides)
    return VirusTotalEnrichment(**values)


def test_enrichment_roundtrip_preserves_summary():
    enrichment = _enrichment()

    restored = VirusTotalEnrichment.from_dict(enrichment.to_dict())

    assert restored == enrichment


def test_repository_returns_empty_for_unknown_operation(tmp_path):
    repo = JSONFileVirusTotalEnrichmentRepository(tmp_path)

    assert repo.list_for_operation("missing") == []


def test_repository_persists_one_file_per_operation(tmp_path):
    repo = JSONFileVirusTotalEnrichmentRepository(tmp_path)
    repo.save(_enrichment())
    repo.save(_enrichment(operation_id="op-2"))

    assert len(repo.list_for_operation("op-1")) == 1
    assert len(repo.list_for_operation("op-2")) == 1
    assert sorted(path.name for path in tmp_path.glob("*.json")) == ["op-1.json", "op-2.json"]


def test_repository_upserts_same_ioc(tmp_path):
    repo = JSONFileVirusTotalEnrichmentRepository(tmp_path)
    repo.save(_enrichment(malicious=1))
    repo.save(_enrichment(malicious=8))

    saved = repo.list_for_operation("op-1")
    assert len(saved) == 1
    assert saved[0].malicious == 8


def test_repository_keeps_distinct_iocs(tmp_path):
    repo = JSONFileVirusTotalEnrichmentRepository(tmp_path)
    repo.save(_enrichment())
    repo.save(_enrichment(subject_key="domain:example.test", ioc_type="domain", ioc_value="example.test"))

    assert len(repo.list_for_operation("op-1")) == 2


def test_config_repository_roundtrip(tmp_path):
    repo = VirusTotalConfigRepository(tmp_path / "virustotal.json")

    assert repo.load() == {}
    repo.save_api_key("vt-secret")

    assert repo.load() == {"api_key": "vt-secret"}


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected_path", "expected_gui"),
    [
        ("hash", "abc123", "/files/abc123", "/file/abc123"),
        ("ip", "8.8.8.8", "/ip_addresses/8.8.8.8", "/ip-address/8.8.8.8"),
        ("domain", "example.com", "/domains/example.com", "/domain/example.com"),
        ("url", "https://example.com/a?b=1", "/urls/aHR0cHM6Ly9leGFtcGxlLmNvbS9hP2I9MQ", "/url/aHR0cHM6Ly9leGFtcGxlLmNvbS9hP2I9MQ"),
    ],
)
def test_query_uses_v3_endpoint_header_timeout_and_summarizes(
    ioc_type, value, expected_path, expected_gui
):
    response = Mock()
    response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 2,
                    "harmless": 70,
                    "undetected": 15,
                    "timeout": 0,
                }
            }
        }
    }
    with patch("apate.telemetry.virustotal.requests.get", return_value=response) as get:
        result = query_virustotal("op-1", ioc_type, value, "vt-key")

    get.assert_called_once_with(
        f"https://www.virustotal.com/api/v3{expected_path}",
        headers={"x-apikey": "vt-key"},
        timeout=8.0,
    )
    response.raise_for_status.assert_called_once_with()
    assert (result.malicious, result.suspicious, result.total) == (3, 2, 90)
    assert result.result_url == f"https://www.virustotal.com/gui{expected_gui}"


def test_query_rejects_unsupported_ioc_without_http_call():
    with patch("apate.telemetry.virustotal.requests.get") as get:
        with pytest.raises(ValueError):
            query_virustotal("op-1", "email", "analyst@example.test", "vt-key")
    get.assert_not_called()


@pytest.mark.parametrize(
    ("ioc_type", "value"),
    [("ip", "10.0.0.7"), ("domain", "fileserver.local"), ("url", "https://127.0.0.1/admin")],
)
def test_query_rejects_private_iocs_without_http_call(ioc_type, value):
    with patch("apate.telemetry.virustotal.requests.get") as get:
        with pytest.raises(ValueError, match="no se enviará"):
            query_virustotal("op-1", ioc_type, value, "vt-key")
    get.assert_not_called()
