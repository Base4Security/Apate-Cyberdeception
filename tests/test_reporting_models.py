import json
from datetime import datetime, timezone

from apate.reporting.models import OperationReport
from apate.telemetry.models import IoC


def _make_report(**overrides) -> OperationReport:
    defaults = dict(
        operation_id="op-1",
        operation_name="Operacion de prueba",
        operation_status="closed",
        generated_at=datetime(2026, 8, 6, 12, 0, tzinfo=timezone.utc),
        expected_ttps=["T1046", "T1078"],
        observed_ttps=["T1078", "T1595.002"],
        matched_ttps=["T1078"],
        ttps_not_observed=["T1046"],
        unexpected_ttps=["T1595.002"],
        iocs=[IoC(type="ip", value="203.0.113.10")],
        event_count=3,
    )
    defaults.update(overrides)
    return OperationReport(**defaults)


def test_to_dict_includes_all_fields_with_json_safe_types():
    report = _make_report()

    data = report.to_dict()

    assert data["operation_id"] == "op-1"
    assert data["generated_at"] == "2026-08-06T12:00:00+00:00"
    assert data["matched_ttps"] == ["T1078"]
    assert data["ttps_not_observed"] == ["T1046"]
    assert data["unexpected_ttps"] == ["T1595.002"]
    assert data["iocs"] == [{"type": "ip", "value": "203.0.113.10"}]
    assert data["event_count"] == 3


def test_to_json_is_valid_json_matching_to_dict():
    report = _make_report()

    parsed = json.loads(report.to_json())

    assert parsed == report.to_dict()


def test_to_markdown_reflects_discrepancies_and_iocs():
    report = _make_report()

    markdown = report.to_markdown()

    assert "T1046" in markdown
    assert "T1078" in markdown
    assert "T1595.002" in markdown
    assert "203.0.113.10" in markdown
    assert "Operacion de prueba" in markdown


def test_to_markdown_handles_empty_lists_without_crashing():
    report = _make_report(
        expected_ttps=[],
        observed_ttps=[],
        matched_ttps=[],
        ttps_not_observed=[],
        unexpected_ttps=[],
        iocs=[],
        event_count=0,
    )

    markdown = report.to_markdown()

    assert "(ninguna)" in markdown
    assert "Sin IoCs observados." in markdown
