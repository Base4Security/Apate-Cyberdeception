"""Tests para el dataclass `WorkshopKit` (M12i, `apate.reporting.models`)
en aislamiento -- roundtrip de serializacion y renderizado Markdown.
Sigue el mismo patron que tests/test_reporting_models.py (OperationReport)."""

import json
from datetime import datetime, timezone

from apate.core import AdversaryProfile, Scenario
from apate.reporting.models import WorkshopKit


def _make_kit(**overrides) -> WorkshopKit:
    defaults = dict(
        operation_id="op-1",
        operation_name="Operacion de prueba",
        operation_status="planning",
        generated_at=datetime(2026, 8, 6, 12, 0, tzinfo=timezone.utc),
        adversary_profile=AdversaryProfile(
            name="APT ficticio",
            motivation="espionaje",
            skill_level="intermediate",
            expected_ttps=["T1046", "T1078"],
            target_assets=["ERP"],
            notes="Notas del analista",
        ),
        scenarios=[Scenario(description="Detectar escaneo interno", related_ttps=["T1046"])],
        expected_ttps=["T1046", "T1078"],
    )
    defaults.update(overrides)
    return WorkshopKit(**defaults)


def test_to_dict_includes_all_fields_with_json_safe_types():
    kit = _make_kit()

    data = kit.to_dict()

    assert data["operation_id"] == "op-1"
    assert data["generated_at"] == "2026-08-06T12:00:00+00:00"
    assert data["adversary_profile"]["name"] == "APT ficticio"
    assert data["scenarios"][0]["description"] == "Detectar escaneo interno"
    assert data["expected_ttps"] == ["T1046", "T1078"]
    assert data["observed_ttps"] is None


def test_to_dict_preserves_none_for_ttp_breakdown_fields_when_not_compared():
    kit = _make_kit(observed_ttps=None, matched_ttps=None, ttps_not_observed=None, unexpected_ttps=None)

    data = kit.to_dict()

    assert data["observed_ttps"] is None
    assert data["matched_ttps"] is None
    assert data["ttps_not_observed"] is None
    assert data["unexpected_ttps"] is None


def test_to_dict_reflects_ttp_breakdown_when_compared():
    kit = _make_kit(
        observed_ttps=["T1078", "T1595.002"],
        matched_ttps=["T1078"],
        ttps_not_observed=["T1046"],
        unexpected_ttps=["T1595.002"],
    )

    data = kit.to_dict()

    assert data["matched_ttps"] == ["T1078"]
    assert data["unexpected_ttps"] == ["T1595.002"]


def test_to_json_is_valid_json_matching_to_dict():
    kit = _make_kit()

    parsed = json.loads(kit.to_json())

    assert parsed == kit.to_dict()


def test_to_markdown_includes_profile_scenario_and_workshop_questions():
    kit = _make_kit()

    markdown = kit.to_markdown()

    assert "APT ficticio" in markdown
    assert "Detectar escaneo interno" in markdown
    assert "T1046" in markdown
    assert "¿Qué debe VER el adversario?" in markdown
    assert "¿Qué debe PENSAR (creer)?" in markdown
    assert "¿Qué debe HACER?" in markdown
    assert "¿Cómo se mide el éxito?" in markdown


def test_to_markdown_degraded_heatmap_mentions_missing_telemetry():
    kit = _make_kit(observed_ttps=None, matched_ttps=None, ttps_not_observed=None, unexpected_ttps=None)

    markdown = kit.to_markdown()

    assert "Sin telemetría cargada" in markdown


def test_to_markdown_full_heatmap_shows_all_five_breakdowns():
    kit = _make_kit(
        observed_ttps=["T1078", "T1595.002"],
        matched_ttps=["T1078"],
        ttps_not_observed=["T1046"],
        unexpected_ttps=["T1595.002"],
    )

    markdown = kit.to_markdown()

    assert "Coincidentes" in markdown
    assert "Observadas y NO esperadas" in markdown
    assert "T1595.002" in markdown


def test_to_markdown_without_scenarios_says_so_explicitly_instead_of_omitting():
    kit = _make_kit(scenarios=[])

    markdown = kit.to_markdown()

    assert "Sin escenarios cargados todavía" in markdown


def test_to_markdown_handles_empty_notes_and_motivation_without_crashing():
    kit = _make_kit(
        adversary_profile=AdversaryProfile(name="Actor sin datos"),
        expected_ttps=[],
    )

    markdown = kit.to_markdown()

    assert "(sin registrar)" in markdown
    assert "(sin notas)" in markdown
    assert "(ninguna)" in markdown
