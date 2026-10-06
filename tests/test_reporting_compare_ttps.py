"""Tests para compare_ttps() -- Fase 4 post-BlackHat (ver
docs/roadmap.md). Extraida de generate_report() para que
apate.web._portfolio.build_portfolio() la reuse sin construir un
OperationReport completo por operacion."""

from apate.reporting import TTPComparison, compare_ttps


def test_compare_ttps_matched_is_intersection():
    result = compare_ttps(["T1046", "T1078"], ["T1078", "T1595.002"])

    assert result.matched_ttps == ["T1078"]
    assert result.ttps_not_observed == ["T1046"]
    assert result.unexpected_ttps == ["T1595.002"]


def test_compare_ttps_results_sorted():
    result = compare_ttps(["T1595.002", "T1046"], ["T1595.002", "T1046"])

    assert result.matched_ttps == ["T1046", "T1595.002"]


def test_compare_ttps_dedupes_repeated_input():
    result = compare_ttps(["T1046", "T1046"], ["T1046"])

    assert result.matched_ttps == ["T1046"]


def test_compare_ttps_empty_inputs():
    result = compare_ttps([], [])

    assert result == TTPComparison(matched_ttps=[], ttps_not_observed=[], unexpected_ttps=[])
