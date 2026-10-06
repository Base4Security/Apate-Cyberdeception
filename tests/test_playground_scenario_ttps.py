"""Tests para apate.playground.scenario_ttps (M14g) -- cruce entre
Scenario.related_ttps (M1) y lo que el escenario fijo del Playground
puede producir de verdad, ver docs/roadmap.md seccion M14g y
src/apate/data/playground_scenario_ttps.json.

Contra el dataset real (no mockeado), mismo criterio que
test_engage_suggestions.py: los 9 ids son los que efectivamente salen
de la investigacion puntual contra el repo real del Playground
(attacker/attack_scripts/components/base_attacker.py::MITRE_TTPS +
filebeat/filebeat.yml), no valores inventados para el test."""

from apate.playground import ScenarioTTP, list_producible_ttps, match_scenario_ttps

# Los 9 ids reales confirmados en la investigacion de M14g -- 8 del
# diccionario MITRE_TTPS del atacante + 1 exclusivo de Filebeat
# (T1083, regla PATH_TRAVERSAL_ATTEMPT), con solapamiento real en
# T1059.004/T1190/T1110.001 (origin="both").
_EXPECTED_IDS = {
    "T1595.003", "T1059.004", "T1190", "T1018", "T1046",
    "T1110.001", "T1021.004", "T1041", "T1083",
}
_BOTH_ORIGIN_IDS = {"T1059.004", "T1190", "T1110.001"}
_ATTACKER_ONLY_IDS = {"T1595.003", "T1018", "T1046", "T1021.004", "T1041"}
_FILEBEAT_ONLY_IDS = {"T1083"}


def test_list_producible_ttps_has_exactly_the_nine_confirmed_ids():
    ids = {ttp.id for ttp in list_producible_ttps()}
    assert ids == _EXPECTED_IDS


def test_list_producible_ttps_returns_real_scenario_ttp_objects():
    for ttp in list_producible_ttps():
        assert isinstance(ttp, ScenarioTTP)
        assert ttp.name
        assert ttp.origin in {"attacker", "filebeat", "both"}


def test_origin_classification_matches_the_investigation_findings():
    by_id = {ttp.id: ttp for ttp in list_producible_ttps()}
    for ttp_id in _BOTH_ORIGIN_IDS:
        assert by_id[ttp_id].origin == "both", ttp_id
    for ttp_id in _ATTACKER_ONLY_IDS:
        assert by_id[ttp_id].origin == "attacker", ttp_id
    for ttp_id in _FILEBEAT_ONLY_IDS:
        assert by_id[ttp_id].origin == "filebeat", ttp_id


def test_list_producible_ttps_returns_a_copy_not_the_cached_list():
    first = list_producible_ttps()
    first.clear()
    assert len(list_producible_ttps()) == len(_EXPECTED_IDS)


def test_match_scenario_ttps_with_empty_related_ttps_returns_empty_coverage():
    coverage = match_scenario_ttps([])
    assert coverage.producible == []
    assert coverage.not_producible == []


def test_match_scenario_ttps_splits_producible_from_not_producible():
    # T1190 (sql_injection, el atacante y Filebeat la producen) vs. un
    # TTP que este escenario fijo nunca genera (persistencia, ninguna
    # de las 8 fases ni las 6 reglas de Filebeat la cubren).
    coverage = match_scenario_ttps(["T1190", "T1098"])

    assert [ttp.id for ttp in coverage.producible] == ["T1190"]
    assert coverage.not_producible == ["T1098"]


def test_match_scenario_ttps_returns_real_scenario_ttp_objects_for_matches():
    coverage = match_scenario_ttps(["T1046"])
    assert len(coverage.producible) == 1
    matched = coverage.producible[0]
    assert isinstance(matched, ScenarioTTP)
    assert matched.id == "T1046"
    assert matched.attacker_phase == "port_scanning"


def test_match_scenario_ttps_preserves_order_of_not_producible():
    coverage = match_scenario_ttps(["T1098", "T1055", "T1190"])
    assert coverage.not_producible == ["T1098", "T1055"]


def test_match_scenario_ttps_all_producible_when_every_ttp_is_covered():
    coverage = match_scenario_ttps(["T1595.003", "T1041"])
    assert {ttp.id for ttp in coverage.producible} == {"T1595.003", "T1041"}
    assert coverage.not_producible == []
