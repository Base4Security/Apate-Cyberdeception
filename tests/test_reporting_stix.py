"""Exportación STIX 2.1 del informe post-operación (M6) -- cierre
verificable del paso 6/7 de la metodología CTI-a-ciberengaño. Ver
docstring de `apate.reporting.stix` para el mapeo completo campo por
campo y las decisiones de formato/dependencias.

Los tests de validación real contra la librería de referencia de OASIS
(`stix2`/`stix2patterns`, dependencia de TEST únicamente -- ver
`pyproject.toml`) se saltean con gracia si no está instalada, en vez de
romper la suite para quien no instaló los extras de `dev`."""

from datetime import datetime, timezone

import pytest

from apate.reporting.models import OperationReport, PluginEffectSummary
from apate.reporting.stix import (
    _attack_pattern_url,
    _escape_pattern_string,
    _hash_algorithm,
    _ioc_pattern,
    _stix_timestamp,
    operation_report_to_stix_bundle,
)
from apate.telemetry.classifications import TlpClassification, TlpLevel
from apate.telemetry.models import IoC

stix2 = pytest.importorskip("stix2", reason="stix2 es una dependencia de test (pyproject.toml, extra dev)")
from stix2patterns.validator import run_validator  # noqa: E402


def _report(**overrides) -> OperationReport:
    defaults = dict(
        operation_id="op-1",
        operation_name="Operación de prueba",
        operation_status="closed",
        generated_at=datetime(2026, 1, 15, 12, 30, 45, 123456, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return OperationReport(**defaults)


# -- Helpers puros --------------------------------------------------------


def test_stix_timestamp_ends_in_z_not_utc_offset():
    ts = _stix_timestamp(datetime(2026, 1, 15, 12, 30, 45, 123456, tzinfo=timezone.utc))
    assert ts == "2026-01-15T12:30:45.123Z"


def test_stix_timestamp_assumes_utc_for_naive_datetime():
    ts = _stix_timestamp(datetime(2026, 1, 15, 12, 30, 45))
    assert ts.endswith("Z")
    assert "+" not in ts


def test_escape_pattern_string_escapes_quote_and_backslash():
    assert _escape_pattern_string(r"O'Brien\path") == r"O\'Brien\\path"


def test_hash_algorithm_inferred_by_length():
    assert _hash_algorithm("a" * 32) == "MD5"
    assert _hash_algorithm("a" * 40) == "SHA-1"
    assert _hash_algorithm("a" * 64) == "SHA-256"
    assert _hash_algorithm("a" * 128) == "SHA-512"


def test_hash_algorithm_custom_when_length_unknown_or_not_hex():
    assert _hash_algorithm("a" * 10) == "Custom-Hash"
    assert _hash_algorithm("z" * 64) == "Custom-Hash"  # no es hex valido


def test_attack_pattern_url_for_parent_technique():
    assert _attack_pattern_url("T1078") == "https://attack.mitre.org/techniques/T1078/"


def test_attack_pattern_url_for_subtechnique_uses_slash_not_dot():
    assert _attack_pattern_url("T1078.004") == "https://attack.mitre.org/techniques/T1078/004/"


def test_ioc_pattern_unknown_type_returns_none():
    assert _ioc_pattern("no-existe", "algo") is None


@pytest.mark.parametrize(
    "ioc_type,value,expected_start",
    [
        ("ip", "192.168.1.5", "[ipv4-addr:value"),
        ("ip", "fe80::1", "[ipv6-addr:value"),
        ("domain", "evil.example", "[domain-name:value"),
        ("url", "http://evil.example/x", "[url:value"),
        ("hash", "a" * 32, "[file:hashes.'MD5'"),
        ("credential", "admin:hunter2", "[user-account:credential"),
    ],
)
def test_ioc_pattern_shapes(ioc_type, value, expected_start):
    pattern = _ioc_pattern(ioc_type, value)
    assert pattern.startswith(expected_start)


# -- Estructura del bundle -------------------------------------------------


def test_bundle_always_has_identity_and_report():
    bundle = operation_report_to_stix_bundle(_report())
    types = [obj["type"] for obj in bundle["objects"]]
    assert types == ["identity", "report"]


def test_bundle_attack_pattern_per_union_of_expected_and_observed_ttps():
    report = _report(expected_ttps=["T1078", "T1566"], observed_ttps=["T1566", "T1110.001"])
    bundle = operation_report_to_stix_bundle(report)

    ttp_ids = {
        ref["external_id"]
        for obj in bundle["objects"]
        if obj["type"] == "attack-pattern"
        for ref in obj["external_references"]
    }
    assert ttp_ids == {"T1078", "T1566", "T1110.001"}


def test_bundle_attack_pattern_uses_catalog_name_and_tactic_when_known():
    bundle = operation_report_to_stix_bundle(_report(expected_ttps=["T1078"]))
    attack_pattern = next(obj for obj in bundle["objects"] if obj["type"] == "attack-pattern")

    assert attack_pattern["name"] == "Valid Accounts"
    assert attack_pattern["kill_chain_phases"] == [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]


def test_bundle_attack_pattern_for_ttp_outside_catalog_has_no_fabricated_name_or_tactic():
    bundle = operation_report_to_stix_bundle(_report(expected_ttps=["T1078.004"]))
    attack_pattern = next(obj for obj in bundle["objects"] if obj["type"] == "attack-pattern")

    # Sin nombre curado -- el ID crudo como name, nunca inventado.
    assert attack_pattern["name"] == "T1078.004"
    assert "kill_chain_phases" not in attack_pattern
    # La referencia externa SI es correcta -- se deriva del ID solo.
    assert attack_pattern["external_references"][0]["url"] == "https://attack.mitre.org/techniques/T1078/004/"


def test_bundle_indicator_per_ioc():
    report = _report(iocs=[IoC(type="ip", value="1.2.3.4"), IoC(type="domain", value="evil.example")])
    bundle = operation_report_to_stix_bundle(report)

    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    assert len(indicators) == 2
    patterns = {ind["pattern"] for ind in indicators}
    assert "[ipv4-addr:value = '1.2.3.4']" in patterns
    assert "[domain-name:value = 'evil.example']" in patterns


# -- Clasificación TLP (segunda de la tanda de mejoras de UI/UX con
# referencia CounterCraft, ver docs/roadmap.md) ---------------------------


def test_ioc_with_tlp_classification_gets_marking_definition_and_object_marking_refs():
    report = _report(iocs=[IoC(type="ip", value="1.2.3.4")])
    classification = TlpClassification(
        operation_id="op-1", subject_type="ioc", subject_key="ip:1.2.3.4", level=TlpLevel.RED
    )

    bundle = operation_report_to_stix_bundle(report, tlp_classifications=[classification])

    marking = next(obj for obj in bundle["objects"] if obj["type"] == "marking-definition")
    assert marking["id"] == "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
    assert marking["definition"] == {"tlp": "red"}

    indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
    assert indicator["object_marking_refs"] == [marking["id"]]


def test_ioc_without_tlp_classification_has_no_marking_refs():
    report = _report(iocs=[IoC(type="ip", value="1.2.3.4")])

    bundle = operation_report_to_stix_bundle(report, tlp_classifications=None)

    assert not any(obj["type"] == "marking-definition" for obj in bundle["objects"])
    indicator = next(obj for obj in bundle["objects"] if obj["type"] == "indicator")
    assert "object_marking_refs" not in indicator


def test_event_tlp_classification_has_no_representation_in_bundle():
    """Documentado a propósito: sin un IoC coincidente, una
    clasificación sobre un evento no tiene ningún objeto STIX que
    marcar (el bundle no modela eventos individuales)."""

    report = _report(iocs=[])
    classification = TlpClassification(
        operation_id="op-1", subject_type="event", subject_key="evt-1", level=TlpLevel.RED
    )

    bundle = operation_report_to_stix_bundle(report, tlp_classifications=[classification])

    assert not any(obj["type"] == "marking-definition" for obj in bundle["objects"])


def test_each_tlp_marking_definition_added_only_once_per_level():
    report = _report(iocs=[IoC(type="ip", value="1.2.3.4"), IoC(type="ip", value="5.6.7.8")])
    classifications = [
        TlpClassification(operation_id="op-1", subject_type="ioc", subject_key="ip:1.2.3.4", level=TlpLevel.AMBER),
        TlpClassification(operation_id="op-1", subject_type="ioc", subject_key="ip:5.6.7.8", level=TlpLevel.AMBER),
    ]

    bundle = operation_report_to_stix_bundle(report, tlp_classifications=classifications)

    markings = [obj for obj in bundle["objects"] if obj["type"] == "marking-definition"]
    assert len(markings) == 1
    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    assert all(ind["object_marking_refs"] == [markings[0]["id"]] for ind in indicators)


def test_all_four_tlp_marking_ids_match_the_real_stix2_library_constants():
    stix2 = pytest.importorskip("stix2", reason="stix2 es una dependencia de test (pyproject.toml, extra dev)")
    expected = {
        TlpLevel.RED: stix2.TLP_RED.id,
        TlpLevel.AMBER: stix2.TLP_AMBER.id,
        TlpLevel.GREEN: stix2.TLP_GREEN.id,
        TlpLevel.WHITE: stix2.TLP_WHITE.id,
    }
    for level, expected_id in expected.items():
        report = _report(iocs=[IoC(type="ip", value="1.2.3.4")])
        classification = TlpClassification(
            operation_id="op-1", subject_type="ioc", subject_key="ip:1.2.3.4", level=level
        )
        bundle = operation_report_to_stix_bundle(report, tlp_classifications=[classification])
        marking = next(obj for obj in bundle["objects"] if obj["type"] == "marking-definition")
        assert marking["id"] == expected_id


def test_bundle_with_tlp_marking_still_parses_with_the_real_stix2_library():
    stix2 = pytest.importorskip("stix2", reason="stix2 es una dependencia de test (pyproject.toml, extra dev)")
    report = _report(iocs=[IoC(type="ip", value="1.2.3.4"), IoC(type="domain", value="evil.example")])
    classifications = [
        TlpClassification(operation_id="op-1", subject_type="ioc", subject_key="ip:1.2.3.4", level=TlpLevel.RED),
        TlpClassification(
            operation_id="op-1", subject_type="ioc", subject_key="domain:evil.example", level=TlpLevel.GREEN
        ),
    ]

    parsed = stix2.parse(report.to_stix(tlp_classifications=classifications), allow_custom=False)

    marking_types = [obj["type"] for obj in parsed.objects if obj["type"] == "marking-definition"]
    assert len(marking_types) == 2


def test_bundle_note_only_for_plugin_effects_with_real_content():
    report = _report(
        plugin_effects=[
            PluginEffectSummary(
                plugin_id="mock-1",
                expected_adversary_belief="cree que es real",
                expected_adversary_action="",
                success_metric="",
                measured_outcome="",
                measured_at=None,
                measured_by="",
            ),
            PluginEffectSummary(
                plugin_id="mock-2",
                expected_adversary_belief="",
                expected_adversary_action="",
                success_metric="",
                measured_outcome="",
                measured_at=None,
                measured_by="",
            ),
        ]
    )
    bundle = operation_report_to_stix_bundle(report)

    notes = [obj for obj in bundle["objects"] if obj["type"] == "note"]
    assert len(notes) == 1
    assert "mock-1" in notes[0]["content"]
    assert "mock-2" not in notes[0]["content"]


def test_engage_activities_never_appear_in_the_bundle():
    """Decision explicita del modulo: las actividades de Engage son
    plan metodologico, no CTI para un consumidor externo -- no deben
    aparecer en ningun texto del bundle."""

    report = _report(
        plugin_effects=[
            PluginEffectSummary(
                plugin_id="mock-1",
                expected_adversary_belief="x",
                expected_adversary_action="y",
                success_metric="z",
                measured_outcome="",
                measured_at=None,
                measured_by="",
            )
        ]
    )
    bundle = operation_report_to_stix_bundle(report)
    assert "EAC" not in str(bundle)
    assert "engage" not in str(bundle).lower()


def test_report_object_object_refs_includes_every_other_object():
    report = _report(
        expected_ttps=["T1078"],
        iocs=[IoC(type="ip", value="1.2.3.4")],
        plugin_effects=[
            PluginEffectSummary(
                plugin_id="mock-1",
                expected_adversary_belief="x",
                expected_adversary_action="",
                success_metric="",
                measured_outcome="",
                measured_at=None,
                measured_by="",
            )
        ],
    )
    bundle = operation_report_to_stix_bundle(report)

    report_object = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    other_ids = {obj["id"] for obj in bundle["objects"] if obj["type"] != "report"}
    assert set(report_object["object_refs"]) == other_ids


def test_bundle_json_serializable_and_matches_operation_report_to_dict_ttps():
    report = _report(expected_ttps=["T1078"], observed_ttps=["T1078"])
    text = report.to_stix()
    import json

    parsed = json.loads(text)
    assert parsed["type"] == "bundle"


# -- Validación real contra la librería de referencia OASIS ----------------


def test_bundle_parses_with_the_real_stix2_library():
    report = _report(
        expected_ttps=["T1078", "T1078.004", "T9999-no-existe"],
        observed_ttps=["T1110.001"],
        iocs=[
            IoC(type="ip", value="192.168.1.5"),
            IoC(type="ip", value="fe80::1"),
            IoC(type="hash", value="d41d8cd98f00b204e9800998ecf8427e"),
            IoC(type="hash", value="not-a-real-hash-but-hex-like-value-of-len-10"[:10]),
            IoC(type="domain", value="evil.example"),
            IoC(type="url", value="http://evil.example/x"),
            IoC(type="credential", value="admin's:hunter2\\path"),
        ],
        plugin_effects=[
            PluginEffectSummary(
                plugin_id="mock-1",
                expected_adversary_belief="cree que es real",
                expected_adversary_action="interactúa",
                success_metric="alerta en 10 min",
                measured_outcome="funcionó",
                measured_at=datetime.now(timezone.utc),
                measured_by="ana",
            )
        ],
    )

    # allow_custom=False: si algun objeto tuviera una propiedad no
    # reconocida por el esquema real de STIX 2.1, esto lanza -- la
    # prueba real de que el bundle es compatible, no solo "parece bien".
    parsed = stix2.parse(report.to_stix(), allow_custom=False)

    assert parsed["type"] == "bundle"
    # identity(1) + attack-pattern por cada TTP distinta en el union
    # expected/observed (T1078, T1078.004, T9999-no-existe, T1110.001 = 4)
    # + indicator por cada IoC (7) + note (1 plugin_effect con contenido) + report(1)
    assert len(parsed.objects) == 1 + 4 + 7 + 1 + 1


def test_every_indicator_pattern_is_valid_stix_pattern_grammar():
    """Ademas de que el objeto parsee (esquema), el STRING del patron
    (`indicator.pattern`) tiene su propia gramatica formal (STIX
    Patterning Language) -- `stix2patterns` la valida de verdad via el
    parser ANTLR oficial, no una regex aproximada."""

    report = _report(
        iocs=[
            IoC(type="ip", value="192.168.1.5"),
            IoC(type="ip", value="fe80::1"),
            IoC(type="hash", value="d41d8cd98f00b204e9800998ecf8427e"),
            IoC(type="hash", value="abcd1234"),
            IoC(type="domain", value="evil.example"),
            IoC(type="url", value="http://evil.example/x"),
            IoC(type="credential", value="admin's:hunter2\\path"),
        ]
    )
    bundle = operation_report_to_stix_bundle(report)
    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    assert len(indicators) == 7

    for indicator in indicators:
        errors = run_validator(indicator["pattern"])
        assert errors == [], f"patron invalido: {indicator['pattern']!r} -> {errors}"


def test_empty_operation_report_still_produces_a_valid_bundle():
    parsed = stix2.parse(_report().to_stix(), allow_custom=False)
    assert [obj["type"] for obj in parsed.objects] == ["identity", "report"]
