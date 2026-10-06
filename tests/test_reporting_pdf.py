"""Tests para la exportacion a PDF del informe post-operacion (M6) y
el kit de taller (M12i) -- M13h, ver docs/roadmap.md seccion M13h.

`OperationReport.to_pdf()`/`WorkshopKit.to_pdf()` son una tercera
representacion de salida sobre los mismos datos que ya arma
`to_dict()` -- estos tests confirman que el contenido sustantivo
(TTPs/IoCs/perfil de adversario/escenarios) es el mismo que ya cubre
`to_markdown()`, no una version recortada.

`fpdf2` comprime los content streams del PDF por defecto (Flate/zlib,
mismo mecanismo que cualquier PDF real) -- el texto no aparece como
substring literal en los bytes crudos. `_pdf_text()` descomprime los
bloques `stream`/`endstream` (regex + zlib, sin ninguna libreria de
parseo de PDF nueva) para poder verificar contenido con `in` simple,
sin parsear la estructura completa del documento."""

import re
import zlib
from datetime import datetime, timezone

from apate.core import AdversaryProfile, Scenario
from apate.core.models import DeceptionLevel
from apate.reporting.models import OperationReport, PluginEffectSummary, WorkshopKit
from apate.reporting.pdf import _pdf_safe
from apate.telemetry.models import IoC


def _pdf_text(pdf_bytes: bytes) -> bytes:
    chunks = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.DOTALL):
        try:
            chunks.append(zlib.decompress(match.group(1)))
        except zlib.error:
            continue
    return b"".join(chunks)


def _make_report(**overrides) -> OperationReport:
    defaults = dict(
        operation_id="op-1",
        operation_name="Operacion de prueba",
        operation_status="closed",
        generated_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return OperationReport(**defaults)


def _make_kit(**overrides) -> WorkshopKit:
    defaults = dict(
        operation_id="op-1",
        operation_name="Operacion de prueba",
        operation_status="planning",
        generated_at=datetime.now(timezone.utc),
        adversary_profile=AdversaryProfile(name="APT ficticio", motivation="espionaje"),
    )
    defaults.update(overrides)
    return WorkshopKit(**defaults)


# -- OperationReport.to_pdf() -------------------------------------------


def test_operation_report_to_pdf_returns_valid_pdf_bytes():
    pdf_bytes = _make_report().to_pdf()

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


def test_operation_report_to_pdf_contains_same_ttps_as_markdown():
    report = _make_report(
        expected_ttps=["T1046", "T1078"],
        observed_ttps=["T1046"],
        matched_ttps=["T1046"],
        ttps_not_observed=["T1078"],
        unexpected_ttps=["T1057"],
    )

    markdown = report.to_markdown()
    text = _pdf_text(report.to_pdf())

    for ttp_id in ("T1046", "T1078", "T1057"):
        assert ttp_id.encode() in text
        assert ttp_id in markdown  # confirma que el fixture es equivalente al que ya cubre to_markdown()


def test_operation_report_to_pdf_contains_iocs_table():
    report = _make_report(iocs=[IoC(type="ip", value="203.0.113.5"), IoC(type="hash", value="deadbeef")])

    text = _pdf_text(report.to_pdf())

    assert b"203.0.113.5" in text
    assert b"deadbeef" in text


def test_operation_report_to_pdf_no_iocs_says_so_explicitly():
    text = _pdf_text(_make_report(iocs=[]).to_pdf())
    assert "Sin IoCs observados".encode("windows-1252") in text


def test_operation_report_to_pdf_contains_operation_name_and_status():
    report = _make_report(operation_name="Operacion Fenix", operation_status="closed")
    text = _pdf_text(report.to_pdf())

    assert b"Fenix" in text
    assert b"closed" in text


# -- WorkshopKit.to_pdf() -------------------------------------------------


def test_workshop_kit_to_pdf_returns_valid_pdf_bytes():
    assert _make_kit().to_pdf().startswith(b"%PDF")


def test_workshop_kit_to_pdf_contains_adversary_profile_fields():
    kit = _make_kit(
        adversary_profile=AdversaryProfile(
            name="Actor de ejemplo", motivation="sabotaje", skill_level="advanced", target_assets=["finanzas"]
        )
    )

    text = _pdf_text(kit.to_pdf())

    assert b"Actor de ejemplo" in text
    assert b"sabotaje" in text
    assert b"advanced" in text
    assert b"finanzas" in text


def test_workshop_kit_to_pdf_without_scenarios_says_so_explicitly():
    text = _pdf_text(_make_kit(scenarios=[]).to_pdf())
    assert "completar durante el taller".encode("windows-1252") in text


def test_workshop_kit_to_pdf_includes_ver_pensar_hacer_prompts_per_scenario():
    kit = _make_kit(
        scenarios=[
            Scenario(description="Detectar escaneo interno", related_ttps=["T1046"], deception_level=DeceptionLevel.BASIC)
        ]
    )

    text = _pdf_text(kit.to_pdf())

    assert "Detectar escaneo interno".encode("windows-1252") in text
    assert "VER el adversario".encode("windows-1252") in text
    # Los parentesis literales de "(creer)" viajan escapados dentro del
    # content stream del PDF (son el delimitador de string de PDF) --
    # se busca sin ellos, mismo criterio que el resto de estas
    # aserciones.
    assert "debe PENSAR".encode("windows-1252") in text
    assert "debe HACER".encode("windows-1252") in text
    assert "mide el \xe9xito".encode("windows-1252") in text


def test_workshop_kit_to_pdf_reflects_ttp_heatmap_when_telemetry_present():
    kit = _make_kit(
        expected_ttps=["T1046"],
        observed_ttps=["T1046"],
        matched_ttps=["T1046"],
        ttps_not_observed=[],
        unexpected_ttps=[],
    )

    text = _pdf_text(kit.to_pdf())
    assert b"T1046" in text


def test_workshop_kit_to_pdf_without_telemetry_says_so_explicitly():
    text = _pdf_text(_make_kit().to_pdf())  # observed_ttps=None por defecto
    assert "Sin telemetr\xeda cargada todav\xeda".encode("windows-1252") in text


# -- _pdf_safe(): nunca lanza, incluso con texto fuera de windows-1252 ------


def test_pdf_safe_passes_through_spanish_accented_text_unchanged():
    text = "Atención, señor, niño, ¿qué? ¡sí!"
    assert _pdf_safe(text) == text


def test_pdf_safe_replaces_characters_outside_windows_1252_instead_of_raising():
    # Emoji: fuera de windows-1252 -- no debe lanzar excepcion, se
    # reemplaza en vez de tirar abajo la generacion completa del PDF.
    text = "Operación con emoji \U0001F600"
    result = _pdf_safe(text)
    assert "\U0001F600" not in result
    assert "Operación con emoji" in result


def test_operation_report_to_pdf_does_not_crash_with_emoji_in_operation_name():
    report = _make_report(operation_name="Operación \U0001F600 Fenix")
    pdf_bytes = report.to_pdf()
    assert pdf_bytes.startswith(b"%PDF")


# -- Fase 2 post-BlackHat: efecto de engaño planificado vs. medido -----------


def test_operation_report_to_pdf_shows_measured_outcome():
    measured_at = datetime(2026, 8, 17, 10, 30, tzinfo=timezone.utc)
    report = _make_report(
        plugin_effects=[
            PluginEffectSummary(
                plugin_id="honeytoken-1",
                expected_adversary_belief="cree que es real",
                expected_adversary_action="usa la credencial",
                success_metric="alerta en 5 min",
                measured_outcome="alerta a los 3 minutos",
                measured_at=measured_at,
                measured_by="Federico",
            )
        ]
    )

    text = _pdf_text(report.to_pdf())

    assert "honeytoken-1".encode("windows-1252") in text
    assert "alerta a los 3 minutos".encode("windows-1252") in text
    assert "Federico".encode("windows-1252") in text


def test_operation_report_to_pdf_shows_not_measured_yet_explicitly():
    report = _make_report(
        plugin_effects=[
            PluginEffectSummary(
                plugin_id="mock-1",
                expected_adversary_belief="",
                expected_adversary_action="",
                success_metric="",
                measured_outcome="",
                measured_at=None,
                measured_by="",
            )
        ]
    )

    text = _pdf_text(report.to_pdf())

    assert "sin medir todav".encode("windows-1252") in text


def test_operation_report_to_pdf_no_plugins_says_so_explicitly():
    text = _pdf_text(_make_report(plugin_effects=[]).to_pdf())
    assert "Sin plugins vinculados".encode("windows-1252") in text


def test_workshop_kit_to_pdf_shows_measured_outcome():
    kit = _make_kit(
        plugin_effects=[
            PluginEffectSummary(
                plugin_id="honeytoken-1",
                expected_adversary_belief="",
                expected_adversary_action="",
                success_metric="",
                measured_outcome="observado en vivo",
                measured_at=datetime.now(timezone.utc),
                measured_by="Federico",
            )
        ]
    )

    text = _pdf_text(kit.to_pdf())

    assert "observado en vivo".encode("windows-1252") in text
