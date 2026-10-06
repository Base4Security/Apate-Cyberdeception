"""Tests de integracion web para la exportacion a PDF (M13h) --
`?format=pdf` en `GET /operations/<id>/report` (M6) y
`GET /operations/<id>/workshop-kit` (M12i). Mismo patron que
tests/test_web_operations.py/test_web_operations_workshop_kit.py
(helper `_create_operation` posteando al formulario real).

`_pdf_text()` descomprime los content streams del PDF (Flate/zlib) para
poder verificar contenido con `in` simple, sin parsear la estructura
completa del documento -- mismo helper que
tests/test_reporting_pdf.py."""

import re
import zlib


def _pdf_text(pdf_bytes: bytes) -> bytes:
    chunks = []
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.DOTALL):
        try:
            chunks.append(zlib.decompress(match.group(1)))
        except zlib.error:
            continue
    return b"".join(chunks)


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M13h",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046", "T1078"],
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def _create_closed_operation(client, **overrides):
    operation_id = _create_operation(client, **overrides)
    client.post(f"/operations/{operation_id}/transition", data={"to": "closed"})
    return operation_id


# -- GET /operations/<id>/report?format=pdf ----------------------------


def test_report_pdf_format_returns_valid_pdf_with_correct_headers(client):
    operation_id = _create_closed_operation(client)

    response = client.get(f"/operations/{operation_id}/report?format=pdf")

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert "attachment" in response.headers["Content-Disposition"]
    assert f"informe-{operation_id}.pdf" in response.headers["Content-Disposition"]
    assert response.data.startswith(b"%PDF")


def test_report_pdf_contains_same_ttps_as_markdown_version(client):
    operation_id = _create_closed_operation(client, expected_ttps=["T1046", "T1078"])

    markdown_response = client.get(f"/operations/{operation_id}/report?format=markdown")
    pdf_response = client.get(f"/operations/{operation_id}/report?format=pdf")

    pdf_text = _pdf_text(pdf_response.data)
    for ttp_id in ("T1046", "T1078"):
        assert ttp_id.encode() in markdown_response.data
        assert ttp_id.encode() in pdf_text


def test_report_pdf_flashes_error_for_non_closed_operation(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}/report?format=pdf", follow_redirects=True)

    assert response.status_code == 200
    assert b"flash-error" in response.data


def test_report_pdf_404_for_unknown_operation(client):
    response = client.get("/operations/no-existe/report?format=pdf")
    assert response.status_code == 404


# -- GET /operations/<id>/workshop-kit?format=pdf -----------------------


def test_workshop_kit_pdf_format_returns_valid_pdf_with_correct_headers(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}/workshop-kit?format=pdf")

    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert "attachment" in response.headers["Content-Disposition"]
    assert f"kit-taller-{operation_id}.pdf" in response.headers["Content-Disposition"]
    assert response.data.startswith(b"%PDF")


def test_workshop_kit_pdf_available_regardless_of_operation_status(client):
    planning_id = _create_operation(client)
    closed_id = _create_closed_operation(client, name="Cerrada M13h")

    for operation_id in (planning_id, closed_id):
        response = client.get(f"/operations/{operation_id}/workshop-kit?format=pdf")
        assert response.status_code == 200
        assert response.data.startswith(b"%PDF")


def test_workshop_kit_pdf_contains_same_adversary_profile_as_markdown_version(client):
    operation_id = _create_operation(client, adversary_name="Actor de ejemplo M13h")

    markdown_response = client.get(f"/operations/{operation_id}/workshop-kit?format=markdown")
    pdf_response = client.get(f"/operations/{operation_id}/workshop-kit?format=pdf")

    assert b"Actor de ejemplo M13h" in markdown_response.data
    assert b"Actor de ejemplo M13h" in _pdf_text(pdf_response.data)


def test_workshop_kit_pdf_404_for_unknown_operation(client):
    response = client.get("/operations/no-existe/workshop-kit?format=pdf")
    assert response.status_code == 404


# -- Botones en operations/detail.html -----------------------------------


def test_detail_page_shows_pdf_download_button_for_report_only_when_closed(client):
    open_operation_id = _create_operation(client)
    response = client.get(f"/operations/{open_operation_id}")
    assert b"Descargar PDF" not in response.data

    closed_operation_id = _create_closed_operation(client, name="Cerrada M13h botones")
    response = client.get(f"/operations/{closed_operation_id}")
    assert b"Descargar PDF" in response.data


def test_detail_page_shows_workshop_kit_pdf_button_regardless_of_status(client):
    operation_id = _create_operation(client)
    response = client.get(f"/operations/{operation_id}")

    assert b"kit de taller (PDF)" in response.data
    assert b"kit de taller (Markdown)" in response.data
