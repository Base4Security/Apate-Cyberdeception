"""Tests de integracion web para Fase 6 post-BlackHat (ver
docs/roadmap.md): POST /operations/cti-extract, la ruta AJAX que
cierra el placeholder de M12k. Cubre la ruta HTTP en si (multipart
upload, errores, forma del JSON) -- el matching determinista propio
ya esta cubierto por tests/test_cti_extraction.py y
tests/test_cti_readers.py contra apate.cti directamente, sin pasar
por HTTP."""

import io


def test_cti_extract_returns_technique_and_group_matches(client):
    data = {
        "cti_report_file": (
            io.BytesIO("El grupo APT28 (Fancy Bear) uso T1566 (Phishing) contra el objetivo.".encode("utf-8")),
            "informe.txt",
        )
    }

    response = client.post("/operations/cti-extract", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    payload = response.get_json()
    technique_ids = [m["id"] for m in payload["technique_matches"]]
    group_ids = [m["id"] for m in payload["group_matches"]]
    assert "T1566" in technique_ids
    assert "G0007" in group_ids


def _upload(client, text: str, filename: str = "informe.txt"):
    data = {"cti_report_file": (io.BytesIO(text.encode("utf-8")), filename)}
    return client.post("/operations/cti-extract", data=data, content_type="multipart/form-data")


def test_cti_extract_technique_match_has_expected_fields(client):
    response = _upload(client, "T1566 observado en el perimetro.")

    match = response.get_json()["technique_matches"][0]
    assert match["id"] == "T1566"
    assert match["name"] == "Phishing"
    assert match["matched_via"] == "id"
    assert match["raw_match"] == "T1566"


def test_cti_extract_group_match_has_expected_fields(client):
    response = _upload(client, "Atribuido a APT28.")

    match = response.get_json()["group_matches"][0]
    assert match["id"] == "G0007"
    assert match["name"] == "APT28"
    assert match["raw_match"] == "APT28"


def test_cti_extract_no_matches_returns_empty_lists(client):
    response = _upload(client, "Documento sin ninguna referencia relevante.")

    payload = response.get_json()
    assert payload["technique_matches"] == []
    assert payload["group_matches"] == []


def test_cti_extract_without_file_returns_400(client):
    response = client.post("/operations/cti-extract", data={}, content_type="multipart/form-data")

    assert response.status_code == 400
    assert "error" in response.get_json()


def test_cti_extract_empty_filename_returns_400(client):
    data = {"cti_report_file": (io.BytesIO(b""), "")}

    response = client.post("/operations/cti-extract", data=data, content_type="multipart/form-data")

    assert response.status_code == 400


def test_cti_extract_unsupported_extension_returns_400_with_message(client):
    response = _upload(client, "contenido", filename="informe.docx")

    assert response.status_code == 400
    assert "no soportado" in response.get_json()["error"]


def test_cti_extract_empty_file_returns_400(client):
    data = {"cti_report_file": (io.BytesIO(b""), "informe.txt")}

    response = client.post("/operations/cti-extract", data=data, content_type="multipart/form-data")

    assert response.status_code == 400


def test_cti_extract_pdf_upload_works_end_to_end(client):
    from fpdf import FPDF

    pdf = FPDF(format="A4")
    pdf.core_fonts_encoding = "windows-1252"
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    pdf.multi_cell(0, 10, "Informe de CTI: se observo T1566 atribuido a APT28.")
    pdf_bytes = bytes(pdf.output())

    data = {"cti_report_file": (io.BytesIO(pdf_bytes), "informe.pdf")}
    response = client.post("/operations/cti-extract", data=data, content_type="multipart/form-data")

    assert response.status_code == 200
    payload = response.get_json()
    assert "T1566" in [m["id"] for m in payload["technique_matches"]]
    assert "G0007" in [m["id"] for m in payload["group_matches"]]


def test_cti_extract_does_not_create_or_modify_any_operation(client, app):
    repo = app.config["OPERATION_REPOSITORY"]
    before = len(list(repo.list()))

    _upload(client, "APT28 uso T1566.")

    assert len(list(repo.list())) == before


def test_cti_extract_get_falls_through_to_operation_detail_as_404(client):
    # /operations/cti-extract solo acepta POST -- para un GET, Werkzeug
    # no devuelve 405: como /operations/<operation_id> tambien matchea
    # ese path literal (interpretando "cti-extract" como operation_id) y
    # si acepta GET, cae ahi en vez de a MethodNotAllowed. Inofensivo en
    # la practica (los ids reales son UUID, nunca van a coincidir), pero
    # el resultado observable es 404 ("operacion no encontrada"), no 405.
    response = client.get("/operations/cti-extract")

    assert response.status_code == 404
