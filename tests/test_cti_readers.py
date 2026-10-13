"""Tests para apate.cti.readers -- Fase 6 post-BlackHat (ver
docs/roadmap.md). Los PDFs de prueba se generan con fpdf2 (ya
dependencia del proyecto desde M13h, apate.reporting.pdf) en vez de
sumar un fixture binario -- mismo criterio que evita archivos binarios
versionados donde un generador simple alcanza."""

import pytest

from apate.cti.exceptions import CTIExtractionError
from apate.cti.readers import MAX_UPLOAD_BYTES, extract_text


def _make_pdf_bytes(text: str = "") -> bytes:
    from fpdf import FPDF

    pdf = FPDF(format="A4")
    pdf.core_fonts_encoding = "windows-1252"
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    if text:
        pdf.multi_cell(0, 10, text)
    return bytes(pdf.output())


# -- .txt -----------------------------------------------------------------


def test_extract_text_txt_returns_decoded_text():
    text = extract_text("informe.txt", "Se detecto T1566 en el perimetro.".encode("utf-8"))

    assert "T1566" in text


def test_extract_text_txt_replaces_invalid_bytes_instead_of_raising():
    # bytes invalidos en utf-8 -- no debe explotar, solo degradar.
    text = extract_text("informe.txt", b"\xff\xfe texto roto")

    assert isinstance(text, str)


# -- Validaciones comunes ---------------------------------------------------


def test_extract_text_empty_file_raises():
    with pytest.raises(CTIExtractionError):
        extract_text("informe.txt", b"")


def test_extract_text_too_large_raises():
    data = b"a" * (MAX_UPLOAD_BYTES + 1)
    with pytest.raises(CTIExtractionError):
        extract_text("informe.txt", data)


def test_extract_text_unsupported_extension_raises():
    with pytest.raises(CTIExtractionError):
        extract_text("informe.docx", b"contenido")


def test_extract_text_no_extension_raises():
    with pytest.raises(CTIExtractionError):
        extract_text("informe", b"contenido")


# -- .pdf -------------------------------------------------------------------


def test_extract_text_pdf_returns_text():
    data = _make_pdf_bytes("El grupo APT28 uso T1566 contra el objetivo.")

    text = extract_text("informe.pdf", data)

    assert "APT28" in text
    assert "T1566" in text


def test_extract_text_pdf_corrupt_raises():
    with pytest.raises(CTIExtractionError):
        extract_text("informe.pdf", b"esto no es un pdf valido")


def test_extract_text_pdf_without_extractable_text_raises():
    data = _make_pdf_bytes("")  # pagina en blanco, sin texto

    with pytest.raises(CTIExtractionError):
        extract_text("informe.pdf", data)
