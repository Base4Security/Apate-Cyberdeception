"""Extraccion de texto plano de un informe de CTI cargado -- Fase 6
post-BlackHat (ver docs/roadmap.md), cierra el placeholder de M12k.

Dado un archivo .txt o .pdf ya leido en memoria, devuelve el texto
plano que `apate.cti.extraction.extract_candidates()` va a analizar.
Sin logica de matching aca -- esta capa solo resuelve "como leo el
archivo"; el matching determinista contra el catalogo de apate.attack
vive aparte, en extraction.py.

Import perezoso de pypdf (mismo criterio que apate.reporting.pdf con
fpdf2, M13h): quien solo use apate.cti con archivos .txt no necesita
la dependencia importada en memoria.

**Límites explícitos, validados desde el primer commit:** esta es una
ruta propia de APATE, por lo que no hay razón para omitir validación de
tamaño y extensión. La biblioteca canónica de contexto de comportamiento
aplica el mismo criterio a EVTX desde la Fase 5 de integración."""

from __future__ import annotations

import io
from pathlib import Path

from ..i18n import gettext as _
from .exceptions import CTIExtractionError

# 10 MB alcanza de sobra para un informe de CTI en texto o PDF de
# varias decenas de paginas sin imagenes pesadas; un archivo mas
# grande que eso es casi con certeza el tipo de archivo equivocado.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
# Tope de paginas de PDF a procesar -- protege contra un PDF gigante
# (o adversarial) sin agregar un limite de tiempo real; 200 paginas ya
# excede holgadamente cualquier informe de CTI real.
MAX_PDF_PAGES = 200

_SUPPORTED_SUFFIXES = {".txt", ".pdf"}


def extract_text(filename: str, data: bytes) -> str:
    """Texto plano de un .txt o .pdf. Lanza CTIExtractionError con un
    mensaje pensado para mostrarse tal cual al operador -- extension
    no soportada, archivo vacio/demasiado grande, o PDF que pypdf no
    puede parsear (corrupto, protegido con contrasena, o una imagen
    escaneada sin texto real)."""

    if not data:
        raise CTIExtractionError(_("El archivo esta vacio."))
    if len(data) > MAX_UPLOAD_BYTES:
        raise CTIExtractionError(
            _(
                "El archivo supera el tamano maximo soportado (%(mb)s MB).",
                mb=MAX_UPLOAD_BYTES // (1024 * 1024),
            )
        )

    suffix = Path(filename).suffix.lower()
    if suffix not in _SUPPORTED_SUFFIXES:
        raise CTIExtractionError(
            _(
                "Formato '%(format)s' no soportado -- solo .txt y .pdf.",
                format=suffix or _("(sin extension)"),
            )
        )

    if suffix == ".txt":
        return _extract_txt(data)
    return _extract_pdf(data)


def _extract_txt(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _extract_pdf(data: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:  # pragma: no cover -- pypdf es dependencia declarada, ver pyproject.toml
        raise CTIExtractionError(
            _("Soporte de PDF no disponible en este servidor (falta pypdf).")
        ) from exc

    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as exc:
        raise CTIExtractionError(_("No se pudo leer el PDF -- archivo corrupto o protegido.")) from exc

    text_parts = []
    for page in reader.pages[:MAX_PDF_PAGES]:
        try:
            text_parts.append(page.extract_text() or "")
        except Exception:
            # Una pagina rota no tira abajo la extraccion completa --
            # se sigue con el resto, mismo criterio de "no perder
            # informacion util por un problema puntual" que ya usa
            # PlaygroundEventBridge con fases individuales del atacante.
            continue

    text = "\n".join(text_parts)
    if not text.strip():
        raise CTIExtractionError(
            _("No se pudo extraer texto del PDF (¿es una imagen escaneada sin OCR?).")
        )
    return text
