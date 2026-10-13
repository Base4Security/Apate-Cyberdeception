"""Ingesta de informes de CTI (Fase 6 post-BlackHat, ver
docs/roadmap.md) -- cierra el placeholder de M12k. Dos capas
separadas: `readers.extract_text()` resuelve un archivo .txt/.pdf
cargado a texto plano; `extraction.extract_candidates()` hace el
matching determinista (sin LLM) de ese texto contra el catalogo
curado de `apate.attack`. Consumido por `apate.web.blueprints.
operations.cti_extract()`, la ruta AJAX que arma el JSON de
sugerencias para el formulario de nueva operacion."""

from .exceptions import CTIExtractionError
from .extraction import CTIExtractionResult, GroupMatch, TechniqueMatch, extract_candidates
from .readers import extract_text

__all__ = [
    "CTIExtractionError",
    "CTIExtractionResult",
    "GroupMatch",
    "TechniqueMatch",
    "extract_candidates",
    "extract_text",
]
