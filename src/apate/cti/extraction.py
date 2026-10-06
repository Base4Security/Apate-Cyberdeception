"""Matching determinista de TTPs/grupos contra el catalogo curado de
apate.attack, a partir del texto plano de un informe de CTI -- Fase 6
post-BlackHat (ver docs/roadmap.md), cierra el placeholder de M12k.

**Deliberadamente sin LLM.** El motor de decision de APATE es
determinista y auditable por diseno (documento de diseno, seccion 8:
"evitar dependencia de LLM para decisiones de despliegue") -- esa
misma filosofia se extiende aca, a la extraccion en si, no solo a la
aplicacion de sus resultados. El matching es basico a proposito (ID de
tecnica por regex, nombre de tecnica/grupo por coincidencia de
palabra completa) y puede tener falsos positivos (nombres de tecnica
genericos mencionados sin relacion real con un TTP observado) y falsos
negativos (parafraseo, sinonimos, texto en otro idioma) reales -- por
eso el resultado es SIEMPRE una sugerencia que el operador revisa y
aplica a mano desde el formulario (mismo criterio de "asistir, nunca
decidir" que ya usan `apate.engage.suggest_activities()`, M12d, y la
Fase 3 de este mismo backlog de mejoras post-BlackHat) -- nunca se
aplica solo, y `extract_candidates()` no tiene ningun efecto
secundario (no toca `AdversaryProfile` ni ningun otro modelo)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..attack import Group, Technique, list_groups, list_techniques

# Tecnica de MITRE ATT&CK: "T" + 4 digitos, con sub-tecnica opcional
# ("T1059" o "T1059.004"). El catalogo curado de apate.attack solo
# tiene tecnicas de nivel padre (ver apate.attack.catalog) -- una
# sub-tecnica mencionada en el informe se normaliza a su padre.
_TECHNIQUE_ID_PATTERN = re.compile(r"\bT(\d{4})(?:\.\d{3})?\b", re.IGNORECASE)


@dataclass(frozen=True)
class TechniqueMatch:
    """Una tecnica del catalogo curado encontrada en el texto.
    `matched_via` distingue como se encontro -- transparencia para el
    operador, no un detalle interno: "id" (referencia directa tipo
    T1566[.001]) o "name" (nombre de la tecnica mencionado en prosa,
    sin su id). `raw_match` conserva el fragmento textual exacto
    encontrado, que puede diferir de `technique.id` cuando el informe
    menciona una sub-tecnica normalizada a su padre."""

    technique: Technique
    matched_via: str
    raw_match: str


@dataclass(frozen=True)
class GroupMatch:
    """Un grupo del catalogo curado encontrado en el texto, por su
    nombre canonico o uno de sus alias. `raw_match` es el nombre/alias
    exacto que aparecio en el texto -- puede no ser `group.name` (ej.
    "Fancy Bear" en vez de "APT28")."""

    group: Group
    raw_match: str


@dataclass(frozen=True)
class CTIExtractionResult:
    technique_matches: list[TechniqueMatch]
    group_matches: list[GroupMatch]


def _find_technique_ids(text: str) -> list[TechniqueMatch]:
    catalog = {technique.id: technique for technique in list_techniques()}
    seen: set[str] = set()
    matches: list[TechniqueMatch] = []
    for found in _TECHNIQUE_ID_PATTERN.finditer(text):
        parent_id = "T" + found.group(1)
        technique = catalog.get(parent_id)
        if technique is None or technique.id in seen:
            continue  # id fuera del catalogo curado, o ya encontrado antes
        seen.add(technique.id)
        matches.append(TechniqueMatch(technique=technique, matched_via="id", raw_match=found.group(0)))
    return matches


def _find_technique_names(text: str, already_matched: set[str]) -> list[TechniqueMatch]:
    matches: list[TechniqueMatch] = []
    for technique in list_techniques():
        if technique.id in already_matched:
            continue  # ya sugerida por id, no duplicar por nombre
        pattern = re.compile(r"\b" + re.escape(technique.name) + r"\b", re.IGNORECASE)
        found = pattern.search(text)
        if found:
            matches.append(TechniqueMatch(technique=technique, matched_via="name", raw_match=found.group(0)))
    return matches


def _find_groups(text: str) -> list[GroupMatch]:
    matches: list[GroupMatch] = []
    for group in list_groups():
        for candidate in (group.name, *group.aliases):
            pattern = re.compile(r"\b" + re.escape(candidate) + r"\b", re.IGNORECASE)
            found = pattern.search(text)
            if found:
                matches.append(GroupMatch(group=group, raw_match=found.group(0)))
                break  # un match por grupo alcanza -- no hace falta probar cada alias restante
    return matches


def extract_candidates(text: str) -> CTIExtractionResult:
    """Punto de entrada del matching determinista -- ver docstring del
    modulo. `text` ya es texto plano (`apate.cti.readers.extract_text()`
    lo resuelve a partir del archivo cargado; esta funcion no sabe ni
    le importa de que formato de archivo vino)."""

    id_matches = _find_technique_ids(text)
    already_matched = {match.technique.id for match in id_matches}
    name_matches = _find_technique_names(text, already_matched)

    return CTIExtractionResult(
        technique_matches=id_matches + name_matches,
        group_matches=_find_groups(text),
    )
