"""Catalogo de MITRE ATT&CK (M12j) - ver docs/analisis-engage-integral.md.

Dataset propio en `apate/data/mitre_attack_groups.json` (mismo patron
que `apate.rules` con YAML editable o `apate.playground` reutilizando
el repo real del Playground: los datos externos viven en un archivo de
datos versionado, no hardcodeados en codigo Python) -- subconjunto
curado a proposito (41 tecnicas, 4 grupos), no las ~150 tecnicas/grupos
completos de ATT&CK; ver el campo `_meta` del propio JSON para el nivel
de verificacion de cada grupo contra los Navigator layer JSON reales de
MITRE (APT29/G0016 y Lazarus Group/G0032 estan marcados como
verificacion "parcial", no "completa" como APT28/G0007 y FIN7/G0046).

Catalogo de solo lectura: a diferencia de `apate.core.models`, estos
dataclasses no tienen to_dict()/from_dict() -- no se persisten ni se
serializan a JSON de operacion, se cargan una vez desde el archivo de
datos (al importar este modulo, no en cada request) y se consultan en
memoria."""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_groups.json"


def catalog_provenance() -> dict[str, str]:
    """Identifica la versión y el contenido exacto del catálogo curado."""
    content = _DATA_PATH.read_bytes()
    meta = json.loads(content)["_meta"]
    return {"schema_version": str(meta["schema_version"]), "source": str(meta["source"]),
            "sha256": hashlib.sha256(content).hexdigest()}


@dataclass(frozen=True)
class Technique:
    """Una tecnica de nivel padre de MITRE ATT&CK (Enterprise). Sin
    sub-tecnicas -- ver `_meta.note` del dataset sobre por que."""

    id: str
    name: str
    tactic: str


@dataclass(frozen=True)
class Group:
    """Un grupo (actor de amenaza) de MITRE ATT&CK, con las tecnicas
    que se le atribuyen. `verification` es el nivel de confianza con el
    que se verifico `technique_ids` contra la fuente real (ver
    `_meta.note` del dataset) -- se expone tal cual, no se oculta."""

    id: str
    name: str
    aliases: list[str]
    description: str
    technique_ids: list[str]
    verification: str


def _load() -> tuple[list[Technique], list[Group]]:
    data = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
    techniques = [
        Technique(id=entry["id"], name=entry["name"], tactic=entry["tactic"]) for entry in data["techniques"]
    ]
    groups = [
        Group(
            id=entry["id"],
            name=entry["name"],
            aliases=list(entry.get("aliases", [])),
            description=entry.get("description", ""),
            technique_ids=list(entry.get("technique_ids", [])),
            verification=entry.get("verification", ""),
        )
        for entry in data["groups"]
    ]
    return techniques, groups


# Cargado una sola vez al importar el modulo -- ver docstring del
# modulo y el punto 1 del hito ("no en cada request").
_TECHNIQUES, _GROUPS = _load()


def list_techniques(tactic: Optional[str] = None) -> list[Technique]:
    """Todas las tecnicas del catalogo, o solo las de `tactic` (ej.
    "credential-access") si se pasa. Devuelve una copia de la lista
    cacheada -- quien la reciba no puede mutar el catalogo compartido."""

    if tactic is None:
        return list(_TECHNIQUES)
    return [technique for technique in _TECHNIQUES if technique.tactic == tactic]


def list_groups() -> list[Group]:
    """Los 4 grupos del catalogo. Copia de la lista cacheada, mismo
    criterio que `list_techniques()`."""

    return list(_GROUPS)


def get_group(group_id: str) -> Optional[Group]:
    """El grupo con ese id (ej. "G0007"), o `None` si no existe en el
    catalogo -- nunca lanza."""

    for group in _GROUPS:
        if group.id == group_id:
            return group
    return None
