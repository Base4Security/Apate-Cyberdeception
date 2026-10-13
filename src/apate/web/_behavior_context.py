"""Servicios compartidos para importar contexto de comportamiento."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Optional

from BUDA.utils.context_utils import extract_ueba_from_evtx as _extract_ueba_from_evtx
from Evtx.Evtx import Evtx
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from ..core import BehaviorContextSource, JSONFileBehaviorContextRepository
from ..i18n import gettext as _

MAX_EVTX_BYTES = 50 * 1024 * 1024


def save_evtx_upload(file: FileStorage, directory: Path) -> tuple[Path, str]:
    """Valida y guarda temporalmente un EVTX con límite explícito."""

    original_name = file.filename or ""
    safe_name = secure_filename(original_name)
    if not safe_name or Path(safe_name).suffix.lower() != ".evtx":
        raise ValueError(_("Seleccioná un archivo con extensión .evtx."))
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{uuid.uuid4()}-{safe_name}"
    file.save(path)
    if path.stat().st_size > MAX_EVTX_BYTES:
        path.unlink(missing_ok=True)
        raise ValueError(_("El archivo EVTX supera el límite de 50 MiB."))
    return path, original_name


def count_evtx_records(path: Path) -> int:
    """Cuenta registros para conservar el progreso SSE heredado."""

    with Evtx(str(path)) as log:
        return sum(1 for _ in log.records())


def extract_candidate(
    path: Path,
    *,
    original_name: str,
    name: str,
    repository: JSONFileBehaviorContextRepository,
    pending_operation_id: Optional[str] = None,
) -> BehaviorContextSource:
    """Extrae y persiste un candidato; nunca lo confirma ni lo aplica."""

    extracted = _extract_ueba_from_evtx(str(path))
    # Verifica de inmediato que el proveedor entregó una forma JSON
    # serializable antes de registrar la huella de integridad.
    if not isinstance(extracted, dict):
        raise ValueError(_("El extractor no devolvió un objeto de contexto válido."))
    json.dumps(extracted, ensure_ascii=False, sort_keys=True)
    source = BehaviorContextSource(
        name=name.strip() or Path(original_name).stem,
        data=extracted,
        provenance=f"EVTX:{original_name}",
        origin_filename=original_name,
        pending_operation_id=pending_operation_id,
    )
    repository.save(source)
    return source
