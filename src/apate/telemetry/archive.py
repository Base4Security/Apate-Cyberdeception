"""Exportación verificable de evidencia por operación, sin alterar el origen."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from ..atomic_write import write_text_atomically
from .models import TelemetryRecord


def export_operation_evidence(repository, operation_id: str, directory: str | Path) -> dict:
    """Crea un JSONL y manifiesto SHA-256 reproducibles de una operación."""
    if not operation_id or "/" in operation_id or "\\" in operation_id or ".." in operation_id:
        raise ValueError("Identificador de operación inválido.")
    records = repository.list_for_operation(operation_id)
    output = Path(directory)
    output.mkdir(parents=True, exist_ok=True)
    content = "".join(
        json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    )
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    filename = f"{operation_id}-{digest[:16]}.jsonl"
    manifest = {
        "schema": "apate.telemetry.archive.v1",
        "operation_id": operation_id,
        "record_count": len(records),
        "sha256": digest,
        "file": filename,
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    write_text_atomically(output / filename, content)
    write_text_atomically(output / f"{filename}.manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
    return manifest


def verify_operation_evidence(directory: str | Path, manifest_name: str) -> list[TelemetryRecord]:
    """Comprueba el hash, el conteo y el alcance antes de importar evidencia."""
    if Path(manifest_name).name != manifest_name:
        raise ValueError("Nombre de manifiesto inválido.")
    base = Path(directory)
    manifest = json.loads((base / manifest_name).read_text(encoding="utf-8"))
    if manifest.get("schema") != "apate.telemetry.archive.v1":
        raise ValueError("Versión de archivo incompatible.")
    filename = manifest.get("file", "")
    if Path(filename).name != filename or not filename.endswith(".jsonl"):
        raise ValueError("Nombre de archivo inválido.")
    content = (base / filename).read_bytes()
    if hashlib.sha256(content).hexdigest() != manifest.get("sha256"):
        raise ValueError("La evidencia no coincide con su hash.")
    records = [TelemetryRecord.from_dict(json.loads(line)) for line in content.decode("utf-8").splitlines()]
    if len(records) != manifest.get("record_count") or any(
        record.operation_id != manifest.get("operation_id") for record in records
    ):
        raise ValueError("El alcance o conteo de evidencia es inconsistente.")
    return records
