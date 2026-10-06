"""Conector de honeyfiles en filesystem local o share SMB montado."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from ..atomic_write import write_json_atomically, write_text_atomically
from ..file_lock import exclusive_file_lock
from .connector import ConnectorManifest, DeploymentConnector
from .exceptions import DeploymentExecutionError, DeploymentValidationError
from .models import ConnectorResult, DeploymentAction, DeploymentPlan, DeploymentRecord, DeploymentStatus, DeploymentTarget, PlannedChange


class FilesystemHoneyfileConnector(DeploymentConnector):
    """Solo toca archivos que su recibo externo al señuelo acredita."""

    kind = "filesystem-honeyfile"
    manifest = ConnectorManifest(kind=kind, contract_version=2,
        actions=frozenset({"deploy", "rotate", "retire"}),
        observations=frozenset({"status"}))

    def __init__(self, receipt_directory: Path | str) -> None:
        self.receipts = Path(receipt_directory)
        self.receipts.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _path(target: DeploymentTarget, configuration: dict[str, Any]) -> Path:
        declared_root = Path(target.address)
        if not declared_root.is_dir() or declared_root.is_symlink():
            raise DeploymentValidationError("El directorio del destino no existe o es un enlace simbólico.")
        root = declared_root.resolve()
        relative = Path(str(configuration.get("relative_path", "")))
        if relative.is_absolute() or not relative.parts or any(part in {"..", "."} for part in relative.parts):
            raise DeploymentValidationError("La ruta del honeyfile debe ser relativa y estar dentro del destino.")
        allowed = [Path(value) for value in target.config.get("allowed_subdirs", ["."])]
        if not allowed or any(directory.is_absolute() or ".." in directory.parts for directory in allowed):
            raise DeploymentValidationError("Los subdirectorios autorizados deben ser rutas relativas.")
        if not any(relative.parent == directory or directory in relative.parent.parents or directory == Path(".") for directory in allowed):
            raise DeploymentValidationError("La ruta no pertenece a un subdirectorio autorizado.")
        path = root / relative
        parent = path.parent
        if root not in path.resolve().parents or not parent.is_dir() or path.is_symlink():
            raise DeploymentValidationError("La ruta escapa del destino o atraviesa un enlace simbólico.")
        while parent != root:
            if parent.is_symlink():
                raise DeploymentValidationError("La ruta no puede atravesar enlaces simbólicos.")
            parent = parent.parent
        return path

    @staticmethod
    def _content(configuration: dict[str, Any], key: str = "content") -> str:
        content = configuration.get(key, "")
        if not isinstance(content, str) or not content or len(content.encode("utf-8")) > 1024 * 1024:
            raise DeploymentValidationError("El contenido del honeyfile debe tener entre 1 byte y 1 MiB.")
        return content

    def validate(self, target: DeploymentTarget, configuration: dict[str, Any]) -> None:
        self._path(target, configuration)
        self._content(configuration)
        if configuration.get("rotation_content"):
            self._content(configuration, "rotation_content")

    def plan(self, *, operation_id: str, plugin_id: str, target: DeploymentTarget,
             configuration: dict[str, Any]) -> DeploymentPlan:
        self.validate(target, configuration)
        path = self._path(target, configuration)
        if path.exists():
            raise DeploymentValidationError("Ya existe un archivo en la ruta declarada; no se adopta un recurso ajeno.")
        content = self._content(configuration)
        parameters = {"relative_path": str(configuration["relative_path"]), "content": content,
                      "rotation_content": str(configuration.get("rotation_content", ""))}
        return DeploymentPlan(operation_id=operation_id, plugin_id=plugin_id, target=target,
                              changes=[PlannedChange(DeploymentAction.CREATE, "honeyfile", str(path),
                                                     "Crear un honeyfile en la ruta autorizada.")], parameters=parameters)

    def _receipt_path(self, plan: DeploymentPlan) -> Path:
        return self.receipts / f"{plan.id}.json"

    @staticmethod
    def _digest(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _receipt(self, plan: DeploymentPlan) -> dict | None:
        path = self._receipt_path(plan)
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None

    def _write_receipt(self, plan: DeploymentPlan, path: Path, digest: str, status: str) -> None:
        write_json_atomically(self._receipt_path(plan), {"plan_id": plan.id, "path": str(path),
                                                     "sha256": digest, "status": status}, mode=0o600)

    def _verified_path(self, plan: DeploymentPlan) -> Path:
        path = self._path(plan.target, plan.parameters)
        receipt = self._receipt(plan)
        if not receipt or receipt.get("plan_id") != plan.id or receipt.get("path") != str(path):
            raise DeploymentExecutionError("No existe un recibo de propiedad válido para el honeyfile.")
        return path

    def deploy(self, plan: DeploymentPlan) -> ConnectorResult:
        path = self._path(plan.target, plan.parameters)
        content = self._content(plan.parameters)
        with exclusive_file_lock(self._receipt_path(plan).with_suffix(".lock")):
            receipt = self._receipt(plan)
            if path.exists():
                if not receipt or receipt.get("sha256") != self._digest(content) or hashlib.sha256(path.read_bytes()).hexdigest() != receipt["sha256"]:
                    raise DeploymentExecutionError("El archivo existente no pertenece a este plan o cambió.")
            else:
                created = False
                try:
                    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    created = True
                    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                except FileExistsError as exc:
                    raise DeploymentExecutionError("El archivo apareció después de preparar el plan; no se sobrescribe.") from exc
                except Exception:
                    if created:
                        path.unlink(missing_ok=True)
                    raise
                self._write_receipt(plan, path, self._digest(content), "active")
        return ConnectorResult(DeploymentStatus.ACTIVE, "Honeyfile creado y verificado.", [str(path)])

    def status(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        path = self._verified_path(plan)
        receipt = self._receipt(plan)
        if receipt["status"] == "retired" and not path.exists():
            return ConnectorResult(DeploymentStatus.RETIRED, "Honeyfile retirado.", [str(path)])
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != receipt["sha256"]:
            return ConnectorResult(DeploymentStatus.DEGRADED, "Honeyfile ausente o modificado fuera de APATE.", [str(path)])
        return ConnectorResult(DeploymentStatus.ACTIVE, "Honeyfile presente y verificado.", [str(path)])

    def rotate(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        path = self._verified_path(plan)
        replacement = self._content(plan.parameters, "rotation_content")
        with exclusive_file_lock(self._receipt_path(plan).with_suffix(".lock")):
            if self.status(record, plan).status is not DeploymentStatus.ACTIVE:
                raise DeploymentExecutionError("El honeyfile cambió; no se rota un recurso ajeno.")
            write_text_atomically(path, replacement)
            self._write_receipt(plan, path, self._digest(replacement), "active")
        return ConnectorResult(DeploymentStatus.ACTIVE, "Contenido señuelo rotado.", [str(path)])

    def retire(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        path = self._verified_path(plan)
        with exclusive_file_lock(self._receipt_path(plan).with_suffix(".lock")):
            if self.status(record, plan).status is not DeploymentStatus.ACTIVE:
                raise DeploymentExecutionError("El honeyfile cambió; no se elimina un recurso ajeno.")
            path.unlink()
            self._write_receipt(plan, path, self._receipt(plan)["sha256"], "retired")
        return ConnectorResult(DeploymentStatus.RETIRED, "Honeyfile retirado.", [str(path)])
