"""Persistencia local de planes y registros de despliegue."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from ..i18n import gettext as _
from ..atomic_write import write_json_atomically
from .exceptions import DeploymentNotFoundError, DeploymentValidationError
from .models import DeploymentPlan, DeploymentRecord


class DeploymentRepository(ABC):
    @abstractmethod
    def save_plan(self, plan: DeploymentPlan) -> None: ...

    @abstractmethod
    def get_plan(self, plan_id: str) -> DeploymentPlan: ...

    @abstractmethod
    def save_record(self, record: DeploymentRecord) -> None: ...

    @abstractmethod
    def get_record(self, record_id: str) -> DeploymentRecord: ...

    @abstractmethod
    def find_record_for_plan(self, plan_id: str) -> Optional[DeploymentRecord]: ...

    @abstractmethod
    def list_records_for_operation(self, operation_id: str) -> list[DeploymentRecord]: ...

    @abstractmethod
    def list_plans_for_operation(self, operation_id: str) -> list[DeploymentPlan]: ...


class JSONFileDeploymentRepository(DeploymentRepository):
    """Un archivo por plan y por registro, con reemplazo atómico local."""

    def __init__(self, directory: Path) -> None:
        self._plans = Path(directory) / "plans"
        self._records = Path(directory) / "records"
        self._plans.mkdir(parents=True, exist_ok=True)
        self._records.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _path(directory: Path, identifier: str) -> Path:
        # Estos identificadores terminarán formando parte de URLs. Aunque los
        # IDs propios son UUID, un conector o cliente futuro puede suministrar
        # uno malicioso: se valida antes de convertirlo en ruta.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", identifier):
            raise DeploymentValidationError(_("Identificador de despliegue inválido."))
        return directory / f"{identifier}.json"

    @staticmethod
    def _write(path: Path, data: dict) -> None:
        write_json_atomically(path, data)

    def save_plan(self, plan: DeploymentPlan) -> None:
        self._write(self._path(self._plans, plan.id), plan.to_dict())

    def get_plan(self, plan_id: str) -> DeploymentPlan:
        path = self._path(self._plans, plan_id)
        if not path.is_file():
            raise DeploymentNotFoundError(_("No existe el plan de despliegue '%(plan_id)s'.", plan_id=plan_id))
        return DeploymentPlan.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def save_record(self, record: DeploymentRecord) -> None:
        self._write(self._path(self._records, record.id), record.to_dict())

    def get_record(self, record_id: str) -> DeploymentRecord:
        path = self._path(self._records, record_id)
        if not path.is_file():
            raise DeploymentNotFoundError(
                _("No existe el registro de despliegue '%(record_id)s'.", record_id=record_id)
            )
        return DeploymentRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def _records_iter(self):
        for path in sorted(self._records.glob("*.json")):
            yield DeploymentRecord.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def find_record_for_plan(self, plan_id: str) -> Optional[DeploymentRecord]:
        return next((record for record in self._records_iter() if record.plan_id == plan_id), None)

    def list_records_for_operation(self, operation_id: str) -> list[DeploymentRecord]:
        return [record for record in self._records_iter() if record.operation_id == operation_id]

    def list_plans_for_operation(self, operation_id: str) -> list[DeploymentPlan]:
        plans = (
            DeploymentPlan.from_dict(json.loads(path.read_text(encoding="utf-8")))
            for path in sorted(self._plans.glob("*.json"))
        )
        return [plan for plan in plans if plan.operation_id == operation_id]
