"""Inventario persistente de destinos alcanzables por conectores."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..atomic_write import write_json_atomically
from ..file_lock import exclusive_file_lock
from ..i18n import gettext as _
from .exceptions import DeploymentNotFoundError, DeploymentValidationError
from .models import DeploymentTarget

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class JSONFileDeploymentTargetRepository:
    """Guarda destinos sin secretos; cada plan conserva su propia instantánea."""

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)

    def _path(self, target_id: str) -> Path:
        if not _SAFE_ID.fullmatch(target_id):
            raise DeploymentValidationError(_("Identificador de destino inválido."))
        return self._directory / f"{target_id}.json"

    def save(self, target: DeploymentTarget) -> None:
        self._validate_no_secrets(target)
        path = self._path(target.id)
        with exclusive_file_lock(path.with_suffix(".lock")):
            if path.is_file():
                previous = DeploymentTarget.from_dict(json.loads(path.read_text(encoding="utf-8")))
                if target.revision != previous.revision + 1:
                    raise DeploymentValidationError(_("La revisión del destino cambió; volvé a cargarlo antes de guardar."))
                history = self._directory / "history" / target.id / f"{previous.revision}.json"
                write_json_atomically(history, previous.to_dict())
            elif target.revision != 1:
                raise DeploymentValidationError(_("Un destino nuevo debe comenzar en la revisión 1."))
            write_json_atomically(path, target.to_dict())

    def history(self, target_id: str) -> list[DeploymentTarget]:
        """Instantáneas anteriores, sin alterar los planes ya confirmados."""

        self._path(target_id)
        directory = self._directory / "history" / target_id
        return [DeploymentTarget.from_dict(json.loads(path.read_text(encoding="utf-8")))
                for path in sorted(directory.glob("*.json"), key=lambda path: int(path.stem))]

    def get(self, target_id: str) -> DeploymentTarget:
        path = self._path(target_id)
        if not path.is_file():
            raise DeploymentNotFoundError(
                _("No existe el destino de despliegue '%(target_id)s'.", target_id=target_id)
            )
        return DeploymentTarget.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self) -> list[DeploymentTarget]:
        return [
            DeploymentTarget.from_dict(json.loads(path.read_text(encoding="utf-8")))
            for path in sorted(self._directory.glob("*.json"))
        ]

    @staticmethod
    def _validate_no_secrets(target: DeploymentTarget) -> None:
        forbidden = {"password", "secret", "token", "credential"}
        for key in target.config:
            normalized = str(key).casefold()
            if any(fragment in normalized for fragment in forbidden):
                raise DeploymentValidationError(
                    _("La configuración del destino no puede contener secretos; usá credential_ref.")
                )
