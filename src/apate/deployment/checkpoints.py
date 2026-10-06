"""Checkpoint persistente para sondeo incremental de eventos de honeyusers."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..i18n import gettext as _
from ..atomic_write import write_json_atomically
from .exceptions import DeploymentValidationError

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class JSONFileHoneyuserCheckpointRepository:
    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)

    def _path(self, record_id: str) -> Path:
        if not _SAFE_ID.fullmatch(record_id):
            raise DeploymentValidationError(_("Identificador de checkpoint inválido."))
        return self._directory / f"{record_id}.json"

    def get(self, record_id: str) -> int:
        return self.get_state(record_id)[0]

    def get_state(self, record_id: str) -> tuple[int, int]:
        """El segundo valor distingue reinicios del Security log."""

        path = self._path(record_id)
        if not path.is_file():
            return 0, 0
        data = json.loads(path.read_text(encoding="utf-8"))
        return max(0, int(data["event_record_id"])), max(0, int(data.get("generation", 0)))

    def save(self, record_id: str, event_record_id: int) -> None:
        self.save_state(record_id, event_record_id, self.get_state(record_id)[1])

    def save_state(self, record_id: str, event_record_id: int, generation: int) -> None:
        if event_record_id < 0:
            raise DeploymentValidationError(_("El EventRecordID no puede ser negativo."))
        if generation < 0:
            raise DeploymentValidationError("La generación del Security log no puede ser negativa.")
        path = self._path(record_id)
        write_json_atomically(path, {"event_record_id": int(event_record_id), "generation": int(generation)})
