"""Instantáneas inmutables del YAML usado para reproducir decisiones."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from ..atomic_write import write_text_atomically
from ..file_lock import exclusive_file_lock
from .models import parse_rules

_REVISION_ID = re.compile(r"^[0-9a-f]{64}$")


class RuleRevisionRepository:
    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(self, text: str) -> str:
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        parse_rules(normalized)
        revision = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        path = self.directory / f"{revision}.yaml"
        with exclusive_file_lock(path.with_suffix(".lock")):
            if not path.exists():
                write_text_atomically(path, normalized)
            elif path.read_text(encoding="utf-8") != normalized:
                raise ValueError("La revisión de reglas no coincide con su huella.")
        return revision

    def get(self, revision: str) -> str:
        if not _REVISION_ID.fullmatch(revision):
            raise KeyError("Revisión de reglas inválida.")
        path = self.directory / f"{revision}.yaml"
        if not path.is_file():
            raise KeyError("Revisión de reglas inexistente.")
        text = path.read_text(encoding="utf-8")
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != revision:
            raise ValueError("La revisión de reglas fue modificada.")
        return text

    def list(self) -> list[str]:
        return [path.stem for path in sorted(self.directory.glob("*.yaml"),
                                             key=lambda path: path.stat().st_mtime, reverse=True)
                if _REVISION_ID.fullmatch(path.stem)]
