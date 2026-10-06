"""Configuracion local para el envio manual de bundles STIX a SIEM/SOAR."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union
from ..atomic_write import write_text_atomically


class SiemSoarConfigRepository:
    """Guarda el destino global y su token sin exponerlo al template."""

    def __init__(self, path: Union[str, Path]):
        self._path = Path(path)

    def load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return {
            "webhook_url": str(data.get("webhook_url", "")),
            "auth_token": str(data.get("auth_token", "")),
        }

    def save(self, webhook_url: str, auth_token: str) -> None:
        write_text_atomically(
            self._path,
            json.dumps({"webhook_url": webhook_url, "auth_token": auth_token}, indent=2),
        )
