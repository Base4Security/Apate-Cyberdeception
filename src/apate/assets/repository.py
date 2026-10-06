"""Persistencia del inventario global de activos y de previsualizaciones CSV."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, Union

from .importer import AssetImportPreview
from .models import Asset
from ..atomic_write import write_text_atomically


class AssetNotFoundError(KeyError):
    """El identificador solicitado no pertenece al inventario."""


class AssetRepository(ABC):
    """Contrato para el inventario global, deliberadamente sin equipo."""

    @abstractmethod
    def save(self, asset: Asset) -> None:
        """Crea o actualiza un activo por su identificador estable."""

    @abstractmethod
    def get(self, identifier: str) -> Asset:
        """Devuelve un activo o levanta ``AssetNotFoundError``."""

    @abstractmethod
    def list(self) -> Iterator[Asset]:
        """Itera todos los activos, sin filtrar por operación ni equipo."""

    @abstractmethod
    def delete(self, identifier: str) -> None:
        """Elimina un activo o levanta ``AssetNotFoundError``."""


class JSONFileAssetRepository(AssetRepository):
    """Un archivo JSON legible por activo, sin dependencias adicionales."""

    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, identifier: str) -> Path:
        # El identificador es un dato externo; el hash evita convertirlo en
        # una ruta y no introduce colisiones por reemplazar caracteres.
        digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
        return self._dir / f"{digest}.json"

    def save(self, asset: Asset) -> None:
        write_text_atomically(self._path_for(asset.identifier), json.dumps(asset.to_dict(), indent=2, ensure_ascii=False))

    def get(self, identifier: str) -> Asset:
        path = self._path_for(identifier)
        if not path.exists():
            raise AssetNotFoundError(identifier)
        return Asset.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list(self) -> Iterator[Asset]:
        assets = [Asset.from_dict(json.loads(path.read_text(encoding="utf-8"))) for path in self._dir.glob("*.json")]
        yield from sorted(assets, key=lambda asset: asset.identifier)

    def delete(self, identifier: str) -> None:
        path = self._path_for(identifier)
        if not path.exists():
            raise AssetNotFoundError(identifier)
        path.unlink()


class JSONFileAssetImportPreviewRepository:
    """Guarda una previsualización hasta que el operador confirme importar.

    La separación permite informar todos los descartes antes de escribir un
    solo activo. Estas previsualizaciones no son parte del inventario.
    """

    def __init__(self, directory: Union[str, Path]):
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, token: str) -> Path:
        if not token.isascii() or not token.isalnum():
            raise AssetNotFoundError(token)
        return self._dir / f"{token}.json"

    def save(self, preview: AssetImportPreview) -> None:
        write_text_atomically(self._path_for(preview.token), json.dumps(preview.to_dict(), indent=2, ensure_ascii=False))

    def get(self, token: str) -> AssetImportPreview:
        path = self._path_for(token)
        if not path.exists():
            raise AssetNotFoundError(token)
        return AssetImportPreview.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def delete(self, token: str) -> None:
        path = self._path_for(token)
        if not path.exists():
            raise AssetNotFoundError(token)
        path.unlink()
