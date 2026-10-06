"""Lectura y validación previa de CSV para el inventario de activos."""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..cti.readers import MAX_UPLOAD_BYTES
from ..i18n import gettext as _
from .models import Asset, AssetValidationError


class AssetImportError(ValueError):
    """El archivo entero no cumple el formato CSV esperado."""


@dataclass(frozen=True)
class AssetImportIssue:
    """Una fila que no se importará, con su número y motivo."""

    row_number: int
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"row_number": self.row_number, "reason": self.reason}

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "AssetImportIssue":
        return cls(row_number=int(data["row_number"]), reason=str(data["reason"]))


@dataclass(frozen=True)
class AssetImportPreview:
    """Resultado completo que se presenta antes de persistir el CSV."""

    token: str
    assets: tuple[Asset, ...]
    issues: tuple[AssetImportIssue, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "token": self.token,
            "assets": [asset.to_dict() for asset in self.assets],
            "issues": [issue.to_dict() for issue in self.issues],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "AssetImportPreview":
        return cls(
            token=str(data["token"]),
            assets=tuple(Asset.from_dict(item) for item in data.get("assets", [])),
            issues=tuple(AssetImportIssue.from_dict(item) for item in data.get("issues", [])),
        )


class CSVAssetImporter:
    """Valida el archivo entero sin escribir; la confirmación se hace aparte."""

    _REQUIRED_COLUMNS = {"identifier", "name", "asset_type", "criticality"}

    def preview(self, filename: str, data: bytes) -> AssetImportPreview:
        if not data:
            raise AssetImportError(_("El archivo está vacío."))
        if len(data) > MAX_UPLOAD_BYTES:
            raise AssetImportError(
                _(
                    "El archivo supera el tamaño máximo soportado (%(mb)s MB).",
                    mb=MAX_UPLOAD_BYTES // (1024 * 1024),
                )
            )
        if Path(filename).suffix.lower() != ".csv":
            raise AssetImportError(_("Formato no soportado: el inventario admite solo archivos .csv."))
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise AssetImportError(_("El CSV debe estar codificado en UTF-8.")) from exc

        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise AssetImportError(_("El CSV no tiene una fila de encabezados."))
        headers = [header.strip() if header else "" for header in reader.fieldnames]
        if len(set(headers)) != len(headers):
            raise AssetImportError(_("El CSV tiene encabezados duplicados."))
        missing = self._REQUIRED_COLUMNS - set(headers)
        if missing:
            raise AssetImportError(
            _("Faltan columnas obligatorias: %(columnas)s.", columnas=", ".join(sorted(missing)))
        )

        assets: list[Asset] = []
        issues: list[AssetImportIssue] = []
        identifiers: set[str] = set()
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                issues.append(AssetImportIssue(row_number, "tiene más columnas que el encabezado."))
                continue
            normalized = {key.strip(): (value or "").strip() for key, value in row.items()}
            if not any(normalized.values()):
                issues.append(AssetImportIssue(row_number, "está vacía."))
                continue
            try:
                asset = Asset(
                    identifier=normalized.get("identifier", ""),
                    name=normalized.get("name", ""),
                    asset_type=normalized.get("asset_type", ""),
                    criticality=normalized.get("criticality", ""),
                    technical_identifier=normalized.get("technical_identifier", ""),
                )
            except AssetValidationError as exc:
                issues.append(AssetImportIssue(row_number, str(exc)))
                continue
            if asset.identifier in identifiers:
                issues.append(AssetImportIssue(row_number, "repite un identificador ya presente en el archivo."))
                continue
            identifiers.add(asset.identifier)
            assets.append(asset)

        return AssetImportPreview(token=uuid.uuid4().hex, assets=tuple(assets), issues=tuple(issues))
