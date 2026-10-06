"""Inventario global de activos de APATE.

Los activos describen infraestructura compartida, no secretos operacionales:
no se aíslan por equipo ni se copian al crear una operación. Las operaciones
solo conservan sus identificadores como texto en ``target_assets`` para no
alterar el contrato histórico del núcleo.
"""

from .importer import AssetImportError, AssetImportPreview, CSVAssetImporter
from .models import Asset, AssetValidationError, CRITICALITY_LABELS, normalize_criticality
from .recommendations import list_suggestible_asset_types, suggest_capabilities_for_asset
from .repository import (
    AssetNotFoundError,
    AssetRepository,
    JSONFileAssetImportPreviewRepository,
    JSONFileAssetRepository,
)

__all__ = [
    "CRITICALITY_LABELS",
    "normalize_criticality",
    "list_suggestible_asset_types",
    "suggest_capabilities_for_asset",
    "Asset",
    "AssetImportError",
    "AssetImportPreview",
    "AssetNotFoundError",
    "AssetRepository",
    "AssetValidationError",
    "CSVAssetImporter",
    "JSONFileAssetImportPreviewRepository",
    "JSONFileAssetRepository",
]
