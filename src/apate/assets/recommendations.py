"""Sugerencias deterministas de colocación para activos inventariados.

El mapa ``asset_type -> kind`` vive en
``apate/data/asset_placement_suggestions.json`` y es un juicio
interpretativo de APATE, no una extracción de una fuente oficial. El tipo de
activo es texto libre: la función solo reconoce las etiquetas literales que
el dataset declara y devuelve una lista vacía para cualquier otra. Nunca crea
un binding, no despliega plugins y no establece una prioridad entre las
sugerencias; el operador conserva la decisión y la aplicación manual.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..plugins import PluginDescription, PluginRegistry
from .models import Asset


_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "asset_placement_suggestions.json"


def _load_suggestion_data() -> dict[str, dict[str, list[str]]]:
    """Carga el dataset propio una sola vez al importar este módulo."""

    return json.loads(_DATA_PATH.read_text(encoding="utf-8"))


_SUGGESTION_DATA = _load_suggestion_data()


def suggest_capabilities_for_asset(asset: Asset) -> list[PluginDescription]:
    """Devuelve capacidades registradas que pueden servir para ``asset``.

    La coincidencia es literal tras ``strip().casefold()``; no convierte el
    campo libre ``asset_type`` en una taxonomía nueva. La criticidad puede
    sumar alternativas documentadas por el dataset, pero el resultado no se
    ordena por riesgo, confianza ni conveniencia. Los kinds que el dataset
    nombra y esta instalación no registra se omiten para que una sugerencia
    nunca prometa una capacidad inexistente.
    """

    asset_type = asset.asset_type.strip().casefold()
    base_kinds = _SUGGESTION_DATA["asset_type_kind_map"].get(asset_type)
    if base_kinds is None:
        return []

    candidate_kinds = list(
        dict.fromkeys(
            base_kinds + _SUGGESTION_DATA["criticality_kind_additions"].get(asset.criticality, [])
        )
    )
    registered_kinds = set(PluginRegistry.list_kinds())
    return [PluginRegistry.describe(kind) for kind in candidate_kinds if kind in registered_kinds]


def list_suggestible_asset_types() -> list[str]:
    """Tipos de activo que hoy producen alguna sugerencia de colocación.

    `Asset.asset_type` es texto libre y sigue siéndolo: esta lista no lo
    restringe ni lo normaliza. Existe para que la pantalla del inventario
    pueda mostrar cuáles son las etiquetas reconocidas, en vez de dejar al
    operador descubrir por ausencia que "servicio" no produce nada mientras
    "servidor" sí. La fuente es el dataset, no una copia: mantener la lista a
    mano en la plantilla es exactamente lo que dejó divergir el vocabulario de
    la criticidad entre el CSV y la interfaz.
    """

    return sorted(_SUGGESTION_DATA["asset_type_kind_map"])
