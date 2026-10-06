"""Lectura explícita de cobertura de activos por capacidades.

La relación vive en ``PluginBinding.protected_asset_ids`` y nunca se infiere
desde hostnames, rutas o texto libre: una capacidad concreta es quien afirma
que protege un activo. Un escenario puede agrupar muchas capacidades, pero no
puede por sí solo demostrar que alguna materializa esa protección.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..assets import Asset
from ..core import Operation, PluginBinding


_CRITICALITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build_asset_coverage(operation: Operation, inventory_assets: Iterable[Asset]) -> dict[str, object]:
    """Cruza los objetivos declarados con relaciones explícitas de capacidad.

    Los objetivos de texto libre se conservan como filas sin ficha. No se
    fabrica una criticidad ni se intenta adivinar su cobertura desde datos
    técnicos; la ausencia de relación es información que el mapa debe mostrar.
    """

    by_identifier = {asset.identifier: asset for asset in inventory_assets}
    targets: list[dict[str, object]] = []
    seen_references: set[str] = set()
    for reference in operation.adversary_profile.target_assets:
        if reference in seen_references:
            continue
        seen_references.add(reference)
        asset = by_identifier.get(reference)
        targets.append(
            {
                "reference": reference,
                "asset": asset,
                "label": asset.name if asset else reference,
                "criticality_order": _CRITICALITY_ORDER.get(asset.criticality, 4) if asset else 4,
                "bindings": [],
            }
        )

    targets_by_reference = {entry["reference"]: entry for entry in targets}
    unresolved_by_reference: dict[str, list[PluginBinding]] = {}
    for binding in operation.plugins:
        for reference in dict.fromkeys(binding.protected_asset_ids):
            target = targets_by_reference.get(reference)
            if target is not None:
                target["bindings"].append(binding)
            else:
                unresolved_by_reference.setdefault(reference, []).append(binding)

    target_sort_key = lambda entry: (entry["criticality_order"], str(entry["label"]).lower())
    covered = sorted((entry for entry in targets if entry["bindings"]), key=target_sort_key)
    uncovered = sorted((entry for entry in targets if not entry["bindings"]), key=target_sort_key)
    unassigned_capabilities = [binding for binding in operation.plugins if not binding.protected_asset_ids]
    unresolved_references = [
        {"reference": reference, "bindings": bindings}
        for reference, bindings in sorted(unresolved_by_reference.items(), key=lambda item: item[0].lower())
    ]

    return {
        "targets": sorted(targets, key=target_sort_key),
        "covered": covered,
        "uncovered": uncovered,
        "unassigned_capabilities": unassigned_capabilities,
        "unresolved_references": unresolved_references,
        "has_content": bool(targets or operation.plugins),
    }
