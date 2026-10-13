"""Mapa de activos: cobertura declarada, sin inferencia de texto técnico."""

from apate.assets import Asset
from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.web._asset_coverage import build_asset_coverage


def _operation(**kwargs):
    return Operation(
        name="Operación de cobertura",
        adversary_profile=kwargs.pop("adversary_profile", AdversaryProfile(name="Actor")),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
        **kwargs,
    )


def _asset(identifier: str, criticality: str = "high") -> Asset:
    return Asset(identifier=identifier, name=f"Activo {identifier}", asset_type="service", criticality=criticality)


def test_covered_inventory_asset_resolves_to_its_explicit_capability():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-ERP"]))
    operation.plugins.append(
        PluginBinding(plugin_id="decoy-erp", surface="network", protected_asset_ids=["ASSET-ERP"])
    )

    coverage = build_asset_coverage(operation, [_asset("ASSET-ERP", "critical")])

    assert coverage["uncovered"] == []
    assert coverage["covered"][0]["asset"].name == "Activo ASSET-ERP"
    assert [binding.plugin_id for binding in coverage["covered"][0]["bindings"]] == ["decoy-erp"]


def test_uncovered_targets_order_known_critical_asset_before_manual_reference():
    operation = _operation(
        adversary_profile=AdversaryProfile(name="Actor", target_assets=["Manual fuera del inventario", "ASSET-CRIT"])
    )

    coverage = build_asset_coverage(operation, [_asset("ASSET-CRIT", "critical")])

    assert [target["reference"] for target in coverage["uncovered"]] == ["ASSET-CRIT", "Manual fuera del inventario"]
    assert coverage["uncovered"][1]["asset"] is None


def test_capability_without_explicit_asset_is_shown_without_calling_it_an_error():
    operation = _operation()
    operation.plugins.append(PluginBinding(plugin_id="miga", surface="data"))

    coverage = build_asset_coverage(operation, [])

    assert [binding.plugin_id for binding in coverage["unassigned_capabilities"]] == ["miga"]


def test_declared_reference_outside_targets_remains_visible():
    operation = _operation(adversary_profile=AdversaryProfile(name="Actor", target_assets=["ASSET-ERP"]))
    operation.plugins.append(
        PluginBinding(plugin_id="decoy-huerfano", surface="network", protected_asset_ids=["ASSET-AUSENTE"])
    )

    coverage = build_asset_coverage(operation, [_asset("ASSET-ERP")])

    assert coverage["covered"] == []
    assert coverage["unassigned_capabilities"] == []
    assert coverage["unresolved_references"][0]["reference"] == "ASSET-AUSENTE"
    assert [binding.plugin_id for binding in coverage["unresolved_references"][0]["bindings"]] == ["decoy-huerfano"]


def test_legacy_binding_without_asset_relation_loads_with_empty_default():
    binding = PluginBinding(plugin_id="legacy", surface="network")
    legacy_data = binding.to_dict()
    legacy_data.pop("protected_asset_ids")

    restored = PluginBinding.from_dict(legacy_data)

    assert restored.protected_asset_ids == []
