"""Tests para `PluginBinding.leads_to_plugin_id` (referencia declarada:
CounterCraft -- breadcrumbs, las migas que llevan al adversario hasta
el engaño). Ver docstring de `PluginBinding`/`Operation.
find_plugin_binding()` en apate.core.models para el diseño completo.

Aditivo: cubre el roundtrip normal y, sobre todo, que un `PluginBinding`
persistido ANTES de este campo (sin la clave `leads_to_plugin_id` en su
JSON) siga cargando con `leads_to_plugin_id is None` -- mismo criterio
que `plugin_kind` (M12h)/`measured_outcome` (Fase 2 post-BlackHat)."""

import pytest

from apate.core import (
    AdversaryProfile,
    InvalidPluginBindingError,
    Narrative,
    Operation,
    PluginBinding,
    RulesOfEngagement,
)


def _operation(**overrides) -> Operation:
    defaults = dict(
        name="Operación de prueba",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


# -- Campo aditivo, compatibilidad hacia atrás --------------------------------


def test_leads_to_plugin_id_defaults_to_none():
    binding = PluginBinding(plugin_id="honeytoken-1", surface="data")
    assert binding.leads_to_plugin_id is None


def test_leads_to_plugin_id_roundtrip():
    binding = PluginBinding(plugin_id="honeytoken-1", surface="data", leads_to_plugin_id="dolost-1")

    restored = PluginBinding.from_dict(binding.to_dict())

    assert restored.leads_to_plugin_id == "dolost-1"
    assert restored.plugin_id == "honeytoken-1"


def test_leads_to_plugin_id_included_in_to_dict():
    binding = PluginBinding(plugin_id="honeytoken-1", surface="data", leads_to_plugin_id="dolost-1")
    assert binding.to_dict()["leads_to_plugin_id"] == "dolost-1"


def test_plugin_binding_from_dict_without_leads_to_plugin_id_key_defaults_to_none():
    # Simula un PluginBinding persistido ANTES de este campo -- mismo
    # formato "legacy" que ya usan test_models_m10.py/test_models_m12h.py,
    # sin la clave nueva en absoluto.
    legacy_dict = {"plugin_id": "dolost-1", "surface": "network", "config": {}}

    restored = PluginBinding.from_dict(legacy_dict)

    assert restored.leads_to_plugin_id is None
    assert restored.plugin_id == "dolost-1"


def test_json_file_repository_loads_legacy_operation_without_leads_to_plugin_id(tmp_path):
    # Mismo criterio que test_models_m10.py::
    # test_json_file_repository_loads_legacy_operation_from_disk -- un
    # JSON de Operation completo escrito a mano, formato pre-breadcrumbs,
    # tiene que seguir cargando sin romper.
    import json

    from apate.core.repository import JSONFileOperationRepository

    operation_id = "legacy-op-1"
    legacy_operation = {
        "id": operation_id,
        "name": "Operación legacy",
        "status": "planning",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "closed_at": None,
        "adversary_profile": {"name": "Actor", "motivation": "", "skill_level": "unknown", "expected_ttps": [], "target_assets": [], "notes": ""},
        "roe": {"environment": "isolated", "allowed_actions": [], "forbidden_actions": [], "legal_constraints": "", "escalation_contact": ""},
        "narrative": {"name": "N", "description": "", "psychological_impact": ""},
        "scenarios": [],
        "plugins": [{"plugin_id": "dolost-1", "surface": "network", "config": {}}],
        "closure_criteria": {"end_date": None, "conditions": []},
        "strategic_decisions": {"objectives": [], "roles": {}, "resource_estimate": ""},
        "behavior_context_source_ids": [],
    }
    repo = JSONFileOperationRepository(tmp_path)
    (tmp_path / f"{operation_id}.json").write_text(json.dumps(legacy_operation), encoding="utf-8")

    operation = repo.get(operation_id)

    assert operation.plugins[0].leads_to_plugin_id is None


# -- Validación: solo lo autocontenido, en __post_init__ ----------------------


def test_self_reference_raises_at_construction():
    with pytest.raises(InvalidPluginBindingError):
        PluginBinding(plugin_id="honeytoken-1", surface="data", leads_to_plugin_id="honeytoken-1")


def test_leads_to_none_never_raises():
    # No debe confundirse "sin destino" con "se apunta a si mismo".
    PluginBinding(plugin_id="honeytoken-1", surface="data", leads_to_plugin_id=None)


def test_different_plugin_ids_never_raise():
    PluginBinding(plugin_id="honeytoken-1", surface="data", leads_to_plugin_id="dolost-1")


# -- Resolución externa: Operation.find_plugin_binding() ----------------------


def test_find_plugin_binding_resolves_existing_target():
    operation = _operation()
    target = PluginBinding(plugin_id="dolost-1", surface="network")
    operation.bind_plugin(target)

    assert operation.find_plugin_binding("dolost-1") is target


def test_find_plugin_binding_none_for_none_plugin_id():
    operation = _operation()
    assert operation.find_plugin_binding(None) is None


def test_find_plugin_binding_none_for_nonexistent_target():
    # "El destino no existe" -- caso real, deliberadamente NO se valida
    # en el dataclass (no tiene visibilidad de la Operation). Se
    # resuelve a None acá, sin lanzar -- la capa de presentación decide
    # cómo mostrar una referencia rota.
    operation = _operation()
    operation.bind_plugin(PluginBinding(plugin_id="honeytoken-1", surface="data", leads_to_plugin_id="no-existe"))

    binding = operation.plugins[0]
    assert operation.find_plugin_binding(binding.leads_to_plugin_id) is None


def test_a_two_node_cycle_does_not_raise_and_both_resolve():
    # "Hay un ciclo" (A lleva a B, B lleva a A) -- caso real, tampoco se
    # bloquea: cada arista "lleva a" es independiente (un solo salto por
    # binding), así que un ciclo no arriesga ningún recorrido recursivo.
    # Se puede persistir y las dos referencias resuelven correctamente,
    # cada una por separado.
    operation = _operation()
    a = PluginBinding(plugin_id="a", surface="network", leads_to_plugin_id="b")
    b = PluginBinding(plugin_id="b", surface="network", leads_to_plugin_id="a")
    operation.bind_plugin(a)
    operation.bind_plugin(b)

    assert operation.find_plugin_binding(a.leads_to_plugin_id) is b
    assert operation.find_plugin_binding(b.leads_to_plugin_id) is a
