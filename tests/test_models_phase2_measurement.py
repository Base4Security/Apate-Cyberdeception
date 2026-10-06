"""Tests para measured_outcome/measured_at/measured_by en
DeceptionEffect (Fase 2 post-BlackHat, ver docs/roadmap.md) - cierra
el lazo entre lo planificado (success_metric, M10) y lo efectivamente
medido. Mismo criterio que tests/test_models_m10.py: roundtrip
to_dict/from_dict, mas que un DeceptionEffect persistido ANTES de esta
fase (sin estos campos) siga cargando sin explotar."""

from datetime import datetime, timezone

from apate.core import DeceptionEffect, PluginBinding


def test_measured_fields_default_empty():
    effect = DeceptionEffect()
    assert effect.measured_outcome == ""
    assert effect.measured_at is None
    assert effect.measured_by == ""


def test_measured_fields_roundtrip_to_dict_from_dict():
    measured_at = datetime(2026, 8, 17, 10, 30, tzinfo=timezone.utc)
    effect = DeceptionEffect(
        success_metric="Alerta de acceso al honeytoken en menos de 5 minutos",
        measured_outcome="Alerta disparada a los 3 minutos de la conexion real",
        measured_at=measured_at,
        measured_by="Federico",
    )

    restored = DeceptionEffect.from_dict(effect.to_dict())

    assert restored.measured_outcome == effect.measured_outcome
    assert restored.measured_at == measured_at
    assert restored.measured_by == "Federico"


def test_measured_at_none_serializes_to_none_not_a_string():
    effect = DeceptionEffect()
    data = effect.to_dict()
    assert data["measured_at"] is None


def test_plugin_binding_effect_measured_fields_survive_binding_roundtrip():
    binding = PluginBinding(
        plugin_id="honeytoken-1",
        surface="data",
        effect=DeceptionEffect(measured_outcome="observado", measured_by="Federico"),
    )

    restored = PluginBinding.from_dict(binding.to_dict())

    assert restored.effect.measured_outcome == "observado"
    assert restored.effect.measured_by == "Federico"


def test_from_dict_on_legacy_effect_without_measured_fields_fills_defaults():
    # DeceptionEffect persistido antes de esta fase -- ningun campo
    # measured_* en el JSON en disco.
    legacy = {
        "expected_adversary_belief": "cree que es real",
        "expected_adversary_action": "usa la credencial",
        "success_metric": "alerta en 5 minutos",
        "engage_activity_ids": ["EAC0001"],
    }

    effect = DeceptionEffect.from_dict(legacy)

    assert effect.expected_adversary_belief == "cree que es real"
    assert effect.measured_outcome == ""
    assert effect.measured_at is None
    assert effect.measured_by == ""
