"""Tests para `DeceptionEffect.engage_activity_ids` (M12c) - conecta el
catalogo de MITRE Engage (M12a, `apate.engage`) al triple Ver-Pensar-
Hacer de `PluginBinding` (M10). Ver docs/analisis-engage-integral.md.

Aditivo: cubre el roundtrip normal y, sobre todo, que un `DeceptionEffect`
persistido antes de M12c (sin la clave `engage_activity_ids` en su
JSON) siga cargando sin explotar -- mismo criterio que el resto de
M10/M12."""

from apate.core import DeceptionEffect, PluginBinding


def test_engage_activity_ids_roundtrip():
    effect = DeceptionEffect(
        expected_adversary_belief="El archivo contiene credenciales reales",
        expected_adversary_action="Las usa para moverse lateralmente",
        success_metric="Alerta en menos de 5 minutos",
        engage_activity_ids=["EAC0005", "EAC0001"],
    )

    restored = DeceptionEffect.from_dict(effect.to_dict())

    assert restored.engage_activity_ids == ["EAC0005", "EAC0001"]
    assert restored.expected_adversary_belief == "El archivo contiene credenciales reales"


def test_engage_activity_ids_defaults_to_empty_list():
    effect = DeceptionEffect()
    assert effect.engage_activity_ids == []


def test_engage_activity_ids_included_in_to_dict():
    effect = DeceptionEffect(engage_activity_ids=["EAC0005"])
    assert effect.to_dict()["engage_activity_ids"] == ["EAC0005"]


def test_deception_effect_from_dict_without_engage_activity_ids_key_does_not_raise():
    # Simula un DeceptionEffect persistido ANTES de M12c (ya tenia
    # belief/action/metric de M10, pero nunca la clave nueva) -- no
    # deberia romper, solo completar el default.
    legacy_dict = {
        "expected_adversary_belief": "Cree que es real",
        "expected_adversary_action": "Interactua con el senuelo",
        "success_metric": "TTP observada",
        # sin "engage_activity_ids"
    }

    restored = DeceptionEffect.from_dict(legacy_dict)

    assert restored.engage_activity_ids == []
    assert restored.expected_adversary_belief == "Cree que es real"


def test_plugin_binding_with_engage_activity_ids_survives_operation_roundtrip():
    binding = PluginBinding(
        plugin_id="honeytoken-1",
        surface="data",
        effect=DeceptionEffect(engage_activity_ids=["EAC0005", "EAC0012"]),
    )
    restored = PluginBinding.from_dict(binding.to_dict())

    assert restored.effect.engage_activity_ids == ["EAC0005", "EAC0012"]


def test_legacy_plugin_binding_dict_without_effect_key_defaults_to_empty_engage_activity_ids():
    # Mismo formato "legacy" que ya usa test_models_m10.py para
    # PluginBinding (sin la clave "effect" en absoluto -- pre-M10).
    legacy_binding_dict = {"plugin_id": "honeytoken-1", "surface": "data", "config": {}}

    restored = PluginBinding.from_dict(legacy_binding_dict)

    assert restored.effect == DeceptionEffect()
    assert restored.effect.engage_activity_ids == []
