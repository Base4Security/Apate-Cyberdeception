"""Tests para M12f (apate.core.models.ClosureCriteria.trigger_conditions)
-- ver docs/roadmap.md seccion M12f y docs/analisis-engage-integral.md
(SAC0005, "Gating Criteria"). Cubre el dataclass en aislamiento
(roundtrip, validacion, compatibilidad hacia atras); el comportamiento
del RuleEngine sobre estas condiciones esta en
tests/test_rules_engine.py, seccion M12f."""

import json

import pytest

from apate.core import (
    AdversaryProfile,
    ClosureCriteria,
    InvalidClosureCriteriaError,
    JSONFileOperationRepository,
    Narrative,
    Operation,
    RulesOfEngagement,
)
from apate.plugins import EventType
from apate.rules import Condition


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba M12f",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


# -- Validacion (event-shaped only) ------------------------------------------


def test_trigger_conditions_accepts_event_shaped_condition():
    criteria = ClosureCriteria(
        trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
    )
    assert len(criteria.trigger_conditions) == 1


def test_trigger_conditions_rejects_closure_due_condition():
    # closure_due=True implica event_type=None (invariante de Condition):
    # esa semantica ya la cubre end_date/is_past_due(), un camino aparte.
    with pytest.raises(InvalidClosureCriteriaError):
        ClosureCriteria(trigger_conditions=[Condition(closure_due=True)])


def test_operation_add_trigger_condition_updates_the_collection():
    operation = _make_operation()
    condition = Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})

    operation.add_trigger_condition(condition)

    assert operation.closure_criteria.trigger_conditions == [condition]


def test_operation_add_trigger_condition_still_rejects_closure_due():
    operation = _make_operation()

    with pytest.raises(InvalidClosureCriteriaError):
        operation.add_trigger_condition(Condition(closure_due=True))

    assert operation.closure_criteria.trigger_conditions == []


def test_operation_remove_trigger_condition_uses_visible_index():
    first = Condition(event_type=EventType.INTERACTION)
    second = Condition(event_type=EventType.TTP_OBSERVED)
    operation = _make_operation(closure_criteria=ClosureCriteria(trigger_conditions=[first, second]))

    operation.remove_trigger_condition(0)

    assert operation.closure_criteria.trigger_conditions == [second]
    with pytest.raises(IndexError):
        operation.remove_trigger_condition(-1)


# -- Roundtrip de serializacion ------------------------------------------------


def test_closure_criteria_roundtrip_with_trigger_conditions():
    criteria = ClosureCriteria(
        trigger_conditions=[
            Condition(event_type=EventType.TTP_OBSERVED, plugin_id="honeypot-mock-1", payload={"ttp_id": "T1499"})
        ]
    )

    restored = ClosureCriteria.from_dict(criteria.to_dict())

    assert restored.trigger_conditions == criteria.trigger_conditions


def test_closure_criteria_defaults_trigger_conditions_to_empty_list():
    assert ClosureCriteria().trigger_conditions == []


def test_operation_roundtrip_preserves_closure_criteria_trigger_conditions(tmp_path):
    operation = _make_operation(
        closure_criteria=ClosureCriteria(
            trigger_conditions=[Condition(event_type=EventType.TTP_OBSERVED, payload={"ttp_id": "T1499"})]
        )
    )
    repo = JSONFileOperationRepository(tmp_path)

    repo.save(operation)
    reloaded = repo.get(operation.id)

    assert reloaded.closure_criteria.trigger_conditions == operation.closure_criteria.trigger_conditions


# -- Compatibilidad hacia atras -----------------------------------------------


def test_closure_criteria_from_dict_without_trigger_conditions_key_defaults_to_empty_list():
    # Forma real pre-M12f (confirmada contra _legacy_operation_dict() de
    # tests/test_models_m10.py): closure_criteria sin la clave nueva.
    restored = ClosureCriteria.from_dict({"end_date": None, "conditions": []})
    assert restored.trigger_conditions == []


def test_json_file_repository_loads_legacy_closure_criteria_from_disk(tmp_path):
    legacy_dict = {
        "id": "op-legacy-m12f",
        "name": "Operacion legacy pre-M12f",
        "status": "planning",
        "adversary_profile": {
            "name": "APT ficticio",
            "motivation": "",
            "skill_level": "unknown",
            "expected_ttps": [],
            "notes": "",
            "target_assets": [],
        },
        "roe": {
            "environment": "isolated",
            "allowed_actions": [],
            "forbidden_actions": [],
            "legal_constraints": [],
            "escalation_contact": "",
        },
        "narrative": {
            "name": "Narrativa legacy",
            "description": "",
            "similarity_percentage": 100,
            "story_elements": [],
            "psychological_impact": "",
        },
        "scenarios": [],
        "plugins": [],
        "closure_criteria": {"end_date": None, "conditions": []},
        "strategic_decisions": {"objectives": [], "roles": {}, "resource_estimate": ""},
        "created_at": "2025-01-01T00:00:00+00:00",
        "updated_at": "2025-01-01T00:00:00+00:00",
        "closed_at": None,
    }
    legacy_path = tmp_path / "op-legacy-m12f.json"
    legacy_path.write_text(json.dumps(legacy_dict), encoding="utf-8")

    repo = JSONFileOperationRepository(tmp_path)
    op = repo.get("op-legacy-m12f")

    assert op.closure_criteria.trigger_conditions == []
