"""Tests de RulesOfEngagement.permits() (M9, hardening) en aislamiento
-- ver tests/test_rules_engine.py para la integracion con el
RuleEngine (M3)."""

from apate.core import RulesOfEngagement


def test_default_roe_permits_everything():
    roe = RulesOfEngagement()

    assert roe.permits("deploy") is True
    assert roe.permits("deploy", "deploy:mock-1") is True
    assert roe.permits("transition:closed") is True


def test_forbidden_action_by_kind_is_not_permitted():
    roe = RulesOfEngagement(forbidden_actions=["retire"])

    assert roe.permits("retire") is False
    assert roe.permits("retire", "retire:mock-1") is False


def test_forbidden_action_by_specific_plugin_signature():
    roe = RulesOfEngagement(forbidden_actions=["deploy:mock-1"])

    assert roe.permits("deploy", "deploy:mock-1") is False  # mock-1 esta prohibido
    assert roe.permits("deploy", "deploy:mock-2") is True  # mock-2 no lo esta


def test_forbidden_transition_target():
    roe = RulesOfEngagement(forbidden_actions=["transition:compromised"])

    assert roe.permits("transition", "transition:compromised") is False
    assert roe.permits("transition", "transition:closed") is True


def test_empty_allowed_actions_does_not_restrict_anything():
    roe = RulesOfEngagement(allowed_actions=[])

    assert roe.permits("deploy") is True
    assert roe.permits("retire", "retire:mock-1") is True


def test_non_empty_allowed_actions_acts_as_allowlist():
    roe = RulesOfEngagement(allowed_actions=["deploy"])

    assert roe.permits("deploy", "deploy:mock-1") is True
    assert roe.permits("retire", "retire:mock-1") is False  # no esta en la allowlist


def test_forbidden_actions_takes_precedence_over_allowed_actions():
    # Un caso deliberadamente contradictorio: si algo esta en ambas
    # listas, gana forbidden_actions (mas restrictivo, en linea con la
    # seccion 8 del diseno: "ninguna regla debe poder afectar sistemas
    # fuera del alcance de la operacion").
    roe = RulesOfEngagement(allowed_actions=["deploy"], forbidden_actions=["deploy:mock-1"])

    assert roe.permits("deploy", "deploy:mock-1") is False
    assert roe.permits("deploy", "deploy:mock-2") is True
