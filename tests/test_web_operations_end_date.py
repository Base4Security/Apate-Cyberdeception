"""E8 de docs/improvements.md: `end_date` apuntaba al comienzo del dia
elegido, no a su final.

`_parse_end_date()` convertia el valor de un `<input type="date">` a la
medianoche UTC de esa fecha, y `Operation.is_past_due()` compara
`now >= end_date`, asi que elegir la fecha de hoy dejaba la operacion
vencida en el instante en que se guardaba:

    end_date = hoy    -> is_past_due: True
    end_date = manana -> is_past_due: False

Estaba enmascarado porque nada llamaba a `RuleEngine.check_closure()`
(E7). Se corrige antes de conectarlo: si no, la primera operacion con
fecha de cierre de hoy se cerraria sola al guardarse.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from apate.core.models import (
    AdversaryProfile,
    ClosureCriteria,
    Environment,
    Narrative,
    Operation,
    RulesOfEngagement,
)
from apate.web.blueprints.operations import _parse_end_date


def _operacion_con_cierre(end_date):
    return Operation(
        name="x",
        adversary_profile=AdversaryProfile(name="a"),
        roe=RulesOfEngagement(environment=Environment.ISOLATED),
        narrative=Narrative(name="n"),
        closure_criteria=ClosureCriteria(end_date=end_date),
    )


# -- El parseo -----------------------------------------------------------


def test_end_date_points_at_the_end_of_the_chosen_day():
    parseada = _parse_end_date("2026-09-01")
    assert parseada.date() == date(2026, 9, 1)
    assert (parseada.hour, parseada.minute) == (23, 59)
    assert parseada.tzinfo == timezone.utc


def test_an_empty_value_stays_empty():
    assert _parse_end_date("") is None
    assert _parse_end_date("   ") is None


# -- La consecuencia que se buscaba --------------------------------------


def test_an_operation_ending_today_is_not_already_past_due():
    hoy = date(2026, 9, 14)
    operacion = _operacion_con_cierre(_parse_end_date(hoy.isoformat()))

    assert operacion.is_past_due(
        now=datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
    ) is False


def test_an_operation_ending_yesterday_is_past_due():
    ayer = date(2026, 9, 13).isoformat()
    operacion = _operacion_con_cierre(_parse_end_date(ayer))

    assert operacion.is_past_due(
        now=datetime(2026, 9, 14, 12, tzinfo=timezone.utc)
    ) is True


def test_it_becomes_past_due_once_the_day_is_over():
    hoy = date(2026, 9, 14)
    operacion = _operacion_con_cierre(_parse_end_date(hoy.isoformat()))
    manana = datetime.combine(hoy + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
    assert operacion.is_past_due(now=manana) is True
