"""Enrutamiento de la cola vendorizada de BUDA por narrativa."""

from BUDA.utils.events import clear_events, drain_events, record_event


def test_drain_events_by_narrative_preserves_other_events_in_order():
    clear_events()
    try:
        first = record_event(kind="step", detail="uno", narrative_id=1)
        expected = [
            record_event(kind="step", detail="dos", narrative_id=2),
            record_event(kind="step", detail="tres", narrative_id=2),
        ]

        assert drain_events(narrative_id="1") == [first]
        assert drain_events(narrative_id=2) == expected
        assert drain_events() == []
    finally:
        clear_events()


def test_drain_events_without_filter_keeps_legacy_contract():
    clear_events()
    try:
        expected = [record_event(kind="step", detail="sin narrativa")]
        assert drain_events() == expected
        assert drain_events() == []
    finally:
        clear_events()
