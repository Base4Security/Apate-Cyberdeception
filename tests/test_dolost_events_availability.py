"""Disponibilidad segura del extractor estructurado de DOLOS-T."""

from DOLOST.services import events


def test_structured_events_are_empty_before_docker_client_is_configured(monkeypatch):
    monkeypatch.setattr(events.docker_manager, "client", None)

    assert events.get_structured_events() == []
