from datetime import datetime, timezone
from unittest.mock import patch

from apate.plugins.base import EventBus, EventType, PluginEvent
from apate.playground.events import PLAYGROUND_PLUGIN_ID, PlaygroundEventBridge, PlaygroundSource


def _make_bridge(bus=None, operation_id="op-1") -> PlaygroundEventBridge:
    return PlaygroundEventBridge(bus=bus or EventBus(), operation_id=operation_id)


def _collect(bus: EventBus, event_type: EventType) -> list[PluginEvent]:
    collected: list[PluginEvent] = []
    bus.subscribe(event_type, collected.append)
    return collected


# -- Elasticsearch (ssh_honeypot, frontend, backend, mysql) -----------------
#
# Fixtures basadas en el esquema real confirmado contra el repositorio
# Cyber Deception Playground: ssh_connections.json (timestamp,
# source_ip, username, event_type, command, fake) indexado por
# Filebeat en playground-logs-*, enriquecido con mitre.tactic/
# mitre.technique_id/mitre.technique_name cuando matchea una regla de
# filebeat.yml (ver docs/analisis-repos-existentes.md).


def test_honeypot_ssh_connection_hit_becomes_interaction_with_credential_ioc():
    bus = EventBus()
    interactions = _collect(bus, EventType.INTERACTION)
    bridge = _make_bridge(bus)
    hit = {
        "_source": {
            "timestamp": "2026-08-06T10:00:00Z",
            "source_ip": "203.0.113.20",
            "username": "admin",
            "event_type": "ssh_connection",
            "fake": True,
        }
    }

    event = bridge.ingest_elastic_hit(hit)

    assert event is not None
    assert event.event_type == EventType.INTERACTION
    assert event.plugin_id == PLAYGROUND_PLUGIN_ID
    assert event.operation_id == "op-1"
    assert event.payload["source_ip"] == "203.0.113.20"
    assert event.payload["credential"] == "admin"
    assert event.payload["fake"] is True
    assert event.payload["source"] == PlaygroundSource.ELASTIC.value
    assert interactions == [event]


def test_honeypot_command_execution_hit_carries_command():
    bridge = _make_bridge()
    hit = {
        "_source": {
            "source_ip": "203.0.113.20",
            "username": "admin",
            "event_type": "command_execution",
            "command": "cat /home/admin/credentials.txt",
            "fake": True,
        }
    }

    event = bridge.ingest_elastic_hit(hit)

    assert event.event_type == EventType.INTERACTION
    assert event.payload["command"] == "cat /home/admin/credentials.txt"


def test_hit_with_mitre_fields_becomes_ttp_observed_regardless_of_service():
    # HONEYTOKEN_ACCESS -> T1190, tal como esta definido en filebeat.yml
    # (ver enunciado del hallazgo); puede venir de cualquiera de los
    # cuatro servicios, no solo del honeypot.
    bus = EventBus()
    ttps = _collect(bus, EventType.TTP_OBSERVED)
    bridge = _make_bridge(bus)
    hit = {
        "_source": {
            "event_type": "http_request",
            "source_ip": "203.0.113.30",
            "mitre": {
                "tactic": "initial-access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
            },
        }
    }

    event = bridge.ingest_elastic_hit(hit)

    assert event.event_type == EventType.TTP_OBSERVED
    assert event.payload["ttp_id"] == "T1190"
    assert event.payload["mitre_tactic"] == "initial-access"
    assert event.payload["mitre_technique_name"] == "Exploit Public-Facing Application"
    assert ttps == [event]


def test_mitre_fields_as_flat_dotted_keys_are_also_recognized():
    bridge = _make_bridge()
    hit = {"_source": {"event_type": "observed", "mitre.technique_id": "T1552"}}

    event = bridge.ingest_elastic_hit(hit)

    assert event.event_type == EventType.TTP_OBSERVED
    assert event.payload["ttp_id"] == "T1552"


def test_elastic_document_without_source_wrapper_is_discarded():
    # ingest_elastic_hit espera siempre un hit con '_source' (la forma
    # real de la respuesta de _search) -- un documento ya desanidado no
    # es la entrada esperada de este metodo.
    bridge = _make_bridge()

    event = bridge.ingest_elastic_hit({"event_type": "file_created", "source_ip": "203.0.113.40"})

    assert event is None


def test_ingest_elastic_hits_processes_hits_list_and_returns_events_in_order():
    bridge = _make_bridge()
    hits = [
        {"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.1"}},
        {"not_a_source": True},
        {"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.2"}},
    ]

    events = bridge.ingest_elastic_hits(hits)

    assert [e.payload["source_ip"] for e in events] == ["203.0.113.1", "203.0.113.2"]


def test_fetch_and_ingest_elastic_queries_then_ingests(monkeypatch):
    bridge = _make_bridge()
    fake_hits = [{"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.50"}}]

    with patch("apate.playground.events.fetch_recent_hits", return_value=fake_hits) as mock_fetch:
        events = bridge.fetch_and_ingest_elastic(since=datetime(2026, 8, 6, tzinfo=timezone.utc))

    mock_fetch.assert_called_once()
    assert len(events) == 1
    assert events[0].payload["source_ip"] == "203.0.113.50"


# -- Contenedor atacante (docker exec + stdout) ------------------------------
#
# Fixtures basadas en el banner real que imprime print_mitre_header()
# en cada fase de main_attacker.py (components/base_attacker.py) --
# confirmado contra el repositorio real. El resto de la salida es
# texto libre pensado para un operador humano, no un formato
# estructurado: el bridge solo reconoce este banner.

_MITRE_BANNER = (
    "============================================================\n"
    "  MITRE ATT&CK  |  T1595.003\n"
    "  Tactic        |  Reconnaissance\n"
    "  Technique     |  Active Scanning\n"
    "============================================================\n"
)


def test_attacker_stdout_with_mitre_banner_becomes_ttp_observed():
    bridge = _make_bridge()

    events = bridge.ingest_attacker_output(_MITRE_BANNER)

    assert len(events) == 1
    event = events[0]
    assert event.event_type == EventType.TTP_OBSERVED
    assert event.payload["ttp_id"] == "T1595.003"
    assert event.payload["mitre_tactic"] == "Reconnaissance"
    assert event.payload["mitre_technique_name"] == "Active Scanning"
    assert event.payload["source"] == PlaygroundSource.ATTACKER.value


def test_attacker_stdout_banner_without_technique_line_is_still_recognized():
    # La linea 'Technique' es opcional: lo que define un match es
    # 'MITRE ATT&CK' seguido de 'Tactic'.
    bridge = _make_bridge()
    stdout = "  MITRE ATT&CK  |  T1110\n  Tactic        |  Credential Access\n"

    events = bridge.ingest_attacker_output(stdout)

    assert len(events) == 1
    assert events[0].payload["ttp_id"] == "T1110"
    assert "mitre_technique_name" not in events[0].payload


def test_attacker_stdout_with_multiple_phases_yields_one_event_per_banner():
    bridge = _make_bridge()
    stdout = "\n".join(
        [
            "Fase 1: Reconocimiento",
            "Escaneando la red interna...",
            _MITRE_BANNER,
            "Fase 2: Fuerza bruta SSH",
            "Probando credenciales...",
            "  MITRE ATT&CK  |  T1110.001\n  Tactic        |  Credential Access\n  Technique     |  Brute Force\n",
        ]
    )

    events = bridge.ingest_attacker_output(stdout)

    assert [e.payload["ttp_id"] for e in events] == ["T1595.003", "T1110.001"]


def test_attacker_stdout_without_any_banner_yields_no_events():
    bridge = _make_bridge()
    stdout = "Fase 1: Reconocimiento\nEscaneando la red interna...\nListo.\n"

    events = bridge.ingest_attacker_output(stdout)

    assert events == []


def test_attacker_stdout_empty_yields_no_events_without_raising():
    bridge = _make_bridge()

    assert bridge.ingest_attacker_output("") == []


def test_attacker_stdout_stream_publishes_a_banner_when_its_lines_arrive():
    bridge = _make_bridge()

    assert bridge.ingest_attacker_output_line("  MITRE ATT&CK  |  T1595.003\n") == []
    assert bridge.ingest_attacker_output_line("  Tactic        |  Reconnaissance\n") == []
    events = bridge.ingest_attacker_output_line("  Technique     |  Active Scanning\n")

    assert [event.payload["ttp_id"] for event in events] == ["T1595.003"]
    assert events[0].payload["mitre_technique_name"] == "Active Scanning"


def test_attacker_stdout_stream_flushes_a_banner_without_optional_technique():
    bridge = _make_bridge()

    bridge.ingest_attacker_output_line("  MITRE ATT&CK  |  T1110\n")
    bridge.ingest_attacker_output_line("  Tactic        |  Credential Access\n")
    events = bridge.finish_attacker_output_stream()

    assert [event.payload["ttp_id"] for event in events] == ["T1110"]
    assert "mitre_technique_name" not in events[0].payload
