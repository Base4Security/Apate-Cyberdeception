from datetime import datetime, timedelta, timezone

from apate.core import AdversaryProfile, DeceptionEffect, Narrative, Operation, PluginBinding, RulesOfEngagement, Scenario
from apate.plugins import EventType
from apate.telemetry import TelemetryRecord
from apate.web._deception_path import build_deception_path


def _operation():
    return Operation(
        name="Operación visual",
        adversary_profile=AdversaryProfile(name="Actor", expected_ttps=["T1078"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )


def test_deception_path_uses_only_explicit_relationships():
    sample_operation = _operation()
    scenario = Scenario(description="Acceso inicial", related_ttps=["T1078"])
    sample_operation.scenarios.append(scenario)
    sample_operation.adversary_profile.expected_ttps = ["T1078"]
    sample_operation.plugins.append(
        PluginBinding(
            plugin_id="mock-1",
            plugin_kind="mock",
            surface="network",
            scenario_id=scenario.id,
            effect=DeceptionEffect(expected_adversary_action="Usar la identidad"),
        )
    )
    sample_operation.plugins.append(
        PluginBinding(
            plugin_id="dolost-1",
            plugin_kind="dolost",
            surface="network",
            scenario_id=scenario.id,
            config={"decoys": [{"Hostname": "srv-finanzas"}]},
        )
    )
    event = TelemetryRecord(
        event_type=EventType.TTP_OBSERVED,
        operation_id=sample_operation.id,
        plugin_id="mock-1",
        surface="network",
        timestamp=datetime.now(timezone.utc),
        source_event_id="source-1",
        ttp_id="T1078",
        payload={"detail": "Acceso observado"},
    )

    path = build_deception_path(
        sample_operation,
        [event],
        dolost_panels={},
        buda_panels={},
        honeytoken_panels={},
    )

    relations = {(edge["source"], edge["target"], edge["relation"]) for edge in path["edges"]}
    assert ("adversary", "ttp:T1078", "esperada") in relations
    assert ("ttp:T1078", f"scenario:{scenario.id}", "implementada por") in relations
    assert (f"scenario:{scenario.id}", "capability:mock-1", "usa") in relations
    assert ("capability:mock-1", f"event:{event.id}", "observado por") in relations
    assert (f"event:{event.id}", "ttp:T1078", "evidencia") in relations
    assert any(node["kind"] == "Decoy" and node["label"] == "srv-finanzas" for node in path["nodes"])


def test_operation_detail_exposes_visual_path_and_table(client, app):
    sample_operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(sample_operation)

    response = client.get(f"/operations/{sample_operation.id}")

    assert response.status_code == 200
    assert b'Camino visual de enga&ntilde;o' in response.data
    assert b'aria-label="Grafo de solo lectura"' in response.data
    assert b'Representaci&oacute;n tabular' in response.data
    assert b'deception-path-data' in response.data


def test_scenario_is_observed_only_by_event_from_its_bound_capability():
    sample_operation = _operation()
    first = Scenario(description="Primero", related_ttps=["T1078"])
    second = Scenario(description="Segundo", related_ttps=["T1078"])
    sample_operation.scenarios.extend([first, second])
    sample_operation.plugins.extend(
        [
            PluginBinding(plugin_id="mock-first", plugin_kind="mock", surface="network", scenario_id=first.id),
            PluginBinding(plugin_id="mock-second", plugin_kind="mock", surface="network", scenario_id=second.id),
        ]
    )
    event = TelemetryRecord(
        event_type=EventType.TTP_OBSERVED,
        operation_id=sample_operation.id,
        plugin_id="mock-first",
        surface="network",
        timestamp=datetime.now(timezone.utc),
        source_event_id="source-first",
        ttp_id="T1078",
    )

    path = build_deception_path(
        sample_operation, [event], dolost_panels={}, buda_panels={}, honeytoken_panels={}
    )
    nodes = {node["id"]: node for node in path["nodes"]}

    assert nodes[f"scenario:{first.id}"]["state"] == "observed"
    assert nodes[f"scenario:{second.id}"]["state"] == "planned"
    assert nodes[f"event:{event.id}"]["href"].endswith(f"event_id={event.id}")


def test_high_volume_path_groups_older_events_but_keeps_exact_recent_links():
    sample_operation = _operation()
    sample_operation.bind_plugin(PluginBinding(plugin_id="mock-1", plugin_kind="mock", surface="network"))
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [TelemetryRecord(event_type=EventType.TTP_OBSERVED, operation_id=sample_operation.id,
                              plugin_id="mock-1", surface="network", timestamp=start + timedelta(minutes=index),
                              source_event_id=f"source-{index}", ttp_id="T1078" if index % 2 else "T1005")
              for index in range(100)]
    path = build_deception_path(sample_operation, events, dolost_panels={}, buda_panels={}, honeytoken_panels={})
    nodes = {node["id"]: node for node in path["nodes"]}
    assert path["total_event_count"] == 100
    assert path["individual_event_count"] == 12
    assert path["summarized_event_count"] == 88
    assert f"event:{events[-1].id}" in nodes
    assert f"event:{events[0].id}" not in nodes
    grouped = [node for node in path["nodes"] if node["id"].startswith("event-group:")]
    assert len(grouped) == 2
    assert all("view=events" in node["href"] and "plugin_id=mock-1" in node["href"] for node in grouped)
