import subprocess
from datetime import datetime, timezone
from unittest.mock import patch

from apate.core.models import AdversaryProfile, Narrative, Operation, OperationStatus, PluginBinding, RulesOfEngagement
from apate.plugins import MockHoneypotPlugin, PluginLifecycleState, PluginRegistry
from apate.playground.config import PlaygroundConfig
from apate.playground.session import PlaygroundSession
from apate.rules.models import Action, ActionKind, Condition, Rule
from apate.plugins.base import EventType
from apate.telemetry.collector import TelemetryCollector
from apate.telemetry.repository import JSONFileTelemetryRepository


def _make_operation() -> Operation:
    return Operation(
        name="Operacion Playground",
        adversary_profile=AdversaryProfile(name="APT ficticio", expected_ttps=["T1110"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )


def _make_telemetry(tmp_path) -> TelemetryCollector:
    return TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path / "telemetry"))


def _make_config(tmp_path) -> PlaygroundConfig:
    checkout = tmp_path / "cyberdeception-playground"
    checkout.mkdir()
    (checkout / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return PlaygroundConfig.from_path(checkout)


def _ssh_rule(*actions: Action) -> Rule:
    return Rule(
        name="Conexion SSH -> accion de plugin",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "ssh_connection"}),
        then=list(actions),
    )


def _ingest_ssh_connection(session: PlaygroundSession) -> None:
    session.bridge.ingest_elastic_hit(
        {"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.10"}}
    )


def test_session_elastic_hit_reaches_telemetry_collector(tmp_path):
    operation = _make_operation()
    telemetry = _make_telemetry(tmp_path)
    session = PlaygroundSession.create(operation=operation, rules=[], telemetry=telemetry)

    session.bridge.ingest_elastic_hit(
        {"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.10"}}
    )

    events = telemetry.list_events(operation.id)
    assert len(events) == 1
    assert events[0].plugin_id == "playground"


def test_session_elastic_hit_reaches_rule_engine_and_can_transition_operation(tmp_path):
    operation = _make_operation()
    telemetry = _make_telemetry(tmp_path)
    rule = Rule(
        name="Conexion al honeypot SSH -> activar",
        when=Condition(event_type=EventType.INTERACTION, payload={"kind": "ssh_connection"}),
        then=[Action(kind=ActionKind.TRANSITION, to=OperationStatus.ACTIVE)],
    )
    session = PlaygroundSession.create(operation=operation, rules=[rule], telemetry=telemetry)

    session.bridge.ingest_elastic_hit(
        {"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.10"}}
    )

    assert operation.status == OperationStatus.ACTIVE
    assert len(session.engine.history) == 1
    assert session.engine.history[0].rule_name == "Conexion al honeypot SSH -> activar"


def test_session_registers_real_binding_and_rule_deploys_it(tmp_path):
    operation = _make_operation()
    operation.bind_plugin(PluginBinding(plugin_id="mock-1", surface="network", plugin_kind="mock"))
    session = PlaygroundSession.create(
        operation=operation,
        rules=[_ssh_rule(Action(kind=ActionKind.DEPLOY, plugin_id="mock-1"))],
        telemetry=_make_telemetry(tmp_path),
    )

    _ingest_ssh_connection(session)

    plugin = session.engine.plugins["mock-1"]
    assert isinstance(plugin, MockHoneypotPlugin)
    assert plugin.state == PluginLifecycleState.DEPLOYED
    assert session.engine.history[0].actions == [Action(kind=ActionKind.DEPLOY, plugin_id="mock-1")]


def test_session_action_without_plugin_id_reaches_all_operation_plugins(tmp_path):
    operation = _make_operation()
    operation.bind_plugin(PluginBinding(plugin_id="mock-1", surface="network", plugin_kind="mock"))
    operation.bind_plugin(PluginBinding(plugin_id="mock-2", surface="network", plugin_kind="mock"))
    session = PlaygroundSession.create(
        operation=operation,
        rules=[_ssh_rule(Action(kind=ActionKind.DEPLOY))],
        telemetry=_make_telemetry(tmp_path),
    )

    _ingest_ssh_connection(session)

    assert {plugin.state for plugin in session.engine.plugins.values()} == {PluginLifecycleState.DEPLOYED}


def test_session_omits_binding_whose_factory_cannot_instantiate_and_logs_reason(tmp_path, monkeypatch, caplog):
    class BrokenPlugin:
        @classmethod
        def from_binding(cls, binding, *, operation_id, bus):
            raise ValueError("configuracion invalida")

    operation = _make_operation()
    operation.bind_plugin(PluginBinding(plugin_id="broken-1", surface="network", plugin_kind="broken"))
    monkeypatch.setattr(PluginRegistry, "resolve_binding_kind", staticmethod(lambda binding: "broken"))
    monkeypatch.setattr(PluginRegistry, "get", staticmethod(lambda kind: BrokenPlugin))

    with caplog.at_level("WARNING", logger="apate.plugins.operation"):
        session = PlaygroundSession.create(operation=operation, rules=[], telemetry=_make_telemetry(tmp_path))

    assert session.engine.plugins == {}
    assert "broken-1' omitido" in caplog.text
    assert "ValueError: configuracion invalida" in caplog.text


def test_session_records_roe_rejection_before_deploying_registered_binding(tmp_path):
    operation = _make_operation()
    operation.roe.forbidden_actions = ["deploy:mock-1"]
    operation.bind_plugin(PluginBinding(plugin_id="mock-1", surface="network", plugin_kind="mock"))
    session = PlaygroundSession.create(
        operation=operation,
        rules=[_ssh_rule(Action(kind=ActionKind.DEPLOY, plugin_id="mock-1"))],
        telemetry=_make_telemetry(tmp_path),
    )

    _ingest_ssh_connection(session)

    assert session.engine.plugins["mock-1"].state == PluginLifecycleState.CREATED
    assert len(session.engine.rejected_actions) == 1
    assert session.engine.rejected_actions[0].action == Action(kind=ActionKind.DEPLOY, plugin_id="mock-1")


def test_session_run_attacker_script_reaches_telemetry_collector(tmp_path):
    operation = _make_operation()
    telemetry = _make_telemetry(tmp_path)
    session = PlaygroundSession.create(operation=operation, rules=[], telemetry=telemetry)
    config = _make_config(tmp_path)

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=["docker", "exec"],
            returncode=0,
            stdout="  MITRE ATT&CK  |  T1595.003\n  Tactic        |  Reconnaissance\n",
            stderr="",
        )
        events = session.run_attacker_script(config)

    assert len(events) == 1
    assert events[0].payload["ttp_id"] == "T1595.003"
    assert telemetry.list_events(operation.id)[0].payload["source"] == "attacker"


def test_session_fetch_elastic_events_reaches_telemetry_collector(tmp_path):
    # Gap real cerrado tras la verificacion manual pendiente desde M5
    # (ver docs/roadmap.md): fetch_and_ingest_elastic() existia desde
    # M5 pero ninguna PlaygroundSession lo llamaba nunca -- la vista de
    # defensor jamas recibia telemetria real de ssh_honeypot/frontend/
    # backend/mysql, solo del contenedor atacante.
    operation = _make_operation()
    telemetry = _make_telemetry(tmp_path)
    session = PlaygroundSession.create(operation=operation, rules=[], telemetry=telemetry)

    fake_hits = [{"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.10"}}]
    with patch("apate.playground.events.fetch_recent_hits", return_value=fake_hits) as mock_fetch:
        events = session.fetch_elastic_events()

    assert mock_fetch.called
    assert len(events) == 1
    assert telemetry.list_events(operation.id)[0].payload["source_ip"] == "203.0.113.10"


def test_session_fetch_elastic_events_advances_watermark_to_avoid_reingesting(tmp_path):
    # TelemetryCollector no deduplica (cada evento publicado se persiste
    # tal cual) -- sin avanzar la marca de tiempo entre llamadas, cada
    # refresco de la vista de defensor volveria a ingerir los mismos
    # documentos ya vistos, inflando eventos/TTPs/disparos de reglas.
    # datetime.now() mockeado (no el reloj real) para que el assert no
    # dependa de la resolucion del reloj de la maquina que corre el test.
    operation = _make_operation()
    telemetry = _make_telemetry(tmp_path)
    session = PlaygroundSession.create(operation=operation, rules=[], telemetry=telemetry)

    fake_hits = [{"_source": {"event_type": "ssh_connection", "source_ip": "203.0.113.10"}}]
    later = datetime(2026, 1, 1, 12, 0, 5, tzinfo=timezone.utc)
    with patch("apate.playground.events.fetch_recent_hits", return_value=fake_hits) as mock_fetch:
        first_since = session._last_elastic_fetch
        with patch("apate.playground.session.datetime") as mock_datetime:
            mock_datetime.now.return_value = later
            session.fetch_elastic_events()

    assert mock_fetch.call_args.kwargs["since"] == first_since
    assert session._last_elastic_fetch == later
    assert len(telemetry.list_events(operation.id)) == 1
