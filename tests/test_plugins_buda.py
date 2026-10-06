"""Tests para BudaPlugin (M8c) - ver apate.plugins.buda_plugin.

Se mockean `start_narrative()`/`stop_narrative()`/`drain_events()`
(importadas por nombre dentro del modulo del adaptador) para probar la
logica del adaptador (estado, payloads) sin depender de la base de
datos de BUDA, WinRM ni el hilo en background que
`start_narrative()` lanza cuando una narrativa es valida -- ver el
docstring de la fixture `buda_calls` para el porque especifico de no
dejar correr el codigo real ahi.

La unica excepcion es `test_deploy_raises_runtime_error_without_flask_app_context`,
que llama al `start_narrative()` REAL de BUDA a proposito: es la forma
mas barata de confirmar la restriccion documentada en el docstring del
modulo (requiere contexto de aplicacion Flask activo) sin necesitar
una base de datos ni un hilo -- `current_app._get_current_object()`
falla en la primera linea, antes de tocar la base o lanzar nada."""

import pytest

from apate.plugins import BudaPlugin, EventBus, EventType, PluginLifecycleState, PluginStateError
from apate.plugins import buda_plugin as buda_plugin_module
from apate.plugins.exceptions import PluginConfigError


def _make_plugin(bus: EventBus = None, **config_overrides) -> BudaPlugin:
    config = {"narrative_id": 1}
    config.update(config_overrides)
    return BudaPlugin(
        plugin_id="buda-1",
        surface="identity",
        operation_id="op-1",
        bus=bus if bus is not None else EventBus(),
        config=config,
    )


@pytest.fixture
def buda_calls(monkeypatch):
    """Reemplaza start_narrative()/stop_narrative() por dobles que
    solo registran la llamada y devuelven el mismo dict {"message":
    ...} que devuelve el codigo real -- sin esto, start_narrative()
    real dispara un hilo en background (narrative_engine) que a su vez
    termina llamando a los endpoints de IA de BUDA hardcodeados a
    localhost:5000 (ver docs/roadmap.md, hallazgos de M8c), ademas de
    requerir un contexto de aplicacion Flask con una Narrative real en
    la base -- nada de eso es lo que estos tests quieren ejercitar."""

    calls = {"start_narrative": [], "stop_narrative": []}

    monkeypatch.setattr(
        buda_plugin_module,
        "start_narrative",
        lambda narrative_id: (calls["start_narrative"].append(narrative_id), {"message": "Narrative started"})[1],
    )
    monkeypatch.setattr(
        buda_plugin_module,
        "stop_narrative",
        lambda narrative_id: (calls["stop_narrative"].append(narrative_id), {"message": "Narrative stopped"})[1],
    )
    return calls


# -- configuracion ------------------------------------------------------


def test_deploy_without_narrative_id_raises_plugin_config_error(buda_calls):
    plugin = _make_plugin(narrative_id=None)
    with pytest.raises(PluginConfigError):
        plugin.deploy()


# -- deploy() -----------------------------------------------------------


def test_deploy_calls_start_narrative_with_configured_id(buda_calls):
    plugin = _make_plugin(narrative_id=42)
    plugin.deploy()

    assert buda_calls["start_narrative"] == [42]


def test_deploy_emits_interaction_event_with_narrative_id_and_message(buda_calls):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    _make_plugin(bus=bus, narrative_id=42).deploy()

    assert len(received) == 1
    assert received[0].payload["kind"] == "deploy"
    assert received[0].payload["narrative_id"] == 42
    assert received[0].payload["detail"] == "Narrative started"


def test_deploy_sets_state_to_deployed(buda_calls):
    plugin = _make_plugin()
    plugin.deploy()
    assert plugin.state == PluginLifecycleState.DEPLOYED


def test_deploy_twice_raises_plugin_state_error(buda_calls):
    plugin = _make_plugin()
    plugin.deploy()
    with pytest.raises(PluginStateError):
        plugin.deploy()


# -- rotate() -------------------------------------------------------------


def test_rotate_before_deploy_raises_plugin_state_error(buda_calls):
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.rotate()


def test_rotate_stops_then_starts_the_same_narrative(buda_calls):
    plugin = _make_plugin(narrative_id=42)
    plugin.deploy()

    plugin.rotate()

    assert buda_calls["stop_narrative"] == [42]
    assert buda_calls["start_narrative"] == [42, 42]


def test_rotate_keeps_deployed_state_and_emits_event(buda_calls):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus, narrative_id=42)
    plugin.deploy()
    received.clear()

    plugin.rotate()

    assert plugin.state == PluginLifecycleState.DEPLOYED
    assert len(received) == 1
    assert received[0].payload["kind"] == "rotate"


# -- retire() ---------------------------------------------------------------


def test_retire_before_deploy_raises_plugin_state_error(buda_calls):
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.retire()


def test_retire_calls_stop_narrative_and_sets_state_retired(buda_calls):
    plugin = _make_plugin(narrative_id=42)
    plugin.deploy()

    plugin.retire()

    assert buda_calls["stop_narrative"] == [42]
    assert plugin.state == PluginLifecycleState.RETIRED


def test_retire_emits_interaction_event(buda_calls):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus, narrative_id=42)
    plugin.deploy()
    received.clear()

    plugin.retire()

    assert received[0].payload["kind"] == "retire"
    assert received[0].payload["detail"] == "Narrative stopped"


def test_retire_twice_raises_plugin_state_error(buda_calls):
    plugin = _make_plugin()
    plugin.deploy()
    plugin.retire()
    with pytest.raises(PluginStateError):
        plugin.retire()


# -- check_activity() --------------------------------------------------------


def test_check_activity_before_deploy_raises_plugin_state_error(buda_calls, monkeypatch):
    monkeypatch.setattr(buda_plugin_module, "drain_events", lambda: [])
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.check_activity()


def test_check_activity_publishes_interaction_for_events_without_ttp_id(buda_calls, monkeypatch):
    raw_event = {"kind": "credential_use", "detail": "Credenciales usadas", "ttp_id": None, "source_ip": "203.0.113.9"}
    monkeypatch.setattr(buda_plugin_module, "drain_events", lambda **_kwargs: [raw_event])

    bus = EventBus()
    interactions = []
    ttps = []
    bus.subscribe(EventType.INTERACTION, interactions.append)
    bus.subscribe(EventType.TTP_OBSERVED, ttps.append)

    plugin = _make_plugin(bus=bus)
    plugin.deploy()
    interactions.clear()

    published = plugin.check_activity()

    assert len(published) == 1
    assert len(interactions) == 1
    assert ttps == []
    assert interactions[0].payload["source_ip"] == "203.0.113.9"
    assert interactions[0].resource_id == "narrative:1"
    assert "ttp_id" not in interactions[0].payload


def test_check_activity_drains_only_its_configured_narrative(buda_calls, monkeypatch):
    requested = []
    monkeypatch.setattr(
        buda_plugin_module,
        "drain_events",
        lambda narrative_id: requested.append(narrative_id) or [],
    )
    plugin = _make_plugin(narrative_id=42)
    plugin.deploy()

    plugin.check_activity()

    assert requested == [42]


def test_check_activity_publishes_ttp_observed_when_ttp_id_present(buda_calls, monkeypatch):
    raw_event = {"kind": "winrm_exec", "detail": "...", "ttp_id": "T1021.006"}
    monkeypatch.setattr(buda_plugin_module, "drain_events", lambda **_kwargs: [raw_event])

    bus = EventBus()
    ttps = []
    bus.subscribe(EventType.TTP_OBSERVED, ttps.append)

    plugin = _make_plugin(bus=bus)
    plugin.deploy()
    plugin.check_activity()

    assert len(ttps) == 1
    assert ttps[0].payload["ttp_id"] == "T1021.006"


def test_check_activity_does_not_deduplicate_across_polls(buda_calls, monkeypatch):
    # A diferencia de DolosTPlugin, drain_events() vacia la cola real
    # en cada llamada -- si el mismo evento aparece dos veces en dos
    # polls distintos (porque record_event() lo volvio a encolar) el
    # adaptador lo publica las dos veces, sin filtrar.
    same_event = {"kind": "credential_use", "detail": "Credenciales usadas", "ttp_id": None}
    events_by_call = [[same_event], [same_event]]
    monkeypatch.setattr(buda_plugin_module, "drain_events", lambda **_kwargs: events_by_call.pop(0))

    plugin = _make_plugin()
    plugin.deploy()

    first = plugin.check_activity()
    second = plugin.check_activity()

    assert len(first) == 1
    assert len(second) == 1


# -- restriccion de contexto de aplicacion Flask (documentada, no mockeada) --


def test_deploy_raises_runtime_error_without_flask_app_context(buda_calls, monkeypatch):
    # Deshace el mock de start_narrative() de la fixture buda_calls
    # para este test puntual: queremos el codigo real de BUDA, que es
    # el que impone la restriccion de app context -- ver docstring de
    # este archivo.
    monkeypatch.undo()
    plugin = _make_plugin(narrative_id=42)

    with pytest.raises(RuntimeError, match="application context"):
        plugin.deploy()


# -- regresion M14e: sigue funcionando sin ningun blueprint de BUDA ---------


def test_deploy_rotate_retire_work_under_real_app_context_with_no_buda_blueprints(
    tmp_path, monkeypatch
):
    # M14e retira los nueve blueprints de mount_buda() -- este test
    # confirma que BudaPlugin.deploy()/rotate()/retire() siguen
    # funcionando igual bajo un contexto de aplicacion real (create_app()
    # de verdad, no un Flask() de juguete), sin que ningun blueprint de
    # BUDA este registrado: la app en si sigue existiendo (con su sesion
    # SQLAlchemy atada, que es lo unico que start_narrative()/
    # stop_narrative() necesitan de flask.current_app), solo cambia que
    # ya no tiene ninguna ruta bajo /buda/....
    from apate.web import create_app

    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-plugin-regression.db'}",
        }
    )
    rules = {r.rule for r in app.url_map.iter_rules()}
    assert not any(rule.startswith("/buda") for rule in rules)

    calls = {"start": [], "stop": []}
    monkeypatch.setattr(
        buda_plugin_module,
        "start_narrative",
        lambda narrative_id: (calls["start"].append(narrative_id), {"message": "Narrative started"})[1],
    )
    monkeypatch.setattr(
        buda_plugin_module,
        "stop_narrative",
        lambda narrative_id: (calls["stop"].append(narrative_id), {"message": "Narrative stopped"})[1],
    )

    plugin = _make_plugin(narrative_id=42)
    with app.app_context():
        plugin.deploy()
        plugin.rotate()
        plugin.retire()

    assert calls["start"] == [42, 42]
    assert calls["stop"] == [42, 42]
    assert plugin.state == PluginLifecycleState.RETIRED
