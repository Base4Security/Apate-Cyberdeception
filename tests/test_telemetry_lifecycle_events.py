"""E3 de docs/improvements.md: las acciones del operador contaminaban la
telemetria del adversario.

Cada plugin publica su deploy/rotate/retire como `EventType.INTERACTION`, y
`TelemetryCollector` guardaba toda INTERACTION sin distinguir. Medido antes
del fix, sobre un honeytoken recien desplegado y accedido una vez: 3
"eventos" para el analista, de los cuales solo 2 eran del adversario.

La consecuencia grave no eran los contadores sino el estado "observed" del
arbol de la operacion y del camino de engano, que se calcula como "existe
algun registro de telemetria para este plugin_id"
(`apate.web._deception_path`): un deploy alcanzaba para pintar la capacidad
-- y su escenario -- como si el adversario ya la hubiera tocado.
"""

from __future__ import annotations

import inspect
import os
import tempfile
from pathlib import Path

import pytest

from apate.plugins import PluginRegistry
from apate.plugins.base import (
    LIFECYCLE_PAYLOAD_KINDS,
    EventBus,
    EventType,
    PluginEvent,
    is_lifecycle_event,
)
from apate.plugins.honeytoken import HoneytokenPlugin
from apate.plugins.mock import MockHoneypotPlugin
from apate.telemetry import JSONFileTelemetryRepository, TelemetryCollector


def _evento(kind: str | None, event_type: EventType = EventType.INTERACTION) -> PluginEvent:
    payload = {"detail": "x"} if kind is None else {"kind": kind, "detail": "x"}
    return PluginEvent(
        event_type=event_type,
        plugin_id="cap-1",
        surface="s",
        operation_id="op-1",
        payload=payload,
    )


@pytest.fixture
def collector(tmp_path):
    return TelemetryCollector(repository=JSONFileTelemetryRepository(tmp_path / "telem"))


# -- is_lifecycle_event() ------------------------------------------------


@pytest.mark.parametrize("kind", sorted(LIFECYCLE_PAYLOAD_KINDS))
def test_lifecycle_kinds_are_recognised(kind):
    assert is_lifecycle_event(_evento(kind)) is True


@pytest.mark.parametrize("kind", ["access", "scan", "hit", "connection", None])
def test_adversary_kinds_are_not_lifecycle(kind):
    assert is_lifecycle_event(_evento(kind)) is False


# -- El colector ---------------------------------------------------------


@pytest.mark.parametrize("kind", sorted(LIFECYCLE_PAYLOAD_KINDS))
def test_collector_discards_lifecycle_events(collector, kind):
    collector.handle_event(_evento(kind))
    assert collector.list_events("op-1") == []


def test_collector_keeps_adversary_interactions(collector):
    collector.handle_event(_evento("access"))
    assert len(collector.list_events("op-1")) == 1


def test_collector_keeps_observed_ttps(collector):
    collector.handle_event(_evento(None, EventType.TTP_OBSERVED))
    assert len(collector.list_events("op-1")) == 1


# -- El escenario real que se midio --------------------------------------


def test_honeytoken_deploy_and_access_only_records_the_access(tmp_path):
    """Antes del fix este flujo dejaba 3 registros: deploy + acceso + TTP."""

    bus = EventBus()
    collector = TelemetryCollector(
        repository=JSONFileTelemetryRepository(tmp_path / "telem"), bus=bus
    )
    plugin = HoneytokenPlugin(
        plugin_id="ht-1",
        operation_id="op-1",
        surface="Archivos / credenciales",
        bus=bus,
        config={"directory": str(tmp_path / "share"), "filenames": ["creds.txt"]},
    )

    plugin.deploy()
    assert collector.list_events("op-1") == [], "el deploy no es actividad del adversario"

    # Este test verifica el filtrado de eventos de ciclo de vida, no que el
    # filesystem local actualice st_atime. NTFS puede diferir esa marca aun
    # cuando la lectura ocurrió; se fuerza el cambio igual que en el E2E del
    # motor para que el resultado no dependa del host donde corre la suite.
    target = tmp_path / "share" / "creds.txt"
    stamps = target.stat()
    os.utime(target, (stamps.st_atime + 10, stamps.st_mtime))
    plugin.check_access()

    kinds = [r.payload.get("kind") for r in collector.list_events("op-1")]
    assert "deploy" not in kinds
    assert "access" in kinds


def test_a_freshly_deployed_capability_is_not_reported_as_observed(tmp_path):
    """`observed` en el arbol y el camino de engano es exactamente esto:
    'hay algun registro de telemetria para este plugin_id'."""

    bus = EventBus()
    collector = TelemetryCollector(
        repository=JSONFileTelemetryRepository(tmp_path / "telem"), bus=bus
    )
    plugin = HoneytokenPlugin(
        plugin_id="ht-1",
        operation_id="op-1",
        surface="Archivos / credenciales",
        bus=bus,
        config={"directory": str(tmp_path / "share")},
    )
    plugin.deploy()
    plugin.rotate()

    registros_por_plugin = {r.plugin_id for r in collector.list_events("op-1")}
    assert bool("ht-1" in registros_por_plugin) is False


# -- La convencion se sostiene en todos los plugins ----------------------

# MockHoneypotPlugin.deploy() es la unica excepcion deliberada: publica
# `kind="scan"` porque su proposito declarado es emitir actividad sintetica
# del adversario para ejercitar el resto del sistema. No es una accion de
# ciclo de vida disfrazada, es un simulador.
_EXCEPCIONES = {(MockHoneypotPlugin, "deploy")}


@pytest.mark.parametrize("kind", sorted(PluginRegistry.list_kinds()))
@pytest.mark.parametrize("metodo", ["deploy", "rotate", "retire"])
def test_every_plugin_tags_its_lifecycle_actions(kind, metodo):
    """Guarda de la convencion: si se suma un plugin nuevo que publique su
    ciclo de vida sin `kind`, sus deploys van a volver a contaminar la
    telemetria y este test lo dice."""

    clase = PluginRegistry.get(kind)
    if (clase, metodo) in _EXCEPCIONES:
        pytest.skip("excepcion documentada: el mock simula actividad del adversario")
    fuente = inspect.getsource(getattr(clase, metodo))
    if "_publish(" not in fuente:
        pytest.skip(f"{clase.__name__}.{metodo}() no publica ningun evento")
    assert any(f'"{k}"' in fuente for k in LIFECYCLE_PAYLOAD_KINDS), (
        f"{clase.__name__}.{metodo}() publica un evento sin marcarlo como ciclo de vida"
    )
