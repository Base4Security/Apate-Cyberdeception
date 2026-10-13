"""E2 de docs/improvements.md: un honeytoken detectaba una sola lectura en
toda su vida y despues quedaba ciego, sin avisar.

La causa no era el baseline sino el filesystem: la condicion de `relatime`
(y el equivalente en APFS y NTFS) es que `atime <= mtime`. Se cumple justo
despues de escribir el archivo, y deja de cumplirse en cuanto la primera
lectura mueve `atime` por delante de `mtime`. Desde ahi ninguna lectura
posterior vuelve a tocar `atime`, asi que `check_access()` no volvia a
detectar nada -- y seguia devolviendo [] como si el senuelo estuviera sano.

Medido antes del fix: lectura #1 detectada, #2/#3/#4 no.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from apate.plugins.base import EventBus, PluginLifecycleState
from apate.plugins.honeytoken import HoneytokenPlugin


def _filesystem_actualiza_atime() -> bool:
    """Sonda una serie de ciclos reales leer -> rearmar, sin sleeps."""

    with tempfile.TemporaryDirectory() as directory:
        probe = pathlib.Path(directory) / "atime-probe"
        probe.write_bytes(b"probe")
        for _ in range(32):
            before = probe.stat().st_atime_ns
            probe.read_bytes()
            if probe.stat().st_atime_ns <= before:
                return False
            before_write = probe.stat().st_mtime_ns
            probe.write_bytes(probe.read_bytes())
            if probe.stat().st_mtime_ns <= before_write:
                return False
        return True


pytestmark = pytest.mark.skipif(
    not _filesystem_actualiza_atime(),
    reason=(
        "El filesystem no distingue lecturas por st_atime tras rearmar; "
        "HoneytokenPlugin no puede detectarlas por polling de forma verificable."
    ),
)


@pytest.fixture
def plugin(tmp_path):
    p = HoneytokenPlugin(
        plugin_id="ht-1",
        operation_id="op-1",
        surface="Archivos / credenciales",
        bus=EventBus(),
        config={"directory": str(tmp_path / "share"), "filenames": ["creds.txt"]},
    )
    p.deploy()
    return p


@pytest.fixture
def senuelo(tmp_path):
    return tmp_path / "share" / "creds.txt"


def _accesos(eventos):
    return [e for e in eventos if e.payload.get("kind") == "access"]


# -- La regresion medida -------------------------------------------------


def test_detects_every_read_not_just_the_first(plugin, senuelo):
    for numero in range(1, 5):
        senuelo.read_text(encoding="utf-8")
        assert _accesos(plugin.check_access()), f"la lectura #{numero} no se detecto"


def test_reports_that_it_rearmed(plugin, senuelo):
    senuelo.read_text(encoding="utf-8")
    (evento,) = _accesos(plugin.check_access())
    assert evento.payload["rearmed"] is True


# -- El re-armado no puede inventar accesos ni cambiar el senuelo --------


def test_a_poll_without_new_access_reports_nothing(plugin, senuelo):
    """El re-armado mueve mtime: si el baseline se tomara antes, el proximo
    chequeo reportaria una "modificacion" fantasma."""

    senuelo.read_text(encoding="utf-8")
    assert plugin.check_access()
    assert plugin.check_access() == []
    assert plugin.check_access() == []


def test_rearming_leaves_the_content_byte_identical(plugin, senuelo):
    antes = senuelo.read_bytes()
    plugin.check_access()
    assert senuelo.read_bytes() == antes


def test_rearming_preserves_a_previous_rotation(plugin, senuelo):
    """El re-armado reescribe los bytes actuales; no regenera el contenido,
    que perderia el sufijo que dejo un rotate() del operador."""

    plugin.rotate()
    rotado = senuelo.read_bytes()
    senuelo.read_bytes()
    plugin.check_access()
    assert senuelo.read_bytes() == rotado


# -- Una modificacion es evidencia: no se sobreescribe -------------------


def test_a_modification_is_detected_and_not_overwritten(plugin, senuelo):
    senuelo.write_text("lo que dejo el adversario\n", encoding="utf-8")
    eventos = plugin.check_access()
    kinds = [e.payload.get("kind") for e in eventos]
    assert "modified" in kinds
    assert senuelo.read_text(encoding="utf-8") == "lo que dejo el adversario\n"


def test_a_modification_does_not_claim_to_have_rearmed(plugin, senuelo):
    """Una modificacion ya dejo mtime por delante de atime: no hace falta
    re-armar, y el evento no debe afirmar que se hizo."""

    senuelo.write_text("otra cosa\n", encoding="utf-8")
    eventos = [e for e in plugin.check_access() if e.payload.get("kind") == "modified"]
    assert eventos and eventos[0].payload["rearmed"] is None


def test_reads_after_a_modification_are_still_detected(plugin, senuelo):
    senuelo.write_text("otra cosa\n", encoding="utf-8")
    plugin.check_access()
    senuelo.read_text(encoding="utf-8")
    assert _accesos(plugin.check_access())


# -- Si el re-armado falla, la deteccion no se pierde --------------------


def test_a_failed_rearm_still_reports_the_access(plugin, senuelo, monkeypatch):
    def sin_permiso(self, data):
        raise OSError("solo lectura")

    senuelo.read_text(encoding="utf-8")
    monkeypatch.setattr(pathlib.Path, "write_bytes", sin_permiso)
    (evento,) = _accesos(plugin.check_access())
    assert evento.payload["rearmed"] is False
    assert "deja de detectar" in evento.payload["detail"]


def test_the_plugin_stays_deployed_after_rearming(plugin, senuelo):
    senuelo.read_text(encoding="utf-8")
    plugin.check_access()
    assert plugin.state is PluginLifecycleState.DEPLOYED


# -- El camino de la web: instancia nueva por request --------------------


def test_detects_repeated_reads_across_fresh_instances(tmp_path):
    """Reproduce lo que hace la ruta web: cada chequeo construye una
    instancia nueva, la rehidrata y compara contra el baseline persistido.

    Es el caso que quedaba sin cubrir: re-armar solo al detectar no
    alcanza, porque el chequeo que apenas fija el punto de referencia no
    detecta nada y dejaba el senuelo con `atime` por delante de `mtime`
    para siempre.
    """

    config = {"directory": str(tmp_path / "share"), "filenames": ["creds.txt"]}
    senuelo = tmp_path / "share" / "creds.txt"

    inicial = HoneytokenPlugin(
        plugin_id="ht-1", operation_id="op-1", surface="s", bus=EventBus(), config=dict(config)
    )
    inicial.deploy()
    baseline = inicial.export_baseline()

    detectados = 0
    for _ in range(3):
        senuelo.read_text(encoding="utf-8")
        plugin = HoneytokenPlugin(
            plugin_id="ht-1", operation_id="op-1", surface="s", bus=EventBus(), config=dict(config)
        )
        plugin.restore_deployed_state()
        plugin.load_baseline(baseline)
        detectados += len(_accesos(plugin.check_access()))
        baseline = plugin.export_baseline()

    assert detectados == 3


def test_a_check_without_stored_baseline_still_arms_the_decoy(tmp_path):
    """El primer chequeo de un binding antiguo (sin baseline guardado) no
    detecta nada, pero tiene que dejar el senuelo armado igual."""

    config = {"directory": str(tmp_path / "share"), "filenames": ["creds.txt"]}
    senuelo = tmp_path / "share" / "creds.txt"

    inicial = HoneytokenPlugin(
        plugin_id="ht-1", operation_id="op-1", surface="s", bus=EventBus(), config=dict(config)
    )
    inicial.deploy()

    senuelo.read_text(encoding="utf-8")  # lectura que no se va a poder atribuir
    primero = HoneytokenPlugin(
        plugin_id="ht-1", operation_id="op-1", surface="s", bus=EventBus(), config=dict(config)
    )
    primero.restore_deployed_state()  # baseline "ahora", sin nada guardado
    assert _accesos(primero.check_access()) == []
    baseline = primero.export_baseline()

    senuelo.read_text(encoding="utf-8")
    segundo = HoneytokenPlugin(
        plugin_id="ht-1", operation_id="op-1", surface="s", bus=EventBus(), config=dict(config)
    )
    segundo.restore_deployed_state()
    segundo.load_baseline(baseline)
    assert _accesos(segundo.check_access()), "el senuelo quedo ciego tras fijar el baseline"
