import os
import time

import pytest

from apate.plugins import EventBus, EventType, HoneytokenPlugin, PluginLifecycleState, PluginStateError
from apate.plugins.exceptions import HoneytokenFileError


def _make_plugin(bus: EventBus = None, **config_overrides) -> HoneytokenPlugin:
    config = {"directory": None}
    config.update(config_overrides)
    return HoneytokenPlugin(
        plugin_id="honeytoken-1",
        surface="data",
        operation_id="op-1",
        bus=bus if bus is not None else EventBus(),
        config=config,
    )


def _bump_atime(path, *, seconds: float = 5) -> None:
    """Simula una lectura externa del archivo. No se usa una lectura
    real (open(path).read()) porque el sistema de archivos de la
    maquina que corre los tests puede tener actualizacion de atime
    deshabilitada (noatime en Linux, NtfsDisableLastAccessUpdate en
    Windows -- ver el docstring de honeytoken.py): os.utime() prueba
    la logica de comparacion del plugin en si, no el comportamiento de
    atime del filesystem subyacente, que es exactamente lo que
    check_access() no puede controlar."""

    stat_result = os.stat(path)
    os.utime(path, (stat_result.st_atime + seconds, stat_result.st_mtime))


# -- deploy() -----------------------------------------------------------


def test_deploy_without_directory_in_config_raises_honeytoken_file_error():
    plugin = _make_plugin()
    with pytest.raises(HoneytokenFileError):
        plugin.deploy()


def test_deploy_creates_default_filenames_with_plausible_content(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()

    created = sorted(p.name for p in tmp_path.iterdir())
    assert created == sorted(["credenciales.csv", "passwords_backup.txt"])

    # El contenido ya no se compara contra un literal fijo: las
    # credenciales se generan por despliegue (E5 de docs/improvements.md).
    # Lo que se verifica es que el senuelo sea completo y plausible.
    txt_content = (tmp_path / "passwords_backup.txt").read_text(encoding="utf-8")
    claves = dict(
        linea.split(": ", 1) for linea in txt_content.strip().splitlines() if ": " in linea
    )
    assert set(claves) == {"username", "password", "connection_string"}
    assert all(valor.strip() for valor in claves.values())
    assert claves["username"] in claves["connection_string"]


def test_deploy_respects_custom_filenames_and_credentials(tmp_path):
    plugin = _make_plugin(
        directory=str(tmp_path),
        filenames=["db_backup.csv"],
        fake_credentials={"username": "root_prod", "password": "Sup3rSecret"},
    )
    plugin.deploy()

    content = (tmp_path / "db_backup.csv").read_text(encoding="utf-8")
    assert "root_prod" in content
    assert "Sup3rSecret" in content


def test_deploy_creates_missing_directory(tmp_path):
    directory = tmp_path / "shared" / "finanzas"
    plugin = _make_plugin(directory=str(directory))

    plugin.deploy()

    assert directory.is_dir()
    assert (directory / "credenciales.csv").exists()


def test_deploy_emits_interaction_event_with_paths(tmp_path):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    _make_plugin(bus=bus, directory=str(tmp_path)).deploy()

    assert len(received) == 1
    assert received[0].payload["kind"] == "deploy"
    assert len(received[0].payload["paths"]) == 2


def test_deploy_sets_state_to_deployed(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()
    assert plugin.state == PluginLifecycleState.DEPLOYED


def test_deploy_twice_raises_plugin_state_error(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()
    with pytest.raises(PluginStateError):
        plugin.deploy()


# -- check_access() -------------------------------------------------------


def test_check_access_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.check_access()


def test_check_access_without_external_touch_returns_no_events(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()

    assert plugin.check_access() == []


def test_check_access_detects_simulated_read_via_atime(tmp_path):
    bus = EventBus()
    interactions = []
    ttps = []
    bus.subscribe(EventType.INTERACTION, interactions.append)
    bus.subscribe(EventType.TTP_OBSERVED, ttps.append)

    plugin = _make_plugin(bus=bus, directory=str(tmp_path))
    plugin.deploy()
    interactions.clear()

    target = tmp_path / "passwords_backup.txt"
    _bump_atime(target)

    events = plugin.check_access()

    assert len(events) == 2
    assert len(interactions) == 1
    assert interactions[0].payload["kind"] == "access"
    assert interactions[0].payload["path"] == str(target)
    assert interactions[0].resource_id == f"honeytoken:{target}"
    assert len(ttps) == 1
    assert ttps[0].payload["ttp_id"] == "T1552.001"
    assert ttps[0].resource_id == f"honeytoken:{target}"


def test_check_access_detects_real_content_modification(tmp_path):
    bus = EventBus()
    interactions = []
    bus.subscribe(EventType.INTERACTION, interactions.append)

    plugin = _make_plugin(bus=bus, directory=str(tmp_path))
    plugin.deploy()
    interactions.clear()

    target = tmp_path / "passwords_backup.txt"
    time.sleep(0.05)
    target.write_text("modificado por el atacante", encoding="utf-8")

    events = plugin.check_access()

    assert len(events) == 2
    assert interactions[0].payload["kind"] == "modified"


def test_check_access_uses_custom_ttp_id(tmp_path):
    bus = EventBus()
    ttps = []
    bus.subscribe(EventType.TTP_OBSERVED, ttps.append)

    plugin = _make_plugin(bus=bus, directory=str(tmp_path), ttp_id="T1005")
    plugin.deploy()
    _bump_atime(tmp_path / "credenciales.csv")

    plugin.check_access()

    assert ttps[0].payload["ttp_id"] == "T1005"


def test_check_access_does_not_report_the_same_access_twice(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()

    _bump_atime(tmp_path / "passwords_backup.txt")
    first = plugin.check_access()
    second = plugin.check_access()

    assert len(first) == 2
    assert second == []


def test_check_access_skips_externally_deleted_file_without_raising(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()

    (tmp_path / "passwords_backup.txt").unlink()

    assert plugin.check_access() == []


# -- rotate() ---------------------------------------------------------------


def test_rotate_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.rotate()


def test_rotate_changes_content_and_keeps_deployed_state(tmp_path):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus, directory=str(tmp_path))
    plugin.deploy()
    target = tmp_path / "passwords_backup.txt"
    original_content = target.read_text(encoding="utf-8")
    received.clear()

    plugin.rotate()

    assert target.read_text(encoding="utf-8") != original_content
    assert plugin.state == PluginLifecycleState.DEPLOYED
    assert len(received) == 1
    assert received[0].payload["kind"] == "rotate"


def test_rotate_resets_baseline_so_it_does_not_look_like_an_access(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()

    plugin.rotate()

    assert plugin.check_access() == []


# -- retire() -----------------------------------------------------------


def test_retire_before_deploy_raises_plugin_state_error():
    plugin = _make_plugin()
    with pytest.raises(PluginStateError):
        plugin.retire()


def test_retire_removes_all_deployed_files(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()

    plugin.retire()

    assert list(tmp_path.iterdir()) == []
    assert plugin.state == PluginLifecycleState.RETIRED


def test_retire_removes_directory_it_created(tmp_path):
    directory = tmp_path / "solo_para_honeytokens"
    plugin = _make_plugin(directory=str(directory))
    plugin.deploy()

    plugin.retire()

    assert not directory.exists()


def test_retire_does_not_remove_preexisting_directory(tmp_path):
    (tmp_path / "otro_archivo.txt").write_text("no tocar", encoding="utf-8")
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()

    plugin.retire()

    assert tmp_path.exists()
    assert (tmp_path / "otro_archivo.txt").exists()


def test_retire_emits_interaction_event_and_no_orphan_files_remain(tmp_path):
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)

    plugin = _make_plugin(bus=bus, directory=str(tmp_path))
    plugin.deploy()
    received.clear()

    plugin.retire()

    assert len(received) == 1
    assert received[0].payload["kind"] == "retire"
    assert list(tmp_path.iterdir()) == []


def test_retire_twice_raises_plugin_state_error(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()
    plugin.retire()
    with pytest.raises(PluginStateError):
        plugin.retire()


def test_retire_tolerates_file_already_deleted_externally(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path))
    plugin.deploy()
    (tmp_path / "credenciales.csv").unlink()

    plugin.retire()  # no debe lanzar por el archivo ya ausente

    assert plugin.state == PluginLifecycleState.RETIRED


# -- Rehidratación entre requests de la UI contextual -----------------------


def test_configured_paths_does_not_create_or_read_targets(tmp_path):
    plugin = _make_plugin(directory=str(tmp_path), filenames=["uno.txt", "dos.csv"])

    assert plugin.configured_paths() == [tmp_path / "uno.txt", tmp_path / "dos.csv"]
    assert list(tmp_path.iterdir()) == []


def test_restore_deployed_state_allows_rotation_from_new_instance(tmp_path):
    original = _make_plugin(directory=str(tmp_path), filenames=["token.txt"])
    original.deploy()
    before = (tmp_path / "token.txt").read_text(encoding="utf-8")

    restored = _make_plugin(directory=str(tmp_path), filenames=["token.txt"])
    restored.restore_deployed_state()
    restored.rotate()

    assert restored.state == PluginLifecycleState.DEPLOYED
    assert (tmp_path / "token.txt").read_text(encoding="utf-8") != before


def test_restore_deployed_state_rejects_partial_files(tmp_path):
    (tmp_path / "uno.txt").write_text("existente", encoding="utf-8")
    plugin = _make_plugin(directory=str(tmp_path), filenames=["uno.txt", "falta.txt"])

    with pytest.raises(HoneytokenFileError, match="faltan archivos"):
        plugin.restore_deployed_state()


# -- M9 (hardening): las credenciales sinteticas nunca se loguean -----------


def test_events_never_carry_credential_values(tmp_path):
    # deploy()/rotate()/check_access() pueden publicar 'path'/'kind'/
    # 'detail'/'ttp_id', pero nunca el valor de username/password/
    # connection_string -- ver la seccion "Credenciales sinteticas" del
    # docstring de honeytoken.py (M9). Este test fija esa garantia
    # como regresion: si alguna vez alguien agrega el valor de una
    # credencial a un payload, este test tiene que fallar.
    bus = EventBus()
    received = []
    bus.subscribe(EventType.INTERACTION, received.append)
    bus.subscribe(EventType.TTP_OBSERVED, received.append)

    custom_credentials = {
        "username": "root_prod",
        "password": "Sup3rSecret-No-Deberia-Aparecer",
        "connection_string": "Server=algo;Password=Sup3rSecret-No-Deberia-Aparecer;",
    }
    plugin = _make_plugin(bus=bus, directory=str(tmp_path), fake_credentials=custom_credentials)
    plugin.deploy()
    _bump_atime(tmp_path / "credenciales.csv")
    plugin.check_access()
    plugin.rotate()
    plugin.retire()

    assert len(received) >= 4  # deploy, access, ttp_observed, rotate, retire
    secret_values = [custom_credentials["username"], custom_credentials["password"]]
    for event in received:
        for value in event.payload.values():
            for secret in secret_values:
                assert secret not in str(value), (
                    f"el evento {event.payload!r} filtro un valor de credencial"
                )
