"""El estado de ejecución vive en `APATE_DATA_DIR`, no en el directorio de trabajo.

**Por qué esto importa más de lo que parece.** DOLOS-T y BUDA guardaban su
estado con rutas relativas: `logs/`, `buda.db`, `docker_client_config/`,
`context.json`, `config_llm.json`. En el checkout de desarrollo eso coincide con
la raíz del repositorio y no se nota nunca. En la máquina de un cliente, el
directorio de trabajo lo decide quien arranca el proceso, y eso dejaba tres
fallas que sólo aparecen allá: un arranque que muere en el import, un estado que
se pierde en la próxima reinstalación, y dos instalaciones pisándose.

El más grave era el `os.makedirs("logs")` **a nivel de módulo** de
`BUDA/utils/logger.py`: está en la cadena de imports obligatoria de `apate.web`,
así que un `gunicorn` bajo systemd sin `WorkingDirectory` moría antes de existir.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from apate.runtime_paths import publish, runtime_dir, runtime_path
from apate.web import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]


# -- La resolución -----------------------------------------------------


def test_sin_variable_se_usa_el_directorio_de_trabajo(monkeypatch, tmp_path):
    """DOLOS-T y BUDA también corren solos: ahí el comportamiento es el de antes."""

    monkeypatch.delenv("APATE_DATA_DIR", raising=False)
    monkeypatch.chdir(tmp_path)

    assert runtime_dir() == Path.cwd()


def test_con_variable_todo_cuelga_de_ahi(monkeypatch, tmp_path):
    monkeypatch.setenv("APATE_DATA_DIR", str(tmp_path / "datos"))

    assert runtime_path("logs") == tmp_path / "datos" / "logs"


def test_una_variable_en_blanco_cuenta_como_ausente(monkeypatch, tmp_path):
    monkeypatch.setenv("APATE_DATA_DIR", "   ")
    monkeypatch.chdir(tmp_path)

    assert runtime_dir() == Path.cwd()


def test_publish_deja_la_ruta_absoluta(monkeypatch, tmp_path):
    """El código vendorizado la lee del entorno mucho después, y posiblemente
    desde otro directorio de trabajo: una ruta relativa ahí no sirve."""

    monkeypatch.chdir(tmp_path)
    (tmp_path / "datos").mkdir()

    publish("datos")

    assert Path(os.environ["APATE_DATA_DIR"]).is_absolute()


# -- El import que mataba el arranque ----------------------------------


def test_importar_apate_web_no_escribe_en_el_directorio_de_trabajo(tmp_path):
    """**La regresión del peor caso.**

    Se importa `apate.web` en un proceso limpio cuyo directorio de trabajo es
    de sólo lectura. Antes esto moría con `PermissionError` desde
    `BUDA/utils/logger.py`, que hacía `os.makedirs` al importarse.
    """

    solo_lectura = tmp_path / "sin-escritura"
    solo_lectura.mkdir()
    os.chmod(solo_lectura, 0o500)
    try:
        resultado = subprocess.run(
            [sys.executable, "-c", "import apate.web; print('importado')"],
            cwd=solo_lectura,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src"), "APATE_DATA_DIR": str(tmp_path / "datos")},
        )
    finally:
        os.chmod(solo_lectura, 0o700)

    assert resultado.returncode == 0, resultado.stderr
    assert "importado" in resultado.stdout
    assert not (solo_lectura / "logs").exists()


def test_el_modulo_de_logs_no_crea_nada_al_importarse(monkeypatch, tmp_path):
    monkeypatch.setenv("APATE_DATA_DIR", str(tmp_path / "datos"))

    import importlib

    import BUDA.utils.logger as modulo

    importlib.reload(modulo)

    assert not (tmp_path / "datos" / "logs").exists()


def test_los_logs_de_comandos_caen_bajo_el_directorio_declarado(monkeypatch, tmp_path):
    monkeypatch.setenv("APATE_DATA_DIR", str(tmp_path / "datos"))

    from BUDA.utils.logger import get_log_filename

    assert str(tmp_path / "datos" / "logs") in get_log_filename()


def test_un_log_que_no_se_puede_abrir_no_detiene_la_narrativa(monkeypatch, tmp_path):
    """Perder una línea de log es malo; que un log caído detenga una operación
    de engaño es peor."""

    import logging

    from BUDA.utils import logger as modulo

    monkeypatch.setenv("APATE_DATA_DIR", str(tmp_path / "datos"))
    logging.getLogger("command_execution").handlers.clear()
    monkeypatch.setattr(modulo.os, "makedirs", lambda *a, **k: (_ for _ in ()).throw(OSError("sin permiso")))

    modulo.log_command(1, "ana", "Get-Date", "ok")  # no levanta

    logging.getLogger("command_execution").handlers.clear()


# -- Las otras tres rutas ----------------------------------------------


def test_la_config_de_docker_cuelga_del_directorio_declarado(monkeypatch, tmp_path):
    monkeypatch.setenv("APATE_DATA_DIR", str(tmp_path / "datos"))

    from DOLOST.context import Context

    assert str(tmp_path / "datos") in Context.config_path()
    assert Context.config_path().endswith("config.json")


def test_la_config_del_modelo_cuelga_del_directorio_declarado(monkeypatch, tmp_path):
    monkeypatch.setenv("APATE_DATA_DIR", str(tmp_path / "datos"))

    from BUDA.utils.config_utils import _config_file

    assert str(tmp_path / "datos") in _config_file()


def test_la_base_de_buda_cae_en_el_directorio_de_datos(tmp_path, monkeypatch):
    monkeypatch.delenv("APATE_BUDA_DATABASE_URI", raising=False)

    app = create_app({
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "datos",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
    })

    assert str((tmp_path / "datos").resolve()) in app.config["SQLALCHEMY_DATABASE_URI"]


def test_create_app_publica_el_directorio_para_el_codigo_vendorizado(tmp_path, monkeypatch):
    """El puente: el código vendorizado no puede leer `app.config`."""

    monkeypatch.delenv("APATE_DATA_DIR", raising=False)

    create_app({
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "datos",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
    })

    assert os.environ["APATE_DATA_DIR"] == str((tmp_path / "datos").resolve())


# -- El preflight ------------------------------------------------------


def _app(tmp_path, **extra):
    return create_app({
        "TESTING": True,
        "APATE_DATA_DIR": tmp_path / "datos",
        "APATE_RULES_PATH": tmp_path / "rules.yaml",
        "APATE_MOUNT_EXTERNAL_TOOLS": False,
        **extra,
    })


def test_un_directorio_que_no_se_puede_crear_falla_temprano_y_lo_dice(tmp_path, monkeypatch):
    """Antes el primer fallo real ocurría dentro de `SecretCipher` y salía como
    un `PermissionError` crudo desde el import del WSGI, que gunicorn reporta
    como "Worker failed to boot" sin decir qué directorio ni por qué.

    Se simula el error en vez de usar permisos del sistema de archivos: la
    suite corre como root en algunos entornos y en Windows los bits de permiso
    no significan lo mismo, así que un `chmod` haría que este test pase por no
    fallar nunca.
    """

    def _explota(self, *args, **kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr(Path, "mkdir", _explota)

    with pytest.raises(RuntimeError, match="no puede escribir en su directorio de datos"):
        _app(tmp_path)


def test_un_directorio_que_existe_pero_no_admite_escritura_tambien(tmp_path, monkeypatch):
    """Existir y ser escribible no son lo mismo: el caso real es un volumen
    montado con otro dueño, donde `mkdir(exist_ok=True)` no falla y el primer
    `open()` sí. Por eso el preflight escribe de verdad en vez de conformarse
    con que el directorio exista.
    """

    original = Path.write_text

    def _explota_en_la_prueba(self, *args, **kwargs):
        if self.name == ".apate-escritura":
            raise PermissionError("Permission denied")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _explota_en_la_prueba)

    with pytest.raises(RuntimeError, match="APATE_DATA_DIR"):
        _app(tmp_path)


def test_el_mensaje_nombra_la_ruta_concreta(tmp_path, monkeypatch):
    """Un error de arranque que no dice qué ruta obliga a leer el código."""

    monkeypatch.setattr(Path, "mkdir", lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("nope")))

    with pytest.raises(RuntimeError) as fallo:
        _app(tmp_path)

    assert str(tmp_path / "datos") in str(fallo.value)
