"""E4 de docs/improvements.md: `credenciales.xlsx` era uno de los dos
nombres por defecto y el archivo desplegado contenia CSV en texto plano.

Medido antes del fix, sobre el senuelo realmente escrito:

    b'usuario,password\\nsvc_backup,B4ckup_2024!\\n'
    file(1) dice: ASCII text
    empieza con PK\\x03\\x04 (ZIP/OOXML, como un .xlsx real): False

Un senuelo que se delata al abrirlo -- o al correrle `file` -- es peor que
no tenerlo: le confirma al adversario que hay engano desplegado.
"""

from __future__ import annotations

import pytest

from apate.plugins.base import EventBus
from apate.plugins.exceptions import HoneytokenFileError
from apate.plugins.honeytoken import _DEFAULT_FILENAMES, HoneytokenPlugin


def _plugin(tmp_path, **config):
    return HoneytokenPlugin(
        plugin_id="ht-1",
        operation_id="op-1",
        surface="Archivos / credenciales",
        bus=EventBus(),
        config={"directory": str(tmp_path / "share"), **config},
    )


# -- El default deja de prometer un formato que no genera ---------------


def test_no_default_filename_promises_a_binary_format():
    assert not [f for f in _DEFAULT_FILENAMES if f.endswith((".xlsx", ".xls", ".ods"))]


def test_the_tabular_default_really_is_a_csv(tmp_path):
    plugin = _plugin(tmp_path)
    plugin.deploy()
    contenido = (tmp_path / "share" / "credenciales.csv").read_text(encoding="utf-8")
    primera, segunda = contenido.splitlines()[:2]
    assert primera == "usuario,password"
    assert "," in segunda


# -- Un formato que no se puede generar falla claro ---------------------


@pytest.mark.parametrize("nombre", ["credenciales.xlsx", "cuentas.XLS", "planilla.ods"])
def test_deploy_refuses_a_format_it_cannot_generate(tmp_path, nombre):
    plugin = _plugin(tmp_path, filenames=[nombre])
    with pytest.raises(HoneytokenFileError) as exc:
        plugin.deploy()
    assert nombre in str(exc.value)
    assert ".csv" in str(exc.value), "el error tiene que decir que usar en su lugar"


def test_nothing_is_written_when_one_filename_is_invalid(tmp_path):
    """Falla antes de escribir: desplegar la mitad del conjunto y abortar
    dejaria senuelos huerfanos que retire() no conoce."""

    plugin = _plugin(tmp_path, filenames=["valido.txt", "invalido.xlsx"])
    with pytest.raises(HoneytokenFileError):
        plugin.deploy()
    assert not (tmp_path / "share" / "valido.txt").exists()


def test_plain_text_and_csv_are_accepted(tmp_path):
    plugin = _plugin(tmp_path, filenames=["notas.txt", "cuentas.csv", "sin_extension"])
    plugin.deploy()
    for nombre in ("notas.txt", "cuentas.csv", "sin_extension"):
        assert (tmp_path / "share" / nombre).exists()
