"""E6 de docs/improvements.md: rotate() dejaba dos contrasenas distintas
para la misma cuenta en el mismo archivo.

Solo `credentials["password"]` recibia el sufijo; `connection_string` se
escribia tal cual, con la contrasena original embebida. Archivo real
despues de rotar, antes del fix:

    username: svc_backup
    password: B4ckup_2024!-62d8a7
    connection_string: Server=db-prod-01;...;Password=B4ckup_2024!;

Ademas de ser incoherente, contradecia el proposito declarado de rotate()
("que un hash/firma estatica del senuelo deje de servir"): la mitad del
contenido no cambiaba nunca.
"""

from __future__ import annotations

from apate.plugins.base import EventBus
from apate.plugins.honeytoken import _rotate_credentials, HoneytokenPlugin


def _plugin(tmp_path, **config):
    p = HoneytokenPlugin(
        plugin_id="ht-1",
        operation_id="op-1",
        surface="Archivos / credenciales",
        bus=EventBus(),
        config={"directory": str(tmp_path), "filenames": ["creds.txt"], **config},
    )
    p.deploy()
    return p


def _campos(tmp_path):
    texto = (tmp_path / "creds.txt").read_text(encoding="utf-8")
    return dict(linea.split(": ", 1) for linea in texto.strip().splitlines() if ": " in linea)


# -- El archivo queda coherente -----------------------------------------


def test_the_rotated_password_is_the_one_in_the_connection_string(tmp_path):
    plugin = _plugin(tmp_path)
    plugin.rotate()
    campos = _campos(tmp_path)
    assert campos["password"] in campos["connection_string"]


def test_the_old_password_is_gone_from_every_field(tmp_path):
    plugin = _plugin(tmp_path)
    anterior = plugin.config["fake_credentials"]["password"]
    plugin.rotate()
    for valor in _campos(tmp_path).values():
        assert f"Password={anterior};" not in valor


def test_every_field_changes_on_rotation(tmp_path):
    """La mitad del contenido no cambiaba nunca, asi que una firma estatica
    sobre esa mitad seguia sirviendo."""

    plugin = _plugin(tmp_path)
    antes = _campos(tmp_path)
    plugin.rotate()
    despues = _campos(tmp_path)
    assert despues["password"] != antes["password"]
    assert despues["connection_string"] != antes["connection_string"]


def test_the_username_is_stable_across_rotations(tmp_path):
    """rotate() cambia la contrasena, no la identidad de la cuenta."""

    plugin = _plugin(tmp_path)
    antes = _campos(tmp_path)["username"]
    plugin.rotate()
    assert _campos(tmp_path)["username"] == antes


# -- _rotate_credentials() en aislamiento -------------------------------


def test_rotation_updates_any_field_holding_the_password():
    rotadas = _rotate_credentials(
        {
            "username": "u",
            "password": "Secreta_1!",
            "connection_string": "Password=Secreta_1!;",
            "uri": "mssql://u:Secreta_1!@host/db",
        }
    )
    assert rotadas["password"] != "Secreta_1!"
    for clave in ("connection_string", "uri"):
        assert "Secreta_1!;" not in rotadas[clave].replace(rotadas["password"], "")
        assert rotadas["password"] in rotadas[clave]


def test_rotation_leaves_unrelated_fields_untouched():
    rotadas = _rotate_credentials(
        {"username": "svc", "password": "Secreta_1!", "connection_string": "Server=db;"}
    )
    assert rotadas["username"] == "svc"
    assert rotadas["connection_string"] == "Server=db;"


def test_rotation_does_not_compound_the_suffix(tmp_path):
    """Cada rotate() parte de las credenciales fijadas en deploy(), asi que
    el sufijo no se acumula."""

    plugin = _plugin(tmp_path)
    plugin.rotate()
    primera = _campos(tmp_path)["password"]
    plugin.rotate()
    segunda = _campos(tmp_path)["password"]
    assert primera != segunda
    assert segunda.count("-") == primera.count("-")
