"""E5 de docs/improvements.md: las credenciales senuelo por defecto eran
literales fijos en un repositorio publico.

    _DEFAULT_FAKE_CREDENTIALS = {
        "username": "svc_backup",
        "password": "B4ckup_2024!",
        "connection_string": "Server=db-prod-01;Database=finance;...",
    }

El repositorio es AGPLv3 y publico, asi que cualquiera podia buscar esa
contrasena y reconocer un honeytoken de esta herramienta por su contenido,
sin tocarlo. El contenido senuelo por defecto era un IOC de la propia
herramienta.
"""

from __future__ import annotations

from apate.plugins import honeytoken as modulo
from apate.plugins.base import EventBus
from apate.plugins.honeytoken import HoneytokenPlugin


def _plugin(tmp_path, **config):
    return HoneytokenPlugin(
        plugin_id="ht-1",
        operation_id="op-1",
        surface="Archivos / credenciales",
        bus=EventBus(),
        config={"directory": str(tmp_path), "filenames": ["creds.txt"], **config},
    )


def _contenido(tmp_path):
    return (tmp_path / "creds.txt").read_text(encoding="utf-8")


# -- No queda ningun literal publicado ----------------------------------


def test_the_published_literal_is_gone():
    assert not hasattr(modulo, "_DEFAULT_FAKE_CREDENTIALS")


def test_the_old_literal_is_not_deployed_anymore(tmp_path):
    plugin = _plugin(tmp_path)
    plugin.deploy()
    assert "B4ckup_2024!" not in _contenido(tmp_path)


def test_two_deployments_do_not_share_credentials(tmp_path):
    """Es lo que rompe el fingerprint: no que el vocabulario sea secreto,
    sino que la combinacion desplegada no sea predecible."""

    generadas = {
        modulo._generate_fake_credentials()["connection_string"] for _ in range(40)
    }
    assert len(generadas) > 1


# -- El senuelo sigue siendo completo y coherente -----------------------


def test_generated_credentials_have_every_field(tmp_path):
    plugin = _plugin(tmp_path)
    plugin.deploy()
    claves = dict(
        linea.split(": ", 1) for linea in _contenido(tmp_path).strip().splitlines() if ": " in linea
    )
    assert set(claves) == {"username", "password", "connection_string"}


def test_the_connection_string_matches_the_generated_credentials(tmp_path):
    credenciales = modulo._generate_fake_credentials()
    assert credenciales["username"] in credenciales["connection_string"]
    assert credenciales["password"] in credenciales["connection_string"]


# -- Lo que configura el operador sigue ganando -------------------------


def test_operator_credentials_win_field_by_field(tmp_path):
    plugin = _plugin(tmp_path, fake_credentials={"username": "root_prod", "password": "Sup3rSecret"})
    plugin.deploy()
    contenido = _contenido(tmp_path)
    assert "root_prod" in contenido
    assert "Sup3rSecret" in contenido


def test_a_missing_field_is_generated_not_taken_from_a_literal(tmp_path):
    plugin = _plugin(tmp_path, fake_credentials={"username": "root_prod"})
    plugin.deploy()
    contenido = _contenido(tmp_path)
    assert "root_prod" in contenido
    assert "B4ckup_2024!" not in contenido
    assert "password: " in contenido


# -- Se fijan en la config para que rotate() sea coherente --------------


def test_deploy_pins_the_credentials_into_the_config(tmp_path):
    """La web construye una instancia nueva por request: sin fijarlas, un
    rotate() posterior generaria credenciales distintas de las del archivo."""

    plugin = _plugin(tmp_path)
    plugin.deploy()
    fijadas = plugin.config["fake_credentials"]
    assert fijadas["password"] in _contenido(tmp_path)


def test_rotate_starts_from_the_pinned_credentials(tmp_path):
    plugin = _plugin(tmp_path)
    plugin.deploy()
    usuario = plugin.config["fake_credentials"]["username"]
    plugin.rotate()
    assert f"username: {usuario}" in _contenido(tmp_path)
