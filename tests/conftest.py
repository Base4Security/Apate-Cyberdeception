import pytest
from cryptography.fernet import Fernet

from apate.web import create_app


@pytest.fixture(autouse=True)
def buda_encryption_key(monkeypatch):
    """BUDA.utils.crypto_utils (M8b) necesita esta variable para
    cifrar/descifrar winrm_username/winrm_password -- autouse porque
    cualquier test que monte BUDA (M8c) podria terminar tocando
    UserProfile aunque no sea el foco del test; barato de setear
    siempre e irrelevante para los tests que no montan BUDA."""

    monkeypatch.setenv("BUDA_CREDENTIAL_ENCRYPTION_KEY", Fernet.generate_key().decode())


@pytest.fixture
def app(tmp_path):
    # APATE_MOUNT_EXTERNAL_TOOLS=False (M8c): esta fixture la usan los
    # tests de Operaciones/Reglas/Telemetria/Playground, que no
    # necesitan DOLOS-T/BUDA montados -- montarlos igual solo agregaria
    # tiempo (crea la base de BUDA, importa Docker/WinRM) sin ningun
    # beneficio para esos tests. Los tests que SI ejercitan el montaje
    # (tests/test_web_external.py) arman su propia app con el flag en
    # True (el default de create_app()).
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def csrf_neutralizado(request, monkeypatch):
    """Apaga la verificacion CSRF salvo en los tests marcados con `csrf`.

    **Por que no es una opcion de configuracion.** Una clave que desactive
    CSRF termina activada en la instalacion de alguien, siempre. Aca se
    reemplaza la funcion que la instala, que es un gesto del banco de pruebas
    y no algo que un operador pueda tocar: no existe forma soportada de
    correr APATE sin esta proteccion.

    Se apaga para la suite general porque pasarle el testigo a las ~2000
    peticiones que prueban otra cosa solo agregaria ruido. El mecanismo
    encendido, y que cada formulario de cada plantilla lleve su campo oculto,
    los prueba `tests/test_csrf.py` con `@pytest.mark.csrf`.

    Sigue definiendo `csrf_token()` en Jinja: sin eso, cualquier plantilla que
    lo invoque reventaria en todos los demas tests, y son casi todas.
    """

    if request.node.get_closest_marker("csrf"):
        return

    import apate.web

    def _solo_el_global(app):
        app.jinja_env.globals["csrf_token"] = lambda: "testigo-de-prueba"

    monkeypatch.setattr(apate.web, "_register_csrf", _solo_el_global)
