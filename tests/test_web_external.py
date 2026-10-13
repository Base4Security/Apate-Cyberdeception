"""Tests para DOLOS-T (M14b) y BUDA (M14e) como librerias puras dentro
del proceso de APATE - ver apate.web.external.

Sin Docker ni WinRM reales: estos tests verifican que ninguna de las
dos herramientas registra ya ningun blueprint Flask (`/dolost/...` y
`/buda/...` devuelven 404 parejo), que sus assets estaticos dejaron de
servirse, y que eso no rompe nada de lo propio de APATE (paginas,
`/static/...`, SocketIO) -- no ejercitan deploy()/rotate()/retire()
(eso se prueba contra los adaptadores de plugin, con Docker/WinRM
mockeados, en test_plugins_dolost.py/test_plugins_buda.py)."""

import pytest

from apate.web import create_app


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


def test_external_tools_mounted_by_default(mounted_app):
    assert mounted_app.config["APATE_MOUNT_EXTERNAL_TOOLS"] is True


# -- M14b: retiro del blueprint de DOLOS-T -----------------------------------


def test_dolost_blueprint_routes_are_not_registered(mounted_app):
    # mount_dolost() ya no registra ningun blueprint Flask (ver
    # apate.web.external) -- ninguna ruta bajo /dolost/... existe en el
    # url_map, ni la de views_blueprint ni la de api_blueprint.
    rules = {r.rule for r in mounted_app.url_map.iter_rules()}
    assert not any(rule.startswith("/dolost") for rule in rules)


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/dolost/activity"),
        ("GET", "/dolost/operations"),
        ("GET", "/dolost/operations/view/1"),
        ("GET", "/dolost/config/docker_client"),
        ("POST", "/dolost/api/operations/new"),
        ("POST", "/dolost/api/operations/1/edit"),
        ("DELETE", "/dolost/api/operations/remove/1"),
        ("POST", "/dolost/api/operations/1/decoy/new"),
        ("POST", "/dolost/api/decoys/start"),
        ("POST", "/dolost/api/decoys/stop"),
        ("POST", "/dolost/api/config/docker_client"),
    ],
)
def test_dolost_blueprint_routes_return_404(mounted_client, method, path):
    # Cubre explicitamente las rutas de operationsdb.json (confirmado
    # con el usuario que nunca se uso en la demo real -- sin datos que
    # migrar, M14b las retira directo) y una muestra del resto de la
    # superficie vieja de DOLOS-T -- 404 (ruta inexistente), no 200 ni
    # ningun otro codigo que sugiera que el blueprint sigue vivo.
    response = mounted_client.open(path, method=method)
    assert response.status_code == 404


# -- M14e: retiro del blueprint de BUDA --------------------------------------


def test_buda_blueprint_routes_are_not_registered(mounted_app):
    # mount_buda() ya no registra ninguno de sus nueve blueprints Flask
    # (ver apate.web.external) -- ninguna ruta bajo /buda/... existe en
    # el url_map.
    rules = {r.rule for r in mounted_app.url_map.iter_rules()}
    assert not any(rule.startswith("/buda") for rule in rules)


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/buda/"),
        ("GET", "/buda/context/"),
        ("GET", "/buda/narratives/"),
        ("GET", "/buda/user_profiles/"),
        ("GET", "/buda/activities/"),
        ("GET", "/buda/narrative_review/"),
        ("GET", "/buda/statistics/"),
        ("POST", "/buda/ai/generate/activitytype"),
        ("POST", "/buda/ai/generate_commands/1"),
        ("GET", "/buda/settings/"),
    ],
)
def test_buda_blueprint_routes_return_404(mounted_client, method, path):
    # Cubre los nueve blueprints retirados (root_bp/context_bp/
    # narratives_bp/user_profiles_bp/activities_bp/narrative_review_bp/
    # statistics_bp/ai_bp/settings_bp) -- 404 parejo, mismo patron que
    # test_dolost_blueprint_routes_return_404 desde M14b.
    response = mounted_client.open(path, method=method)
    assert response.status_code == 404


def test_apate_own_pages_still_render_correctly_when_mounted(mounted_client):
    # Con DOLOS-T (M14b) y BUDA (M14e) sin ningun blueprint propio, la
    # colision de templates que _BlueprintAwareLoader resolvia hasta
    # M14e es estructuralmente imposible (retirado, ver
    # apate.web.external) -- este test confirma que las paginas propias
    # de APATE siguen renderizando bien con el loader por defecto de
    # Flask.
    response = mounted_client.get("/operations/")
    assert response.status_code == 200
    assert b"Apate" in response.data


def test_dolost_static_asset_no_longer_served(mounted_client):
    # M14b: DOLOS-T ya no aporta ningun directorio a static_dirs (ver
    # create_app()) -- este archivo real de DOLOST/static/js/ deja de
    # resolver, ya que nada vuelve a pedirlo (sin blueprint que
    # renderice sus templates).
    response = mounted_client.get("/static/js/theme_switcher.js")
    assert response.status_code == 404


def test_buda_static_asset_no_longer_served(mounted_client):
    # M14e: mismo caso que DOLOS-T arriba -- BUDA ya no aporta su
    # carpeta static/ a static_dirs (ver create_app()), este archivo
    # real de BUDA/static/images/ deja de resolver.
    response = mounted_client.get("/static/images/logo.png")
    assert response.status_code == 404


def test_unknown_static_asset_returns_404(mounted_client):
    response = mounted_client.get("/static/does-not-exist.js")
    assert response.status_code == 404


def test_socketio_extension_is_registered_when_mounted(mounted_app):
    assert "socketio" in mounted_app.extensions


def test_mount_dolost_reuses_the_given_socketio_instance_instead_of_creating_a_second_one():
    # M13f: mount_dolost() ya no crea su propia SocketIO(app, ...) --
    # la recibe. Regresion real que esto evita: Flask-SocketIO guarda
    # la instancia en app.extensions['socketio'], asi que si
    # mount_dolost() volviera a crear una propia por error, esa
    # llamada pisaria silenciosamente la que ya estaba ahi (la que
    # create_app() ya le habia pasado a todo lo demas, incluida la
    # suscripcion de notificaciones de M13f) -- se arma la instancia
    # una sola vez, aca mismo (no via create_app(), para poder
    # comparar identidad contra un unico punto de creacion conocido),
    # y se confirma que sigue siendo la misma despues de mount_dolost().
    from flask import Flask
    from flask_socketio import SocketIO

    from apate.web.external import mount_dolost

    app = Flask(__name__)
    socketio = SocketIO(app, async_mode="threading")

    result = mount_dolost(app, socketio)

    assert result is socketio
    assert app.extensions["socketio"] is socketio


def test_nav_never_links_dolost_or_buda_even_when_mounted(mounted_client):
    # Decision de la fase de construccion de la UI oscura unificada: la
    # navegacion de APATE nunca enlazo /dolost ni /buda como secciones
    # de primer nivel (las pantallas que administraban ahi se
    # reclasificaron como "operacion", ver docs/roadmap.md) -- desde
    # M14b/M14e esas rutas directamente no existen mas, asi que esto
    # ahora es tambien una consecuencia trivial de
    # test_dolost_blueprint_routes_return_404/
    # test_buda_blueprint_routes_return_404, no solo una decision de UI.
    response = mounted_client.get("/operations/")
    assert b'href="/dolost"' not in response.data
    assert b'href="/buda"' not in response.data


# -- APATE_MOUNT_EXTERNAL_TOOLS=False --------------------------------------


def test_external_tools_can_be_disabled(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )

    rules = {r.rule for r in app.url_map.iter_rules()}
    assert not any(rule.startswith("/dolost") for rule in rules)
    assert not any(rule.startswith("/buda") for rule in rules)
    # M13f: la instancia de SocketIO ya no depende de este flag -- es
    # justo la regresion que M13f existe para prevenir (antes de este
    # hito, esta asercion era la inversa: "socketio" not in
    # app.extensions). Sigue existiendo con APATE_MOUNT_EXTERNAL_TOOLS
    # en False porque cualquier notificacion propia de APATE (no de
    # DOLOS-T) la necesita disponible siempre, sin depender de que
    # DOLOST/BUDA esten instalados.
    assert "socketio" in app.extensions


def test_nav_hides_dolost_and_buda_links_when_disabled(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )
    response = app.test_client().get("/operations/")

    assert b'href="/dolost"' not in response.data
    assert b'href="/buda"' not in response.data


# -- Ubicacion de la base de BUDA (APATE_BUDA_DATABASE_URI) ------------------


def test_buda_database_uri_can_point_to_persistent_storage(tmp_path, monkeypatch):
    """El default de `mount_buda()` es un URI relativo que Flask resuelve
    contra `instance_path`: dentro del entorno de Python, fuera de
    `APATE_DATA_DIR`. En una instalacion con almacenamiento persistente
    montado aparte (un volumen), eso perderia las narrativas simuladas en
    cada reinstalacion mientras los `PluginBinding` que las referencian
    sobreviven. La variable permite apuntarla al mismo almacenamiento."""

    target = tmp_path / "buda-persistente.db"
    monkeypatch.setenv("APATE_BUDA_DATABASE_URI", f"sqlite:///{target}")

    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
        }
    )

    assert app.config["SQLALCHEMY_DATABASE_URI"] == f"sqlite:///{target}"
    # `mount_buda()` corre `db.create_all()`: el archivo tiene que quedar
    # donde se pidio, no en `instance_path`.
    assert target.exists()


def test_explicit_config_wins_over_buda_database_uri_environment(tmp_path, monkeypatch):
    """Misma prioridad que ya tenia `mount_buda()`: un
    `SQLALCHEMY_DATABASE_URI` explicito (los tests de este archivo) no lo
    pisa nada."""

    monkeypatch.setenv("APATE_BUDA_DATABASE_URI", f"sqlite:///{tmp_path / 'ignorada.db'}")
    explicit = f"sqlite:///{tmp_path / 'explicita.db'}"

    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
            "SQLALCHEMY_DATABASE_URI": explicit,
        }
    )

    assert app.config["SQLALCHEMY_DATABASE_URI"] == explicit


def test_no_buda_database_uri_falls_back_to_the_data_directory(tmp_path, monkeypatch):
    """Sin la variable, la base de BUDA cae en `APATE_DATA_DIR`.

    **Cambio deliberado de contrato.** Antes `create_app()` no fijaba nada y
    la resolvia `mount_buda()` con `sqlite:///buda.db`, una ruta relativa que
    Flask interpreta contra su `instance_path` -- dentro del entorno de
    Python. En una instalacion de sistema eso es un directorio que el usuario
    de servicio no escribe (y el arranque revienta), o uno que se borra en la
    proxima reinstalacion, llevandose las narrativas mientras los
    `PluginBinding` que las referencian sobreviven en el almacenamiento de
    operaciones. Ver `docs/riesgos-piloto.md`, seccion 2.2.
    """

    monkeypatch.delenv("APATE_BUDA_DATABASE_URI", raising=False)

    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )

    uri = app.config["SQLALCHEMY_DATABASE_URI"]
    assert uri.startswith("sqlite:///")
    assert str((tmp_path / "data").resolve()) in uri
    assert uri.endswith("buda.db")


def test_an_explicit_buda_database_uri_still_wins(tmp_path, monkeypatch):
    """El default nuevo no le pisa la eleccion a quien la declara."""

    monkeypatch.setenv("APATE_BUDA_DATABASE_URI", "sqlite:///ruta/elegida.db")

    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )

    assert app.config["SQLALCHEMY_DATABASE_URI"] == "sqlite:///ruta/elegida.db"
