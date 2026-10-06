"""Tests para la correccion de UI post-M14: las pantallas nativas de
"Herramientas" y los paneles de despliegue se organizan por funci&oacute;n
(superficie que cubren), no por el nombre de la herramienta de origen.
Los nombres de procedencia tampoco se muestran como proveedor: las
capacidades son parte de APATE y se presentan por su función.

El backend ya retiro `mount_dolost()`/`mount_buda()` como blueprints
completos en M14b/M14e (pura libreria Python, sin rutas propias); esta
correccion es del lado de la presentacion, que hasta ahora seguia
separando las pantallas por herramienta de origen, contradiciendo el
objetivo de "un sistema integral unico".

El control de texto renderizado excluye comentarios y scripts porque no
forman parte de la superficie visible. Los nombres de Canarytokens y
OpenCanary sí están permitidos: designan integraciones de terceros."""

import datetime
from html.parser import HTMLParser

import pytest

from apate.core import (
    AdversaryProfile,
    Narrative,
    Operation,
    PluginBinding,
    RulesOfEngagement,
    Scenario,
)
from apate.plugins import buda_plugin as buda_plugin_module
from apate.plugins import dolost_plugin as dolost_plugin_module
from apate.web import create_app

_BRANDED_SUBSTRINGS = ("DOLOS-T", "DOLOST", "BUDA")


class _VisibleTextCollector(HTMLParser):
    """Recoge solo texto que puede llegar al operador.

    Los identificadores técnicos pueden vivir en atributos y los
    comentarios/scripts no se muestran como contenido de la página;
    el control protege el copy visible sin convertir contratos internos
    en restricciones de presentación.
    """

    def __init__(self) -> None:
        super().__init__()
        self._ignored_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag in {"script", "style"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag) -> None:
        if tag in {"script", "style"}:
            self._ignored_depth -= 1

    def handle_data(self, data) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'naming-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


@pytest.fixture
def unmounted_client(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )
    return app.test_client()


@pytest.fixture
def dolost_calls(monkeypatch):
    monkeypatch.setattr(dolost_plugin_module, "deploy_collector", lambda: None)
    monkeypatch.setattr(dolost_plugin_module, "deploy_decoy", lambda decoy: None)
    monkeypatch.setattr(dolost_plugin_module, "clean_decoy", lambda decoy: None)


@pytest.fixture
def dolost_docker_calls(monkeypatch):
    from apate.web.blueprints import health as health_module

    monkeypatch.setattr(health_module._docker_manager, "check_client_configuration", lambda docker_client: True)
    monkeypatch.setattr(health_module._docker_manager, "configure_client", lambda docker_client: None)
    monkeypatch.setattr(health_module._docker_manager, "check_connection", lambda: None)
    monkeypatch.setattr(health_module._docker_manager, "get_current_client_config", lambda: {})


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba",
        adversary_profile=AdversaryProfile(name="APT ficticio", motivation="espionaje", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _make_buda_narrative(app, **overrides) -> int:
    from BUDA.app import db as buda_db
    from BUDA.models import Narrative as BudaNarrative

    defaults = dict(
        title="t",
        objective="o",
        attacker_profile="a",
        deception_activities="d",
        end_date=datetime.date.today(),
        is_running=False,
        percentage_of_similarity=100,
    )
    defaults.update(overrides)
    with app.app_context():
        narrative = BudaNarrative(**defaults)
        buda_db.session.add(narrative)
        buda_db.session.commit()
        return narrative.id


def _assert_no_branded_text(response) -> None:
    parser = _VisibleTextCollector()
    parser.feed(response.get_data(as_text=True))
    # Case-sensitive a proposito. La forma en minuscula ("dolost", "buda") es el
    # `kind` tecnico, y aparece legitimamente dentro de identificadores que
    # elige el propio operador: un binding llamado "dolost-1" es SU nombre de
    # recurso, no una mencion de la herramienta de origen. Buscar sin distinguir
    # mayusculas convertia cada plugin_id en un falso positivo.
    #
    # El caso que esta forma NO cubre -- el kind crudo mostrado como etiqueta y
    # pasado a mayuscula por CSS -- tiene su propio test mas abajo
    # (test_operation_tree_labels_capabilities_by_function).
    visible_text = " ".join(parser.parts)
    for substring in _BRANDED_SUBSTRINGS:
        assert substring not in visible_text, f"{substring!r} filtrado a texto visible del operador"


# -- Nav (base.html) ----------------------------------------------------


def test_nav_never_shows_origin_tool_names_when_mounted(mounted_client):
    response = mounted_client.get("/operations/")
    assert response.status_code == 200
    _assert_no_branded_text(response)


def test_nav_never_shows_origin_tool_names_when_not_mounted(unmounted_client):
    response = unmounted_client.get("/operations/")
    assert response.status_code == 200
    _assert_no_branded_text(response)


# -- Panel "Mecanica especifica" (operations/detail.html) ---------------


def test_operation_detail_panels_do_not_show_origin_tool_names(
    mounted_app, mounted_client, dolost_calls, monkeypatch
):
    # Un dolost-* y un buda-* vinculados a la misma operacion -- los dos
    # tipos de panel de mecanica especifica renderizados a la vez.
    narrative_id = _make_buda_narrative(mounted_app)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    mounted_app.config["OPERATION_REPOSITORY"].save(op)

    response = mounted_client.get(f"/operations/{op.id}")

    assert response.status_code == 200
    assert b"Decoys" in response.data
    assert b"Narrativa de comportamiento simulado" in response.data
    _assert_no_branded_text(response)


# -- Áreas canónicas de integración -------------------------------------


def test_dolost_docker_page_never_shows_origin_tool_name(mounted_client, dolost_docker_calls):
    response = mounted_client.get("/health/configuration/network-host-runtime")
    assert response.status_code == 200
    _assert_no_branded_text(response)


def test_buda_settings_page_never_shows_origin_tool_name_outside_code_blocks(mounted_client):
    response = mounted_client.get("/health/configuration/content-generation")
    assert response.status_code == 200
    _assert_no_branded_text(response)


def test_main_rendered_surfaces_do_not_reintroduce_origin_tool_names(
    mounted_app, mounted_client, dolost_docker_calls
):
    # La operacion lleva escenario, kind explicito y narrativa con contenido a
    # proposito: varias superficies solo se renderizan con datos suficientes.
    # Con un binding suelto y sin escenario, el arbol del tab "Mapa" no dibuja
    # ningun nodo de capacidad y el chequeo de coherencia de la ficcion no se
    # dispara -- y eran justo esos dos los que seguian filtrando el nombre de
    # origen desde codigo Python, no desde una plantilla. Este test pasaba
    # igual: un falso verde.
    operation = _make_operation(
        narrative=Narrative(name="Narrativa base", description="Historia de tapadera con contenido real."),
    )
    scenario = Scenario(description="Escenario de prueba", related_ttps=["T1046"])
    operation.add_scenario(scenario)
    operation.bind_plugin(
        PluginBinding(
            plugin_id="dolost-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id
        )
    )
    operation.bind_plugin(
        PluginBinding(
            plugin_id="buda-1", plugin_kind="buda", surface="identity", scenario_id=scenario.id
        )
    )
    mounted_app.config["OPERATION_REPOSITORY"].save(operation)

    routes = (
        "/operations/",
        "/operations/portfolio",
        "/capabilities/",
        "/health/configuration/network-host-runtime",
        "/health/configuration/content-generation",
        f"/operations/{operation.id}",
        f"/telemetry/{operation.id}",
    )
    for route in routes:
        response = mounted_client.get(route)
        assert response.status_code == 200, route
        _assert_no_branded_text(response)


def test_buda_activities_page_never_shows_origin_tool_name(mounted_client):
    response = mounted_client.get("/capabilities/behavior-activities")
    assert response.status_code == 200
    _assert_no_branded_text(response)


def test_buda_user_profiles_page_never_shows_origin_tool_name(mounted_client):
    response = mounted_client.get("/capabilities/identity-profiles")
    assert response.status_code == 200
    _assert_no_branded_text(response)


def test_buda_context_page_never_shows_origin_tool_name_outside_code_blocks(mounted_client):
    response = mounted_client.get("/capabilities/behavior-context")
    assert response.status_code == 200
    text = response.data.decode()
    assert "vista original de BUDA" not in text


# -- Playground defender (comparacion esperado-vs-observado) ------------


def test_playground_defender_view_never_shows_origin_tool_name(client):
    response = client.post(
        "/operations/new",
        data=dict(name="Operacion Playground", adversary_name="APT ficticio", narrative_name="Narrativa base"),
        follow_redirects=False,
    )
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]

    response = client.get(f"/playground/{operation_id}/defender")
    assert response.status_code == 200
    _assert_no_branded_text(response)


def test_capability_kinds_are_labelled_by_function_not_by_raw_value(
    mounted_app, mounted_client, dolost_docker_calls
):
    """El `kind` tecnico ("dolost", "buda") se mostraba crudo como etiqueta en
    tres lugares del detalle: el nodo del arbol, el badge de la tabla de
    capacidades y las opciones del selector de tipo. En el arbol ademas el CSS
    lo pasa a mayuscula (`.op-tree-kind { text-transform: uppercase }`), asi que
    el operador leia literalmente "DOLOST".

    El chequeo general de nombres de origen no lo detectaba: busca la forma en
    mayuscula dentro del HTML, y en el HTML el texto esta en minuscula -- la
    mayuscula la agrega el navegador al pintar. De ahi este test aparte.
    """

    operation = _make_operation()
    scenario = Scenario(description="Escenario de prueba", related_ttps=["T1046"])
    operation.add_scenario(scenario)
    operation.bind_plugin(
        PluginBinding(
            plugin_id="mi-decoy-1", plugin_kind="dolost", surface="network", scenario_id=scenario.id
        )
    )
    mounted_app.config["OPERATION_REPOSITORY"].save(operation)

    parser = _VisibleTextCollector()
    parser.feed(mounted_client.get(f"/operations/{operation.id}").data.decode())
    visible_text = " ".join(parser.parts)

    # El nombre de funcion aparece; el valor tecnico no, como texto suelto.
    assert "Decoys de red" in visible_text
    for raw_kind in ("dolost", "buda", "canarytoken", "opencanary"):
        assert f" {raw_kind} " not in f" {visible_text} ", (
            f"el kind tecnico {raw_kind!r} se muestra crudo en vez de su nombre de funcion"
        )

    # Pero el contrato sigue intacto: el kind viaja como value del formulario.
    html = mounted_client.get(f"/operations/{operation.id}").data.decode()
    assert 'value="dolost"' in html
