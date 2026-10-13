"""Tests de integracion web para la navegacion por tabs del detalle de
operacion (M13e) -- ver docs/roadmap.md seccion M13e.

Dos cosas puntuales, no solo "los tabs existen":

1. Cada formulario de Escenarios/Plugins vinculados/Mecanica especifica
   (todos POST-y-vuelven-al-detalle) tiene que redirigir de vuelta al
   tab correcto -- ver `_redirect_to_detail()` en operations.py, que
   agrega el fragmento `#tab-...` al `Location` de la respuesta.
2. Ningun formulario queda partido entre dos tab-panels -- el mismo
   bug class que motivo el `novalidate` del wizard de M12e (un
   `required` oculto bloqueando un submit ajeno) no puede repetirse
   aca porque cada `<form>` vive entero dentro de un unico tab-panel;
   se verifica estructuralmente (conteo balanceado de <form>/</form>
   por panel), ya que este entorno no tiene un navegador real para
   ejercitar la validacion nativa (mismo limite que ya documenta
   test_web_operations_wizard.py para M12e).

Mismos fixtures/helpers que tests/test_web_operations_panels.py
(mounted_app/mounted_client con APATE_MOUNT_EXTERNAL_TOOLS=True,
dolost_calls/buda_calls mockeando Docker/WinRM)."""

import datetime
import re

import pytest

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.plugins import buda_plugin as buda_plugin_module
from apate.plugins import dolost_plugin as dolost_plugin_module
from apate.web import create_app
from apate.web.blueprints import operations as operations_module


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'tabs-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


def _make_operation(**overrides) -> Operation:
    defaults = dict(
        name="Operacion de prueba M13e",
        adversary_profile=AdversaryProfile(name="APT ficticio", motivation="espionaje", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    defaults.update(overrides)
    return Operation(**defaults)


def _save(app, operation: Operation) -> Operation:
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


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


@pytest.fixture
def dolost_calls(monkeypatch):
    calls = {"deploy_collector": [], "deploy_decoy": [], "clean_decoy": [], "web_deploy_decoy": [], "web_clean_decoy": []}
    monkeypatch.setattr(dolost_plugin_module, "deploy_collector", lambda: calls["deploy_collector"].append(True))
    monkeypatch.setattr(dolost_plugin_module, "deploy_decoy", lambda decoy: calls["deploy_decoy"].append(decoy))
    monkeypatch.setattr(dolost_plugin_module, "clean_decoy", lambda decoy: calls["clean_decoy"].append(decoy))
    monkeypatch.setattr(operations_module, "_dolost_deploy_decoy", lambda decoy: calls["web_deploy_decoy"].append(decoy))
    monkeypatch.setattr(operations_module, "_dolost_clean_decoy", lambda decoy: calls["web_clean_decoy"].append(decoy))
    return calls


@pytest.fixture
def buda_calls(monkeypatch):
    calls = {"start_narrative": [], "stop_narrative": []}
    monkeypatch.setattr(
        buda_plugin_module,
        "start_narrative",
        lambda narrative_id: (calls["start_narrative"].append(narrative_id), {"message": "Narrative started"})[1],
    )
    monkeypatch.setattr(
        buda_plugin_module,
        "stop_narrative",
        lambda narrative_id: (calls["stop_narrative"].append(narrative_id), {"message": "Narrative stopped"})[1],
    )
    return calls


# -- Estructura: cinco tabs, con anclas heredadas dentro de los consolidados --


def test_five_tab_links_present_when_mechanics_available(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    for tab_id, label in [
        ("tab-design", "Diseño"),
        ("tab-mechanics", "Despliegue"),
        ("tab-review", "Preparación y revisión"),
        ("tab-mapa", "Mapa"),
        ("tab-resultados", "Resultados"),
    ]:
        assert f'data-tab="{tab_id}"' in text
        assert f'id="{tab_id}"' in text


def test_mechanics_tab_link_absent_without_any_dolost_or_buda_panel(client):
    # `client` (conftest.py) usa APATE_MOUNT_EXTERNAL_TOOLS=False -- ni
    # siquiera con un binding de por medio hay panel que mostrar.
    response = client.post(
        "/operations/new",
        data={"name": "Sin mecanica", "adversary_name": "APT", "narrative_name": "N"},
        follow_redirects=False,
    )
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]

    detail = client.get(f"/operations/{operation_id}")
    text = detail.data.decode()

    assert 'data-tab="tab-mechanics"' not in text
    # Los cuatro tabs restantes siguen estando, sin depender de esto.
    assert 'data-tab="tab-design"' in text
    assert 'data-tab="tab-review"' in text


def test_consolidated_tabs_keep_each_step_content_and_legacy_anchors(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    def panel_slice(tab_id):
        start = text.index(f'id="{tab_id}"')
        try:
            end = text.index('<div class="tab-panel"', start + 1)
        except ValueError:
            # Ultimo panel (tab-mechanics) -- no hay otro tab-panel
            # despues, corta al final del documento.
            end = len(text)
        return text[start:end]

    design = panel_slice("tab-design")
    assert 'class="design-step-nav"' in design
    assert design.count('class="collapsible design-step"') == 5
    for legacy_anchor, expected_content in [
        ("tab-profile", "Paso 1"),
        ("tab-roe", "Paso 2"),
        ("tab-scenarios", "Paso 3"),
        ("tab-narrative", "Paso 5"),
        ("tab-plugins", "Paso 4"),
    ]:
        assert f'<section id="{legacy_anchor}"' in design
        assert expected_content in design
        assert design.rfind('class="collapsible design-step"', 0, design.index(f'<section id="{legacy_anchor}"')) != -1
    assert "Decisiones estrat" in design
    # HTML crudo, no texto renderizado -- las tildes viajan como
    # entidades (mismo patron que el resto del template).
    assert "Despliegue contextual" in panel_slice("tab-mechanics")
    review = panel_slice("tab-review")
    assert '<section id="tab-preparation"' in review
    assert '<section id="tab-dryrun"' in review
    assert "Preparaci" in review and "Ensayo en seco" in review


def test_legacy_fragment_resolves_to_its_consolidated_tab_instead_of_falling_back(client, app):
    """Cada fragmento que antes apuntaba a un panel sigue encontrando su
    contenido: ahora es una sección y el script activa su panel ancestro."""

    op = _make_operation()
    app.config["OPERATION_REPOSITORY"].save(op)
    text = client.get(f"/operations/{op.id}").get_data(as_text=True)

    for legacy_anchor in (
        "tab-profile",
        "tab-roe",
        "tab-scenarios",
        "tab-narrative",
        "tab-plugins",
        "tab-preparation",
        "tab-dryrun",
    ):
        assert f'<section id="{legacy_anchor}"' in text
    assert "const panel = section.closest('.tab-panel');" in text
    assert "const designStep = targetElement.closest('details.design-step');" in text
    assert "step.open = step === designStep;" in text


# -- Ningun formulario queda partido entre dos tab-panels --------------------


def test_no_form_spans_multiple_tab_panels(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    panel_ids = ["tab-design", "tab-mechanics", "tab-review", "tab-mapa", "tab-resultados"]
    starts = {
        tab_id: text.index(f'<div class="tab-panel" id="{tab_id}"')
        for tab_id in panel_ids
        if f'<div class="tab-panel" id="{tab_id}"' in text
    }
    ordered = sorted(starts.items(), key=lambda item: item[1])

    total_forms_in_panels = 0
    for index, (tab_id, start) in enumerate(ordered):
        end = ordered[index + 1][1] if index + 1 < len(ordered) else len(text)
        panel_text = text[start:end]
        opens = len(re.findall(r"<form\b", panel_text))
        closes = panel_text.count("</form>")
        # Balanceado dentro del propio panel -- ningun <form> abierto
        # en un panel se cierra en el siguiente (o viceversa).
        assert opens == closes, f"{tab_id}: {opens} <form> vs {closes} </form>"
        total_forms_in_panels += opens

    # La cabecera (transiciones de estado, antes del primer tab-panel)
    # tiene sus propios <form> a proposito -- son acciones de la
    # operacion entera, no de un tab puntual (ver docstring del
    # modulo). Se excluyen de la comparacion: lo que importa es que
    # NINGUN <form> quede repartido entre panels, no que todos vivan
    # dentro de alguno.
    forms_before_tabs = len(re.findall(r"<form\b", text[: ordered[0][1]]))
    total_forms_in_page = len(re.findall(r"<form\b", text))
    assert total_forms_in_panels == total_forms_in_page - forms_before_tabs


# -- Redirect al tab correcto tras cada submit -------------------------------


def test_add_scenario_success_redirects_to_scenarios_tab(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/scenarios",
        data={"description": "Detectar escaneo interno", "related_ttps": "T1046", "deception_level": "basic"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-scenarios")


def test_add_scenario_validation_error_redirects_to_scenarios_tab(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/scenarios", data={"description": ""}, follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-scenarios")


def test_add_plugin_binding_redirects_to_plugins_tab(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins",
        data={"plugin_id": "honeytoken-1", "surface": "data"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-plugins")


def test_dolost_deploy_redirects_to_mechanics_tab(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/dolost-1/dolost/deploy", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_dolost_add_decoy_redirects_to_mechanics_tab(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network"))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys",
        data={"Hostname": "ftp1"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_dolost_deploy_decoy_redirects_to_mechanics_tab(mounted_app, mounted_client, dolost_calls):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/deploy", follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_dolost_delete_decoy_redirects_to_mechanics_tab(mounted_app, mounted_client, monkeypatch):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", config={"decoys": [{"Hostname": "ssh1"}]}))
    _save(mounted_app, op)
    monkeypatch.setattr(dolost_plugin_module._docker_manager, "get_containers", lambda all: [])

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/dolost-1/dolost/decoys/ssh1/delete", follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_buda_start_redirects_to_mechanics_tab(mounted_app, mounted_client, buda_calls):
    narrative_id = _make_buda_narrative(mounted_app)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/plugins/buda-1/buda/start", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_buda_link_narrative_redirects_to_mechanics_tab(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(mounted_app)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity"))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/link",
        data={"narrative_id": str(narrative_id)},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_buda_update_narrative_profiles_redirects_to_mechanics_tab(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(mounted_app)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/profiles", data={}, follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_buda_delete_narrative_redirects_to_mechanics_tab(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative(mounted_app)
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", config={"narrative_id": narrative_id}))
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/plugins/buda-1/buda/narrative/delete", follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_deploy_all_route_redirects_to_mechanics_tab(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", config={"directory": "/tmp", "filenames": ["a"]}))
    _save(mounted_app, op)

    response = mounted_client.post(f"/operations/{op.id}/deploy-all", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["Location"].endswith(f"/operations/{op.id}#tab-mechanics")


def test_deploy_all_button_shows_in_mechanics_tab(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="honeytoken-1", plugin_kind="honeytoken", surface="data", config={"directory": "/tmp", "filenames": ["a"]}))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    assert 'action="' + f"/operations/{op.id}/deploy-all" + '"' in text
    assert "Desplegar toda la campaña" in text
    assert 'data-slow-action' in text


# -- Acciones de cabecera (no ligadas a un tab) siguen sin fragmento --------


def test_transition_redirect_has_no_tab_fragment(mounted_app, mounted_client):
    op = _make_operation()
    _save(mounted_app, op)

    response = mounted_client.post(
        f"/operations/{op.id}/transition", data={"to": "active"}, follow_redirects=False
    )

    assert response.status_code == 302
    assert response.headers["Location"] == f"/operations/{op.id}"


# -- Aislamiento entre la barra de tabs y el selector de lentes del Mapa -----


def test_tab_script_scopes_its_buttons_to_its_own_bar(mounted_app, mounted_client):
    """El selector de lentes del tab "Mapa" reusa la clase .tab-link para
    verse igual que la barra principal. Con un querySelectorAll('.tab-link')
    global, el script de tabs capturaba tambien esos tres botones y les pisaba
    la clase .active recien puesta por su propio switcher -- resultado: hacer
    click en una lente no hacia absolutamente nada, sin ningun error visible.
    """

    op = _make_operation()
    _save(mounted_app, op)

    text = mounted_client.get(f"/operations/{op.id}").data.decode()

    assert "document.querySelectorAll('.operation-tabs .tab-link')" in text
    assert "document.querySelectorAll('.tab-link')" not in text


def test_map_lens_switcher_handles_arrow_keys(mounted_app, mounted_client):
    """role="radiogroup" con roving tabindex (las lentes inactivas quedan en
    tabindex="-1") obliga a manejar las flechas: sin eso, quien navega por
    teclado llega al grupo y no puede cambiar de lente."""

    op = _make_operation()
    _save(mounted_app, op)

    text = mounted_client.get(f"/operations/{op.id}").data.decode()
    lens_script = text.split("operation-map-lens-switcher")[-1]

    for key in ("ArrowLeft", "ArrowRight", "Home", "End"):
        assert key in lens_script


# -- Progressive disclosure en el tab "Despliegue" ---------------------------


def _mechanics_body(client, operation_id: str) -> str:
    text = client.get(f"/operations/{operation_id}").data.decode()
    return text.split('id="tab-mechanics"')[1].split('class="tab-panel"')[0]


def test_deploy_forms_with_fields_are_collapsed_but_action_buttons_are_not(
    mounted_app, mounted_client
):
    """Los formularios de alta/configuracion (2 campos o mas) van detras de un
    disclosure; los de un solo boton (deploy/rotate/retire/start/stop) quedan
    siempre visibles -- son las acciones que un operador necesita a mano."""

    import re

    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", plugin_kind="dolost", surface="network"))
    _save(mounted_app, op)

    body = _mechanics_body(mounted_client, op.id)

    for match in re.finditer(r'<form[^>]*action="([^"]*)"[^>]*>(.*?)</form>', body, re.S):
        action, inner = match.group(1), match.group(2)
        fields = re.findall(
            r'<(?:input type="(?:text|number|file)"|textarea|select)[^>]*name="([^"]*)"', inner
        )
        before = body[: match.start()]
        inside_details = before.count("<details") - before.count("</details>") > 0

        if len(fields) >= 2:
            assert inside_details, f"{action} tiene {len(fields)} campos y deberia estar colapsado"
        elif not fields:
            assert not inside_details, f"{action} es un boton de accion y no deberia esconderse"


def test_invalid_handler_uses_capture_phase(mounted_app, mounted_client):
    """El evento 'invalid' NO burbujea (spec), asi que un listener en document
    solo lo recibe en fase de captura. Sin el tercer argumento en true, un
    campo required dentro de un <details> cerrado vuelve a bloquear el submit
    sin que se vea nada -- el mismo bug class que M12e documento en el wizard.
    """

    op = _make_operation()
    _save(mounted_app, op)

    text = mounted_client.get(f"/operations/{op.id}").data.decode()
    handler = text.split("document.addEventListener('invalid'")[1].split("}, true);")[0]

    # El split por "}, true);" ya prueba la fase de captura: sin ese tercer
    # argumento no habria donde cortar y el handler se llevaria el resto del
    # documento -- de ahi el assert de que no llegue hasta el cierre del HTML.
    assert "details.open = true" in handler
    assert "</html>" not in handler
