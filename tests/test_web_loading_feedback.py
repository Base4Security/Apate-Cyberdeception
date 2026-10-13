"""Tests para el feedback visual de acciones lentas (Docker/WinRM/
subprocess/red) -- `apate/web/static/loading.js` + `.btn-spinner`
(theme.css). Ver docs/roadmap.md.

Comportamiento del lado del cliente (deshabilitar el boton, mostrar el
spinner) no se puede probar de verdad sin un navegador real -- mismo
limite ya documentado varias veces en este proyecto (M12e/M13e, el
housekeeping de responsividad). La verificacion queda estructural:
confirmar que el atributo marcador (`data-slow-action`) esta presente
en los formularios "genuinamente lentos" del inventario del hito y
ausente en los que solo tocan el `OperationRepository`/SQLite local
(rapidos), y que el script/CSS compartidos se sirven correctamente.

Mismo patron de fixtures que test_web_operations_panels.py/
test_web_integrations.py (`mounted_app`/`mounted_client`, `SQLALCHEMY_DATABASE_URI`
real -- los paneles de DOLOS-T/BUDA necesitan `APATE_MOUNT_EXTERNAL_TOOLS=True`,
el default)."""

import pytest

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.web import create_app


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-loading-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


@pytest.fixture
def dolost_docker_calls(monkeypatch):
    from apate.web.blueprints import health as health_module

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


def _save(app, operation: Operation) -> Operation:
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


# -- Script/CSS compartidos, servidos en cualquier pagina --------------------


def test_loading_js_is_referenced_from_base_html(client):
    response = client.get("/operations/")
    assert response.status_code == 200
    assert b'src="/static/loading.js"' in response.data


def test_loading_js_is_served_and_contains_the_delegated_listener(client):
    response = client.get("/static/loading.js")
    assert response.status_code == 200
    text = response.data.decode()
    assert "data-slow-action" in text
    assert "addEventListener(\"submit\"" in text


def test_theme_css_defines_the_spinner_class(client):
    response = client.get("/static/theme.css")
    assert response.status_code == 200
    assert b".btn-spinner" in response.data


# -- Formularios marcados: panel de decoys (DOLOS-T) -------------------------


def test_dolost_lifecycle_buttons_are_marked_as_slow(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", plugin_kind="dolost"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    assert response.status_code == 200
    for action in ("dolost/deploy", "dolost/rotate", "dolost/retire"):
        idx = text.index(action)
        form_start = text.rindex("<form", 0, idx)
        form_end = text.index(">", idx)
        assert "data-slow-action" in text[form_start:form_end], action


def test_honeytoken_lifecycle_buttons_are_marked_as_slow(mounted_app, mounted_client, tmp_path):
    draft = _make_operation(name="Honeytokens por desplegar")
    draft.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-draft",
            surface="data",
            plugin_kind="honeytoken",
            config={"directory": str(tmp_path / "draft"), "filenames": ["credenciales.txt"]},
        )
    )
    _save(mounted_app, draft)

    deployed_directory = tmp_path / "deployed"
    deployed_directory.mkdir()
    (deployed_directory / "credenciales.txt").write_text("sintético", encoding="utf-8")
    deployed = _make_operation(name="Honeytokens desplegados")
    deployed.bind_plugin(
        PluginBinding(
            plugin_id="honeytoken-live",
            surface="data",
            plugin_kind="honeytoken",
            config={"directory": str(deployed_directory), "filenames": ["credenciales.txt"]},
        )
    )
    _save(mounted_app, deployed)

    draft_text = mounted_client.get(f"/operations/{draft.id}").get_data(as_text=True)
    deployed_text = mounted_client.get(f"/operations/{deployed.id}").get_data(as_text=True)
    for text, action in (
        (draft_text, "honeytoken/deploy"),
        (deployed_text, "honeytoken/rotate"),
        (deployed_text, "honeytoken/retire"),
    ):
        index = text.index(action)
        form_start = text.rindex("<form", 0, index)
        form_end = text.index(">", index)
        assert "data-slow-action" in text[form_start:form_end], action


def test_dolost_add_decoy_form_is_not_marked_as_slow(mounted_app, mounted_client):
    # Config-only (JSON local) -- no toca Docker.
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="dolost-1", surface="network", plugin_kind="dolost"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    idx = text.index("dolost/decoys\"")
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx)
    assert "data-slow-action" not in text[form_start:form_end]


def test_dolost_decoy_row_actions_marked_slow_except_delete(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="dolost-1",
            surface="network",
            plugin_kind="dolost",
            config={"decoys": [{"Hostname": "ssh1", "Service": "ssh", "IP": "10.0.0.5"}]},
        )
    )
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    def _form_attrs(action_fragment):
        idx = text.index(action_fragment)
        form_start = text.rindex("<form", 0, idx)
        form_end = text.index(">", idx)
        return text[form_start:form_end]

    for action in (
        "dolost/decoys/ssh1/deploy",
        "dolost/decoys/ssh1/undeploy",
        "dolost/decoys/ssh1/start",
        "dolost/decoys/ssh1/stop",
    ):
        assert "data-slow-action" in _form_attrs(f'{action}"'), action

    # Borrar de la config: solo saca la entrada de PluginBinding.config,
    # no toca Docker -- rapido, no deberia tener el marcador.
    assert "data-slow-action" not in _form_attrs('dolost/decoys/ssh1/delete"')


# -- Formularios marcados: panel de narrativa (BUDA) --------------------------
#
# El boton start/stop solo aparece cuando panel.found es True (una
# Narrative real resuelta) -- se prueba directo contra ese caso, con una
# narrativa real creada en la base de BUDA de este test, en vez de un
# caso "narrative_id que no resuelve" que ni siquiera renderiza el
# formulario.


def test_buda_start_button_marked_slow_when_narrative_exists(mounted_app, mounted_client):
    with mounted_app.app_context():
        from BUDA.app import db as buda_db
        from BUDA.models import Narrative as BudaNarrative
        import datetime as dt

        narrative = BudaNarrative(
            title="t",
            objective="o",
            attacker_profile="a",
            deception_activities="d",
            end_date=dt.date.today(),
            is_running=False,
            percentage_of_similarity=100,
        )
        buda_db.session.add(narrative)
        buda_db.session.commit()
        narrative_id = narrative.id

    op = _make_operation()
    op.bind_plugin(
        PluginBinding(
            plugin_id="buda-1", surface="identity", plugin_kind="buda", config={"narrative_id": narrative_id}
        )
    )
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    idx = text.index("buda/start\"")
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx)
    assert "data-slow-action" in text[form_start:form_end]


def test_buda_create_narrative_form_is_not_marked_as_slow(mounted_app, mounted_client):
    op = _make_operation()
    op.bind_plugin(PluginBinding(plugin_id="buda-1", surface="identity", plugin_kind="buda"))
    _save(mounted_app, op)

    response = mounted_client.get(f"/operations/{op.id}")
    text = response.data.decode()

    idx = text.index("buda/narrative/create\"")
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx)
    assert "data-slow-action" not in text[form_start:form_end]


# -- Formularios marcados: Playground -----------------------------------------


def test_playground_start_and_stop_forms_are_marked_as_slow(client):
    response = client.post(
        "/operations/new",
        data=dict(name="Operacion Playground", adversary_name="APT ficticio", narrative_name="Narrativa base"),
        follow_redirects=False,
    )
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]

    response = client.get("/playground/")
    text = response.data.decode()

    assert operation_id in text
    idx = text.index(f"/playground/{operation_id}/start\"")
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx)
    assert "data-slow-action" in text[form_start:form_end]


# -- Formularios marcados: integraciones canónicas ---------------------------


def test_dolost_docker_config_form_is_marked_as_slow(mounted_client, dolost_docker_calls):
    response = mounted_client.get("/health/configuration/network-host-runtime")
    text = response.data.decode()

    # action="...", no href="..." -- el nav tambien enlaza a esta misma
    # URL y aparece primero en la pagina.
    idx = text.index('action="/health/configuration/network-host-runtime"')
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx)
    assert "data-slow-action" in text[form_start:form_end]


def test_buda_context_upload_form_is_not_marked_but_handles_its_own_loading_state(mounted_client):
    response = mounted_client.get("/capabilities/behavior-context")
    text = response.data.decode()

    idx = text.index("behavior-context-upload-form")
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx, )
    assert "data-slow-action" not in text[form_start:form_end]
    # Maneja su propio estado de carga (fetch() con progreso en vivo ya
    # existente) reusando la misma clase de spinner, ver el comentario
    # en el template.
    assert "btn-spinner" in text


# -- Formularios NO marcados: JSON/SQLite local, rapidos -----------------------


def test_create_operation_wizard_form_is_not_marked_as_slow(client):
    response = client.get("/operations/new")
    text = response.data.decode()
    assert 'id="operation-form"' in text

    idx = text.index('id="operation-form"')
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx)
    assert "data-slow-action" not in text[form_start:form_end]
    # novalidate del wizard (M12e) sigue intacto -- no lo pisamos.
    assert "novalidate" in text[form_start:form_end]


def test_add_scenario_and_add_plugin_binding_forms_are_not_marked_as_slow(client):
    response = client.post(
        "/operations/new",
        data=dict(name="Operacion rapida", adversary_name="APT ficticio", narrative_name="Narrativa base"),
        follow_redirects=False,
    )
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    scenario_idx = text.index(f'/operations/{operation_id}/scenarios"')
    form_start = text.rindex("<form", 0, scenario_idx)
    form_end = text.index(">", scenario_idx)
    assert "data-slow-action" not in text[form_start:form_end]

    plugins_idx = text.index(f'/operations/{operation_id}/plugins"')
    form_start = text.rindex("<form", 0, plugins_idx)
    form_end = text.index(">", plugins_idx)
    assert "data-slow-action" not in text[form_start:form_end]


def test_transition_forms_are_not_marked_as_slow(client):
    response = client.post(
        "/operations/new",
        data=dict(name="Operacion transicion", adversary_name="APT ficticio", narrative_name="Narrativa base"),
        follow_redirects=False,
    )
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    idx = text.index(f'/operations/{operation_id}/transition"')
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx)
    assert "data-slow-action" not in text[form_start:form_end]


def test_save_rules_form_is_not_marked_as_slow(client):
    response = client.get("/rules/")
    text = response.data.decode()

    idx = text.index('id="rules-form"')
    form_start = text.rindex("<form", 0, idx)
    form_end = text.index(">", idx)
    assert "data-slow-action" not in text[form_start:form_end]
