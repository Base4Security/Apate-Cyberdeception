"""Constructor visual de reglas (referencia declarada: CounterCraft,
cuya interfaz de reglas es drag-and-drop -- evaluado y descartado, ver
docstring de `apate.web.blueprints.rules`). Estos tests cubren la parte
Python (contexto de `show_rules()`/`save_rules()`, markup estructural);
la generación de YAML y el merge en el editor son JS puro, verificados
con Playwright (ver docs/roadmap.md para la verificación visual real)."""

from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement


def _operation_with_bindings(*plugin_ids: str) -> Operation:
    operation = Operation(
        name="Operación con plugins",
        adversary_profile=AdversaryProfile(name="Actor"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa"),
    )
    for plugin_id in plugin_ids:
        operation.plugins.append(PluginBinding(plugin_id=plugin_id, plugin_kind="mock", surface="network"))
    return operation


# -- Contexto: opciones reales pobladas ---------------------------------------


def test_show_rules_exposes_the_two_event_types(client):
    response = client.get("/rules/")
    text = response.data.decode()

    assert '<option value="interaction">interaction</option>' in text
    assert '<option value="ttp_observed">ttp_observed</option>' in text


def test_show_rules_exposes_the_four_action_kinds(client):
    response = client.get("/rules/")
    text = response.data.decode()

    for kind in ("deploy", "rotate", "retire", "transition"):
        assert f'value="{kind}">{kind}</option>' in text


def test_show_rules_exposes_transition_targets_without_planning(client):
    response = client.get("/rules/")
    text = response.data.decode()

    assert 'class="rb-action-to"' in text
    for target in ("active", "compromised", "closed"):
        assert f'value="{target}">{target}</option>' in text
    # "planning" no es un destino de transicion valido (Action.__post_init__,
    # apate.rules.models) -- no debe aparecer como opcion del select.
    assert 'value="planning">planning</option>' not in text


def test_known_plugin_ids_come_from_real_operation_bindings(client, app):
    operation = _operation_with_bindings("mock-1", "dolost-finance")
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get("/rules/")
    text = response.data.decode()

    assert 'id="rb-known-plugins"' in text
    assert '<option value="mock-1">' in text


def test_known_plugin_ids_are_deduplicated_across_operations(client, app):
    app.config["OPERATION_REPOSITORY"].save(_operation_with_bindings("shared-plugin"))
    app.config["OPERATION_REPOSITORY"].save(_operation_with_bindings("shared-plugin"))

    response = client.get("/rules/")
    text = response.data.decode()

    assert text.count('<option value="shared-plugin">') == 1


def test_no_operations_means_empty_plugin_datalist_without_error(client):
    response = client.get("/rules/")

    assert response.status_code == 200
    assert 'id="rb-known-plugins"' in response.data.decode()


# -- Markup del constructor presente, sin romper el editor existente ---------


def test_builder_markup_present(client):
    text = client.get("/rules/").data.decode()

    assert 'id="rule-builder-form"' in text
    assert 'id="rb-name"' in text
    assert 'id="rb-event-fields"' in text
    assert 'id="rb-payload-row-template"' in text
    assert 'id="rb-action-row-template"' in text
    assert 'id="rb-preview"' in text
    assert "Solo agrega reglas nuevas" in text


def test_existing_editor_and_validation_markup_untouched(client):
    """No-regresion: CodeMirror, el dialogo de diff y el status de
    validacion en vivo (M13c) siguen presentes tal cual."""

    text = client.get("/rules/").data.decode()

    assert 'id="rules_text"' in text
    assert 'id="rules-form"' in text
    assert "data-guard-unsaved" in text
    assert 'id="rules-diff-dialog"' in text
    assert 'id="rules-live-status"' in text
    assert "CodeMirror.fromTextArea" in text


def test_save_rules_error_path_still_renders_builder_context(client):
    """Regresion especifica: antes de _render_rules_page(), el camino de
    error (400) de save_rules() no pasaba event_types/action_kinds/
    transition_targets/known_plugin_ids -- estos quedaban Undefined en
    Jinja y el render explotaria al iterarlos en el constructor."""

    response = client.post("/rules/", data={"rules_text": "esto: [no es valido"})

    assert response.status_code == 400
    text = response.data.decode()
    assert 'id="rule-builder-form"' in text
    assert '<option value="interaction">interaction</option>' in text


def test_valid_save_still_works_after_builder_context_changes(client, app):
    yaml_text = (
        "rules:\n"
        "  - name: \"Regla de prueba\"\n"
        "    when:\n"
        "      closure_due: true\n"
        "    then:\n"
        "      - action: retire\n"
    )
    response = client.post("/rules/", data={"rules_text": yaml_text}, follow_redirects=False)

    assert response.status_code == 302
    saved = app.config["APATE_RULES_PATH"].read_text(encoding="utf-8")
    assert saved == yaml_text


def test_rule_builder_open_by_default_when_no_rules_loaded(client):
    text = client.get("/rules/").data.decode()

    assert 'id="rule-builder" open>' in text


def test_rule_builder_closed_by_default_when_rules_already_exist(client, app):
    yaml_text = "rules:\n  - name: \"Existente\"\n    when:\n      closure_due: true\n    then:\n      - action: retire\n"
    app.config["APATE_RULES_PATH"].write_text(yaml_text, encoding="utf-8")

    text = client.get("/rules/").data.decode()

    assert 'id="rule-builder" open>' not in text
    assert 'id="rule-builder" >' in text


# -- Regresion: CRLF encontrado verificando con un navegador real ------------


def test_save_rules_normalizes_crlf_submitted_by_a_real_browser(client, app):
    """Un navegador real normaliza el contenido de un <textarea> a CRLF
    al enviar el formulario (HTML/HTTP spec) -- el test client de Flask
    (`data={...}`) no reproduce eso, por lo que la suite nunca lo
    ejercitaba. Encontrado verificando el constructor visual con
    Playwright: `Path.write_text()` en Windows, sin `newline=`, traduce
    cada "\\n" a CRLF de nuevo sobre un texto que YA tenia CRLF,
    duplicando el retorno de carro ("\\r\\r\\n") en el archivo guardado.
    Simula exactamente ese envio (CRLF ya presente en el valor
    posteado) y confirma que el archivo queda con LF puro."""

    crlf_text = "rules:\r\n  - name: \"Con CRLF\"\r\n    when:\r\n      closure_due: true\r\n    then:\r\n      - action: retire\r\n"

    response = client.post("/rules/", data={"rules_text": crlf_text}, follow_redirects=False)

    assert response.status_code == 302
    saved = app.config["APATE_RULES_PATH"].read_bytes()
    assert b"\r" not in saved
    assert saved.count(b"\n\n") == 0, "el CRLF duplicado se decodifica como lineas en blanco de mas"


def test_save_rules_normalizes_lone_cr(client, app):
    """Mismo criterio que el CRLF -- un CR suelto (Mac clasico, o
    cualquier fuente que no use CRLF ni LF) tampoco debe sobrevivir al
    guardado."""

    cr_text = "rules:\r  - name: \"Con CR\"\r    when:\r      closure_due: true\r    then:\r      - action: retire\r"

    response = client.post("/rules/", data={"rules_text": cr_text}, follow_redirects=False)

    assert response.status_code == 302
    saved = app.config["APATE_RULES_PATH"].read_bytes()
    assert b"\r" not in saved
