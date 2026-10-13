_VALID_RULES_YAML = """
rules:
  - name: "Escaneo -> activar"
    when:
      event_type: interaction
      payload:
        kind: scan
    then:
      - action: transition
        to: active
"""


def test_rules_view_returns_200(client):
    response = client.get("/rules/")
    assert response.status_code == 200


def test_rules_view_starts_with_no_rules(client):
    response = client.get("/rules/")
    assert b'id="loaded-rules-title">Reglas cargadas</h2>' in response.data
    assert b'class="summary-count-badge">0</span>' in response.data


def test_save_valid_rules_updates_file_and_shows_new_rules(client, app):
    response = client.post("/rules/", data={"rules_text": _VALID_RULES_YAML}, follow_redirects=True)

    assert response.status_code == 200
    assert b"Escaneo -&gt; activar" in response.data or b"Escaneo -> activar" in response.data

    saved = app.config["APATE_RULES_PATH"].read_text(encoding="utf-8")
    assert "Escaneo -> activar" in saved


def test_save_invalid_rules_returns_400_and_does_not_overwrite_file(client, app):
    rules_path = app.config["APATE_RULES_PATH"]
    original = rules_path.read_text(encoding="utf-8")

    response = client.post("/rules/", data={"rules_text": "rules: [invalid"}, follow_redirects=False)

    assert response.status_code == 400
    assert rules_path.read_text(encoding="utf-8") == original


def test_save_rules_with_missing_field_returns_400(client):
    invalid_yaml = """
    rules:
      - when:
          event_type: interaction
        then: []
    """
    response = client.post("/rules/", data={"rules_text": invalid_yaml}, follow_redirects=False)
    assert response.status_code == 400


def test_rules_index_page_sends_rules_text_field_to_the_real_save_route(client):
    # M13c: CodeMirror envuelve el <textarea>, pero el contrato del
    # formulario (name="rules_text", POST a rules.save_rules) no
    # cambia -- ver rules/index.html.
    response = client.get("/rules/")
    text = response.data.decode()

    assert 'name="rules_text"' in text
    assert f'action="{ "/rules/" }"' in text or 'action="/rules/"' in text


def test_rules_editor_previews_diff_before_overwriting(client):
    text = client.get("/rules/").data.decode()

    assert 'id="rules-diff-dialog"' in text
    assert 'id="rules-diff-before"' in text
    assert 'id="rules-diff-after"' in text
    assert "Nada se guard" in text
    assert "rulesSaveConfirmed" in text


def test_rules_view_separates_engine_scope_reading_and_editing(client):
    text = client.get("/rules/").get_data(as_text=True)

    assert "Motor determinista" in text
    assert "Las reglas de interacci&oacute;n (RoE) gobiernan las acciones autom" in text
    assert 'class="panel rules-overview"' in text
    assert 'class="panel rules-editor-panel"' in text
    assert 'role="status" aria-live="polite"' in text
    assert "Antes de escribir el archivo ver" in text


# -- Validacion en linea (M13c, POST /rules/validate) ------------------------


def test_validate_endpoint_returns_valid_true_for_valid_yaml(client):
    response = client.post("/rules/validate", data={"rules_text": _VALID_RULES_YAML})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["valid"] is True
    assert payload["rule_count"] == 1


def test_validate_endpoint_returns_valid_false_with_error_for_invalid_yaml(client):
    response = client.post("/rules/validate", data={"rules_text": "rules: [invalid"})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["valid"] is False
    assert "error" in payload
    assert payload["error"]


def test_validate_endpoint_returns_valid_false_for_yaml_with_missing_field(client):
    invalid_yaml = """
    rules:
      - when:
          event_type: interaction
        then: []
    """
    response = client.post("/rules/validate", data={"rules_text": invalid_yaml})

    payload = response.get_json()
    assert payload["valid"] is False


def test_validate_endpoint_never_writes_to_the_rules_file(client, app):
    rules_path = app.config["APATE_RULES_PATH"]
    original = rules_path.read_text(encoding="utf-8")

    client.post("/rules/validate", data={"rules_text": _VALID_RULES_YAML})
    client.post("/rules/validate", data={"rules_text": "rules: [invalid"})

    assert rules_path.read_text(encoding="utf-8") == original


def test_validate_endpoint_handles_missing_field_as_empty_document(client):
    # Sin rules_text en el POST -- mismo comportamiento que un
    # documento vacio, no un error del servidor (400/500).
    response = client.post("/rules/validate", data={})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["valid"] is True
    assert payload["rule_count"] == 0
