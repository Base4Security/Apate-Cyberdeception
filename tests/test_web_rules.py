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
    assert b"Reglas cargadas (0)" in response.data


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
