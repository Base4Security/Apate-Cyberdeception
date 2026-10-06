"""Integración: catálogo de plantillas de operación -> wizard precargado
-> confirmar crea una operación independiente. Mismo criterio de prueba
que `tests/test_web_operations_reoperate.py` (M12g): postea a los
formularios reales, sin mockear nada.

Criterio central de la tarea, verificado explícitamente: elegir una
plantilla PRECARGA el formulario, nunca crea una `Operation` por sí
sola -- `GET /operations/new?template=<id>` nunca debe persistir nada."""

from apate.web._operation_templates import get_template, list_templates


def _is_checked(text: str, ttp_id: str) -> bool:
    start = text.index(f'value="{ttp_id}"')
    tag_end = text.index(">", start)
    return "checked" in text[start:tag_end]


def _is_selected_option(text: str, select_value: str) -> bool:
    start = text.index(f'value="{select_value}"')
    tag_end = text.index(">", start)
    return "selected" in text[start:tag_end]


# -- Catálogo -----------------------------------------------------------------


def test_templates_gallery_lists_every_template(client):
    response = client.get("/operations/templates")

    assert response.status_code == 200
    text = response.data.decode()
    for template in list_templates():
        assert template["operation"]["name"] in text
        assert template["summary"] in text
    assert "Una plantilla precarga el perfil" in text
    assert "los escenarios y las capacidades los agreg" in text


def test_templates_gallery_uses_the_english_dataset_when_the_interface_is_english(client, app):
    app.config["APATE_LOCALE"] = "en"

    text = client.get("/operations/templates").get_data(as_text=True)

    assert "APT28 — Lateral movement to the financial segment" in text
    assert "APT28 — Movimiento lateral hacia el segmento financiero" not in text


def test_templates_gallery_links_to_prefilled_wizard(client):
    response = client.get("/operations/templates")

    text = response.data.decode()
    for template in list_templates():
        assert f"/operations/new?template={template['id']}" in text


def test_templates_gallery_creates_no_operation(client, app):
    client.get("/operations/templates")

    assert list(app.config["OPERATION_REPOSITORY"].list()) == []


# -- Wizard precargado: no crea nada por sí solo -------------------------------


def test_choosing_a_template_creates_no_operation(client, app):
    template = list_templates()[0]

    response = client.get(f"/operations/new?template={template['id']}")

    assert response.status_code == 200
    assert list(app.config["OPERATION_REPOSITORY"].list()) == []


def test_unknown_template_id_flashes_error_and_renders_blank_form(client):
    response = client.get("/operations/new?template=no-existe", follow_redirects=True)

    assert response.status_code == 200
    assert b"flash-error" in response.data
    text = response.data.decode()
    assert "no existe" in text.lower()
    # Sin plantilla aplicada, el nombre queda vacio (formulario en blanco).
    assert 'id="name" name="name" required value=""' in text


def test_template_banner_shown_with_link_to_go_blank(client):
    template = get_template("apt28-lateral-finance")

    response = client.get(f"/operations/new?template={template['id']}")

    text = response.data.decode()
    assert "Plantilla" in text
    assert template["operation"]["name"] in text
    assert 'href="/operations/new"' in text


def test_template_shows_next_steps_for_scenario_and_plugins_without_creating_them(client, app):
    template = get_template("lazarus-exfil-validation")

    response = client.get(f"/operations/new?template={template['id']}")

    text = response.data.decode()
    assert template["scenario"]["description"] in text
    assert "dolost, buda" in text
    # Ninguna Operation persistida todavia -- solo texto informativo.
    assert list(app.config["OPERATION_REPOSITORY"].list()) == []


# -- Precarga real de cada campo del wizard ------------------------------------


def test_template_prefills_name_and_adversary_fields(client):
    template = get_template("apt28-lateral-finance")

    response = client.get(f"/operations/new?template={template['id']}")

    text = response.data.decode()
    op = template["operation"]
    assert f'value="{op["name"]}"' in text
    assert f'value="{op["adversary_name"]}"' in text
    assert f'value="{op["adversary_motivation"]}"' in text
    assert "Perfil basado en TTPs publicamente atribuidas a APT28" in text
    assert f'value="{op["target_assets"]}"' in text


def test_template_prefills_expected_ttps_checkboxes(client):
    template = get_template("apt28-lateral-finance")

    response = client.get(f"/operations/new?template={template['id']}")

    text = response.data.decode()
    for ttp_id in template["operation"]["expected_ttps"]:
        assert _is_checked(text, ttp_id)


def test_template_prefills_skill_level_and_environment_selects(client):
    template = get_template("apt28-lateral-finance")

    response = client.get(f"/operations/new?template={template['id']}")

    text = response.data.decode()
    assert _is_selected_option(text, template["operation"]["adversary_skill_level"])
    assert _is_selected_option(text, template["operation"]["environment"])


def test_template_prefills_end_date_as_absolute_date(client):
    from apate.web._operation_templates import resolve_operation_fields

    template = get_template("apt28-lateral-finance")
    expected_end_date = resolve_operation_fields(template)["end_date"]

    response = client.get(f"/operations/new?template={template['id']}")

    assert f'value="{expected_end_date}"' in response.data.decode()


def test_template_prefills_objectives_checkboxes(client):
    template = get_template("apt28-lateral-finance")

    response = client.get(f"/operations/new?template={template['id']}")

    text = response.data.decode()
    for objective in template["operation"]["objectives"]:
        assert _is_checked(text, objective)


def test_template_prefills_roles_and_resource_estimate(client):
    template = get_template("apt28-lateral-finance")

    response = client.get(f"/operations/new?template={template['id']}")

    text = response.data.decode()
    assert template["operation"]["roles"].split("\n")[0] in text
    assert template["operation"]["resource_estimate"] in text


def test_template_prefills_narrative_fields(client):
    template = get_template("apt28-lateral-finance")

    response = client.get(f"/operations/new?template={template['id']}")

    text = response.data.decode()
    op = template["operation"]
    assert f'value="{op["narrative_name"]}"' in text
    assert f'value="{op["narrative_description"]}"' in text
    assert f'value="{op["psychological_impact"]}"' in text


# -- Confirmar el formulario precargado crea una operacion nueva --------------


def test_confirming_prefilled_template_form_creates_matching_operation(client, app):
    from apate.web._operation_templates import resolve_operation_fields

    template = get_template("apt28-lateral-finance")
    fields = resolve_operation_fields(template)

    # Lo que el operador ve precargado...
    prefilled = client.get(f"/operations/new?template={template['id']}").data.decode()
    for ttp_id in fields["expected_ttps"]:
        assert _is_checked(prefilled, ttp_id)

    # ...es exactamente lo que confirma via el submit normal de create_operation().
    response = client.post("/operations/new", data=fields, follow_redirects=False)
    assert response.status_code == 302
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.name == fields["name"]
    assert operation.adversary_profile.name == fields["adversary_name"]
    assert sorted(operation.adversary_profile.expected_ttps) == sorted(fields["expected_ttps"])
    assert operation.strategic_decisions.objectives, "objectives no se aplicaron"


def test_operator_can_edit_prefilled_fields_before_confirming(client, app):
    """El wizard precargado sigue siendo un formulario normal editable
    -- confirma que un campo del prefill se puede pisar antes de
    enviar, no queda bloqueado."""

    from apate.web._operation_templates import resolve_operation_fields

    template = get_template("apt28-lateral-finance")
    fields = resolve_operation_fields(template)
    fields["name"] = "Nombre editado por el operador"

    response = client.post("/operations/new", data=fields, follow_redirects=False)
    assert response.status_code == 302
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.name == "Nombre editado por el operador"


# -- Descubribilidad: enlaces desde el listado ---------------------------------


def test_operations_list_links_to_templates_gallery(client):
    response = client.get("/operations/templates")
    assert response.status_code == 200

    list_response = client.get("/operations/")
    assert b'href="/operations/templates"' in list_response.data
    assert b"Plantilla: inici" in list_response.data
    assert b"En blanco: inici" in list_response.data
