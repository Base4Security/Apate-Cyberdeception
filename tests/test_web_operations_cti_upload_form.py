"""Tests estructurales para el control de carga de CTI en
operations/form.html -- Fase 6 post-BlackHat (ver docs/roadmap.md),
reemplaza el placeholder deshabilitado de M12k (antes cubierto por
tests/test_web_operations_cti_upload.py, retirado: sus aserciones
describian un <input disabled> que ya no existe). Mismo criterio que
test_web_operations_wizard.py (M12e): sin Selenium/Playwright en este
entorno, se confirma la estructura HTML resultante, no la interaccion
JS en si."""


def test_new_operation_form_cti_upload_is_enabled_not_disabled(client):
    response = client.get("/operations/new")

    text = response.data.decode()
    assert 'id="cti_report_upload"' in text
    assert "disabled" not in text.split('id="cti_report_upload"')[1].split(">")[0]


def test_new_operation_form_cti_upload_has_no_name_attribute(client):
    # A proposito: el archivo se sube via fetch() a /operations/cti-extract,
    # nunca como parte del POST normal de create_operation() -- sin
    # `name`, un input file no viaja en un submit application/x-www-
    # form-urlencoded aunque el control quede sin tocar.
    response = client.get("/operations/new")

    text = response.data.decode()
    tag = text.split('id="cti_report_upload"')[1].split(">")[0]
    assert "name=" not in tag


def test_new_operation_form_has_cti_extract_button_and_result_container(client):
    response = client.get("/operations/new")

    text = response.data.decode()
    assert 'id="cti-extract-button"' in text
    assert 'id="cti-extract-result"' in text


def test_new_operation_form_no_longer_shows_soon_placeholder_for_cti(client):
    response = client.get("/operations/new")

    text = response.data.decode()
    # El badge "proximamente" (M12k) tiene que haber desaparecido --
    # confirma que esto reemplaza el placeholder, no que coexiste con el.
    cti_section = text.split('id="cti_report_upload"')[0][-400:] + text.split('id="cti_report_upload"')[1][:400]
    assert "soon" not in cti_section
    assert "todav" not in cti_section.lower()


def test_creating_operation_does_not_require_cti_upload_field(client):
    # Sin `name`, el control de CTI nunca viaja en el POST normal (ver
    # test_new_operation_form_cti_upload_has_no_name_attribute) -- crear
    # una operacion sin haber usado la extraccion de CTI sigue
    # funcionando igual que siempre.
    form = dict(
        name="Operacion sin informe de CTI",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    response = client.post("/operations/new", data=form, follow_redirects=False)

    assert response.status_code == 302
