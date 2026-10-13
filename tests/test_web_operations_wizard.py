"""Tests para el wizard cosmetico de operations/form.html (M12e) -- ver
docs/roadmap.md seccion M12e. La suite es pytest sobre Flask (sin
Selenium/Playwright en ningun hito anterior), asi que no hay forma de
ejercitar la navegacion entre pasos en si (JS puro, mostrar/ocultar) --
lo que se puede confirmar automatizado es que el HTML resultante trae
la estructura de pasos (progreso, botones, wizard-step) y que TODOS los
campos que ya postea la suite existente (test_web_operations.py y
demas test_web_operations_*.py) siguen presentes con el mismo `name`,
sin importar en que fieldset/paso hayan quedado -- el wizard es
puramente cosmetico, el POST a create_operation() no cambia.

Checklist manual de navegacion (documentado en el resumen de M12e en
vez de un test de browser nuevo, ver docs/roadmap.md): abrir
/operations/new, confirmar que "Siguiente" avanza y "Atras" retrocede,
que el indicador de progreso actualiza ("Paso X de 3"), que "Crear
operacion" solo aparece en el paso 3, que dejar "Nombre" u otro campo
required vacio en el paso 1 bloquea "Siguiente" con el tooltip nativo
del navegador (no deja avanzar a un paso con el error invisible), y
que el selector de grupo APT (M12j) y la precarga de "Reoperar" (M12g)
siguen funcionando dentro del paso 1."""


def test_new_operation_form_has_wizard_structure(client):
    response = client.get("/operations/new")

    assert response.status_code == 200
    text = response.data.decode()
    assert 'id="operation-form"' in text
    assert 'id="wizard-progress"' in text
    assert "Paso 1 de 3" in text
    assert 'id="wizard-prev"' in text
    assert 'id="wizard-next"' in text
    assert 'id="wizard-submit"' in text
    assert text.count('class="wizard-step') == 3  # 3 pasos: perfil, reglas/objetivos, narrativa


def test_empty_inventory_links_to_a_new_tab_without_replacing_the_wizard(client):
    text = client.get("/operations/new").get_data(as_text=True)

    assert 'href="/assets/"' in text
    assert 'target="_blank"' in text
    assert 'rel="noopener"' in text
    assert "conservar este formulario" in text


def test_form_has_novalidate_so_native_validation_never_blocks_submit_silently(client):
    # Sin novalidate, el navegador corre su validacion automatica ANTES
    # de disparar 'submit' -- si hay un required invalido en un paso
    # oculto (display:none), cancela el envio en silencio sin que el
    # listener de submit del wizard llegue a ejecutarse siquiera. Con
    # novalidate, 'submit' siempre dispara y la validacion queda en
    # manos del JS del wizard (que navega al paso correcto antes de
    # llamar reportValidity()).
    response = client.get("/operations/new")

    text = response.data.decode()
    form_idx = text.index('id="operation-form"')
    form_tag_end = text.index(">", form_idx)
    assert "novalidate" in text[form_idx:form_tag_end]


def test_wizard_submit_button_starts_hidden_and_next_button_does_not(client):
    # El paso 1 es el que se ve al cargar la pagina -- "Crear operacion"
    # (el submit real) tiene que arrancar oculto, "Siguiente" no.
    response = client.get("/operations/new")

    text = response.data.decode()
    submit_idx = text.index('id="wizard-submit"')
    submit_tag_end = text.index(">", submit_idx)
    assert "hidden" in text[submit_idx:submit_tag_end]

    next_idx = text.index('id="wizard-next"')
    next_tag_end = text.index(">", next_idx)
    assert "hidden" not in text[next_idx:next_tag_end]


def test_wizard_prev_button_starts_hidden(client):
    response = client.get("/operations/new")

    text = response.data.decode()
    prev_idx = text.index('id="wizard-prev"')
    prev_tag_end = text.index(">", prev_idx)
    assert "hidden" in text[prev_idx:prev_tag_end]


def test_new_operation_form_still_has_every_field_name_regardless_of_step(client):
    # Todos los name= que ya postea el resto de la suite, sin importar
    # en que paso/fieldset hayan terminado -- confirma que agrupar en
    # pasos no perdio ni renombro ningun campo.
    response = client.get("/operations/new")

    text = response.data.decode()
    expected_field_names = [
        "name",
        "adversary_name",
        "adversary_motivation",
        "adversary_skill_level",
        "adversary_notes",
        "target_assets",
        "expected_ttps",
        "environment",
        "end_date",
        "objectives",
        "roles",
        "resource_estimate",
        "narrative_name",
        "narrative_description",
        "psychological_impact",
    ]
    for field_name in expected_field_names:
        assert f'name="{field_name}"' in text, f"falta name={field_name!r} en el formulario"


def test_attack_group_script_and_engine_still_present_inside_wizard(client):
    # M12j: el selector de grupo APT y el script que lo maneja siguen
    # en el HTML -- solo cambio el contenedor (wizard-step), no el
    # mecanismo en si.
    response = client.get("/operations/new")

    text = response.data.decode()
    assert 'id="attack_group_select"' in text
    assert "APATE_ATTACK_GROUPS" in text
    assert "attack-technique-checkbox" in text


def test_create_operation_post_unaffected_by_wizard_markup(client):
    # El submit real sigue siendo el mismo POST atomico de siempre --
    # el wizard es cosmetico, no cambia create_operation().
    response = client.post(
        "/operations/new",
        data=dict(
            name="Operacion wizard",
            adversary_name="APT ficticio",
            adversary_skill_level="intermediate",
            expected_ttps=["T1046"],
            environment="isolated",
            narrative_name="Narrativa base",
        ),
        follow_redirects=False,
    )

    assert response.status_code == 302
    detail = client.get(response.headers["Location"])
    assert detail.status_code == 200
    assert b"Operacion wizard" in detail.data
