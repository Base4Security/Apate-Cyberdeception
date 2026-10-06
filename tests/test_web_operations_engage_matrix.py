"""Tests de integracion web para la matriz visual de MITRE Engage
(M13b) en el selector "Vincular plugin" -- ver docs/roadmap.md
seccion M13b.

Complementa (no reemplaza) tests/test_web_operations_engage.py (M12c,
name/value de los checkboxes y el submit) y
tests/test_web_operations_engage_suggestions.py (M12d, badge
"sugerida") -- esos dos siguen pasando sin modificar contra el nuevo
layout, confirmando que el POST no cambio de comportamiento. Este
archivo cubre especificamente la reestructuracion visual: Goals como
columnas, en el orden real de apate.engage.list_goals(), y que una
actividad con mas de un Approach siga apareciendo en mas de una celda
sin romper el dedup del submit."""

from apate.engage import get_activity, list_approaches


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M13b",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


# -- Estructura de la matriz (Goals como columnas) ---------------------------


def test_engage_matrix_wrapper_and_column_classes_present(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    assert 'class="engage-matrix"' in text
    assert 'class="card engage-matrix-column"' in text


def test_engage_matrix_goal_columns_appear_in_the_real_engage_order(client):
    # Confirmado contra apate.engage.list_goals(): Expose, Affect,
    # Elicit (Prepare/Understand son "strategic", filtrados antes de
    # llegar al template -- ver _engagement_activities_by_goal()).
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    matrix_start = text.index('class="engage-matrix"')
    expose_index = text.index(">Expose<", matrix_start)
    affect_index = text.index(">Affect<", matrix_start)
    elicit_index = text.index(">Elicit<", matrix_start)

    assert matrix_start < expose_index < affect_index < elicit_index


def test_engage_matrix_does_not_offer_strategic_goals_as_columns(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    matrix = text[text.index('class="engage-matrix"') : text.index("</form>")]
    assert ">Prepare<" not in matrix
    assert ">Understand<" not in matrix


# -- Una misma actividad en mas de un Approach/celda -------------------------


def test_activity_with_multiple_approaches_appears_once_per_approach_cell(client):
    # "Lures" (EAC0005) pertenece a 3 Approaches reales (Detect/Direct/
    # Disrupt, confirmado contra apate.engage.get_activity("EAC0005").
    # approach_ids) -- tiene que aparecer como checkbox en las 3
    # celdas, cada una con el mismo value= (no un value distinto por
    # celda, que rompería el dedup por set() de add_plugin_binding()).
    operation_id = _create_operation(client)
    lures = get_activity("EAC0005")
    approach_names = {
        approach.name for approach in list_approaches() if approach.id in lures.approach_ids
    }
    assert approach_names == {"Detect", "Direct", "Disrupt"}

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    occurrences = text.count(f'name="engage_activity_ids" value="{lures.id}"')
    assert occurrences == len(lures.approach_ids) == 3

    # Cada input tiene un id= distinto (uno por celda/Approach), asi
    # que el navegador no los colapsa -- pero todos comparten el mismo
    # name/value, que es lo unico que llega al servidor en el POST.
    ids_present = {
        f'id="engage-{approach_id}-{lures.id}"' in text for approach_id in lures.approach_ids
    }
    assert ids_present == {True}


def test_repeated_activity_across_cells_still_dedupes_on_submit(client, app):
    # Regresion end-to-end: marcar la misma actividad en mas de una de
    # las celdas donde aparece (simulando al operador tildando "Lures"
    # bajo Detect y bajo Direct) sigue guardando un solo id -- mismo
    # comportamiento que ya cubre test_web_operations_engage.py, mas
    # explicito sobre "mas de una celda" ahora que el layout es una
    # matriz real.
    operation_id = _create_operation(client)
    lures = get_activity("EAC0005")

    client.post(
        f"/operations/{operation_id}/plugins",
        data={
            "plugin_id": "honeytoken-1",
            "surface": "data",
            "engage_activity_ids": [lures.id, lures.id],
        },
        follow_redirects=False,
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins[0].effect.engage_activity_ids == [lures.id]


# -- Badge "sugerida" dentro de la celda correcta (regresion visual, M12d) ---


def test_suggested_badge_still_appears_inside_the_matching_cell_in_the_matrix(client):
    # Mismo criterio que test_web_operations_engage_suggestions.py,
    # pero verificando explicitamente que la celda vive dentro de la
    # nueva estructura de matriz (una columna .card por Goal).
    operation_id = _create_operation(client, expected_ttps=["T1003"])
    lures = get_activity("EAC0005")

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    assert 'class="card engage-matrix-column"' in text
    checkbox_index = text.index(f'value="{lures.id}"')
    label_end = text.find("</label>", checkbox_index)
    assert "sugerida" in text[checkbox_index:label_end]
