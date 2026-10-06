"""Test de integracion web para la sugerencia de actividades de Engage
a partir del objetivo estrategico -- segunda mejora del backlog de
Engage post-M12, funcion hermana de la sugerencia por TTP (M12d, ver
tests/test_web_operations_engage_suggestions.py).

Mismo patron: postea al formulario real via el `client` de
tests/conftest.py, sin mockear nada."""

import re

from apate.engage import get_activity

_ENGAGE_CHECKBOX_RE = re.compile(rb'<input type="checkbox"[^>]*name="engage_activity_ids"[^>]*>')


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba sugerencia por objetivo",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_detail_page_marks_activity_suggested_by_objective(client):
    # early_detection -> Expose/Detect (EAP0002), incluye EAC0004
    # (Network Analysis).
    operation_id = _create_operation(client, objectives=["early_detection"])
    activity = get_activity("EAC0004")

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    assert response.status_code == 200
    checkbox_index = text.index(f'value="{activity.id}"')
    label_end = text.find("</label>", checkbox_index)
    row = text[checkbox_index:label_end]
    assert "sugerida (objetivo)" in row


def test_objective_suggestion_badge_distinguishes_from_ttp_suggestion(client):
    # T1005 (collection) -> EAC0011 "Pocket Litter" por TTP (M12d);
    # early_detection -> EAC0004 "Network Analysis" por objetivo --
    # dos actividades distintas, sin superposicion entre los dos
    # conjuntos (confirmado contra el dataset real antes de escribir
    # el test), cada una con su propio origen marcado.
    operation_id = _create_operation(client, expected_ttps=["T1005"], objectives=["early_detection"])

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    pocket_litter = get_activity("EAC0011")
    network_analysis = get_activity("EAC0004")

    pl_index = text.index(f'value="{pocket_litter.id}"')
    pl_row = text[pl_index : text.find("</label>", pl_index)]
    assert "sugerida por TTP" in pl_row
    assert "sugerida (objetivo)" not in pl_row

    na_index = text.index(f'value="{network_analysis.id}"')
    na_row = text[na_index : text.find("</label>", na_index)]
    assert "sugerida (objetivo)" in na_row
    assert "sugerida (TTP)" not in na_row


def test_activity_suggested_by_both_ttp_and_objective_shows_both_badges(client):
    # T1071 (command-and-control) -> EAC0016 (Network Manipulation) via
    # M12d (engage_ttp_suggestions.json); controls_validation ->
    # Affect/Prevent (EAP0003), que tambien incluye EAC0016 -- misma
    # actividad sugerida por las dos señales. Confirmado contra el
    # dataset real antes de escribir el test.
    operation_id = _create_operation(client, expected_ttps=["T1071"], objectives=["controls_validation"])
    activity = get_activity("EAC0016")

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    index = text.index(f'value="{activity.id}"')
    row = text[index : text.find("</label>", index)]
    assert "sugerida por TTP" in row
    assert "sugerida (objetivo)" in row


def test_detail_page_does_not_mark_objective_suggestion_without_objectives(client):
    # "sugerida (objetivo)" en si aparece siempre en la leyenda
    # explicativa (estatica, sin depender de los objetivos de la
    # operacion) -- lo que no deberia aparecer es el badge puntual por
    # actividad, que lleva este title especifico (mismo criterio que
    # test_web_operations_engage_suggestions.py con la sugerencia por TTP).
    operation_id = _create_operation(client)  # sin objectives

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b'title="Sugerida a partir de los objetivos' not in response.data


def test_objective_suggestion_does_not_preselect_any_checkbox(client):
    # Chequeo acotado a los propios tags <input ... name="engage_activity_ids">
    # (en vez de buscar el substring "checked" en toda la pagina) porque
    # la reorganizacion de la matriz en un <details> colapsable sumo un
    # script con la palabra "checked" (querySelector(':checked')) que no
    # tiene nada que ver con el HTML de los checkboxes en si.
    operation_id = _create_operation(client, objectives=["early_detection"])

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b'name="engage_activity_ids"' in response.data
    checkbox_tags = _ENGAGE_CHECKBOX_RE.findall(response.data)
    assert checkbox_tags, "no se encontro ningun checkbox de engage_activity_ids"
    assert all(b"checked" not in tag for tag in checkbox_tags)


def test_legend_explains_the_two_suggestion_origins(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    assert "sugerida (TTP)" in text
    assert "sugerida (objetivo)" in text
    assert "juicio interpretativo" in text
