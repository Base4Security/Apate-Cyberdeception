"""Test de integracion web para la sugerencia de actividades de Engage
(M12d) en el formulario de "Vincular plugin" -- ver
docs/analisis-engage-integral.md y apate.engage.suggest_activities().

Sigue el mismo patron que tests/test_web_operations_engage.py: postea
al formulario real via el `client` de tests/conftest.py, sin mockear
nada."""

import re

from apate.engage import get_activity

_ENGAGE_CHECKBOX_RE = re.compile(rb'<input type="checkbox"[^>]*name="engage_activity_ids"[^>]*>')


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M12d",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_detail_page_marks_suggested_activities_for_operation_with_expected_ttps(client):
    # T1003 (credential-access) -> EAC0005 (Lures) via
    # engage_ttp_suggestions.json.
    operation_id = _create_operation(client, expected_ttps=["T1003"])
    lures = get_activity("EAC0005")

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    text = response.data.decode()
    assert "sugerida" in text
    # La marca aparece asociada al checkbox de esa actividad puntual
    # (mismo <label>), no solo en cualquier lugar de la pagina.
    lures_checkbox_index = text.index(f'value="{lures.id}"')
    next_checkbox_index = text.find("</label>", lures_checkbox_index)
    assert "sugerida" in text[lures_checkbox_index:next_checkbox_index]


def test_detail_page_does_not_mark_any_activity_when_no_expected_ttps(client):
    operation_id = _create_operation(client)  # sin expected_ttps

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    # La palabra "sugerida" aparece siempre en la leyenda explicativa
    # del selector (est&aacute;tica, sin depender de los TTPs de la
    # operacion) -- lo que no deberia aparecer es el badge puntual por
    # actividad, que lleva este title especifico.
    assert b'title="Sugerida a partir de' not in response.data


def test_detail_page_does_not_mark_activities_for_ttp_in_unmapped_tactic(client):
    # T1190 (initial-access) no tiene ninguna actividad mapeada en el
    # dataset de M12d -- no deberia aparecer ninguna marca "sugerida".
    operation_id = _create_operation(client, expected_ttps=["T1190"])

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    # La palabra "sugerida" aparece siempre en la leyenda explicativa
    # del selector (est&aacute;tica, sin depender de los TTPs de la
    # operacion) -- lo que no deberia aparecer es el badge puntual por
    # actividad, que lleva este title especifico.
    assert b'title="Sugerida a partir de' not in response.data


def test_suggestion_does_not_preselect_any_checkbox(client):
    # La sugerencia es indicativa nomas: ningun checkbox del selector
    # deberia salir marcado ("checked") solo por estar sugerido. Chequeo
    # acotado a los propios tags <input ... name="engage_activity_ids">
    # (en vez de buscar el substring "checked" en toda la pagina) porque
    # la reorganizacion de la matriz en un <details> colapsable sumo un
    # script con la palabra "checked" (querySelector(':checked')) que no
    # tiene nada que ver con el HTML de los checkboxes en si.
    operation_id = _create_operation(client, expected_ttps=["T1003"])

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b'name="engage_activity_ids"' in response.data
    checkbox_tags = _ENGAGE_CHECKBOX_RE.findall(response.data)
    assert checkbox_tags, "no se encontro ningun checkbox de engage_activity_ids"
    assert all(b"checked" not in tag for tag in checkbox_tags)
