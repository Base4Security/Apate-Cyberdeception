"""Tests de integracion web para el heatmap de TTPs (M13a) en
operations/detail.html -- ver docs/roadmap.md seccion M13a y
docs/analisis-ui-profesional.md. Sigue el mismo patron que
tests/test_web_operations.py (helper _create_operation/_create_closed_operation
posteando al formulario real) y tests/test_web_telemetry.py (_seed_event
para inyectar telemetria directo via TELEMETRY_COLLECTOR.handle_event(),
sin pasar por un EventBus/plugin real)."""

from apate.plugins import EventType, PluginEvent


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M13a",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def _create_closed_operation(client, **overrides):
    operation_id = _create_operation(client, **overrides)
    client.post(f"/operations/{operation_id}/transition", data={"to": "closed"})
    return operation_id


def _seed_ttp_observed(app, operation_id: str, ttp_id: str) -> None:
    app.config["TELEMETRY_COLLECTOR"].handle_event(
        PluginEvent(
            event_type=EventType.TTP_OBSERVED,
            plugin_id="honeypot-mock-1",
            surface="network",
            operation_id=operation_id,
            payload={"ttp_id": ttp_id},
        )
    )


def _cell_classes(text: str, ttp_id: str) -> str:
    """Extrae el atributo class= completo de la celda de esa tecnica,
    identificada por su id dentro del title= del div.ttp-cell."""

    # Acotamos primero al bloque del heatmap: el mismo id de tecnica aparece
    # en otras partes de la pagina (TTPs esperadas del perfil, por ejemplo) y
    # cual de esas ocurrencias viene primero depende del orden de los tabs.
    heatmap = text[text.index('<div class="ttp-heatmap">') :]
    idx = heatmap.index(f'>{ttp_id}<')  # <span class="mono">T1078</span> -- el id aparece como texto de ese span
    # Retrocedemos hasta el div.ttp-cell que contiene este span.
    div_start = heatmap.rindex('<div class="ttp-cell', 0, idx)
    div_tag_end = heatmap.index(">", div_start)
    return heatmap[div_start:div_tag_end]


# -- Heatmap solo para operaciones CLOSED ------------------------------------


def test_ttp_heatmap_not_shown_for_non_closed_operation(client):
    operation_id = _create_operation(client, expected_ttps=["T1078"])

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b"Heatmap de TTPs" not in response.data
    assert b"ttp-heatmap" not in response.data


def test_ttp_heatmap_shown_for_closed_operation(client):
    operation_id = _create_closed_operation(client, expected_ttps=["T1078"])

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b'Matriz de <abbr title="T&aacute;cticas, t&eacute;cnicas y procedimientos">TTPs</abbr>' in response.data
    assert b'class="ttp-heatmap"' in response.data


# -- Clasificacion correcta por conjunto (matched/not-observed/unexpected) --


def test_ttp_heatmap_classifies_matched_not_observed_and_unexpected_cells(client, app):
    # T1078/T1005/T1057 estan los tres en el catalogo curado de M12j
    # (apate.attack.list_techniques()) -- confirmado, es lo que dibuja
    # una celda en la grilla.
    operation_id = _create_closed_operation(client, expected_ttps=["T1078", "T1005"])
    _seed_ttp_observed(app, operation_id, "T1078")  # esperada y observada -> matched
    # T1005 esperada pero nunca observada -> not-observed (no hace falta sembrar nada)
    _seed_ttp_observed(app, operation_id, "T1057")  # observada, no esperada -> unexpected

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    assert "ttp-cell-matched" in _cell_classes(text, "T1078")
    assert "ttp-cell-not-observed" in _cell_classes(text, "T1005")
    assert "ttp-cell-unexpected" in _cell_classes(text, "T1057")


def test_ttp_heatmap_neutral_cell_for_technique_unrelated_to_operation(client, app):
    operation_id = _create_closed_operation(client, expected_ttps=["T1078"])
    _seed_ttp_observed(app, operation_id, "T1078")

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    # T1005 (catalogo) no esta ni esperada ni observada en esta operacion
    # -- celda neutra, sin ninguna clase ttp-cell-<status>.
    classes = _cell_classes(text, "T1005")
    assert "ttp-cell-matched" not in classes
    assert "ttp-cell-not-observed" not in classes
    assert "ttp-cell-unexpected" not in classes


# -- TTPs fuera del catalogo curado: listadas aparte, no perdidas -----------


def test_uncatalogued_unexpected_ttp_listed_separately_not_lost(client, app):
    # T1046 confirmado fuera del catalogo curado de 41 tecnicas
    # (apate.attack.list_techniques()) -- no puede tener celda en la
    # grilla, pero tampoco debe desaparecer silenciosamente.
    operation_id = _create_closed_operation(client, expected_ttps=["T1078"])
    _seed_ttp_observed(app, operation_id, "T1078")
    _seed_ttp_observed(app, operation_id, "T1046")

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    text = response.data.decode()
    assert "fuera del cat" in text  # "TTPs fuera del catálogo curado..."
    assert "T1046" in text
    assert "observada, no esperada" in text
    # Y no le agrego una celda fantasma a la grilla (no hay ninguna
    # tecnica T1046 en el catalogo curado que pueda pintarse).
    assert 'value="T1046"' not in text  # no es un checkbox de ningun otro formulario en esta pagina


def test_operation_without_any_ttps_renders_heatmap_without_crashing(client):
    operation_id = _create_closed_operation(client)  # sin expected_ttps

    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b'Matriz de <abbr title="T&aacute;cticas, t&eacute;cnicas y procedimientos">TTPs</abbr>' in response.data
