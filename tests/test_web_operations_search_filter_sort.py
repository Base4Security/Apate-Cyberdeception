"""Tests para el buscador/filtro/orden de la tabla de /operations/
(ultimo item de la tanda de mejoras post-BlackHat) -- ver
docs/roadmap.md para el detalle.

Todo client-side (JS plano sobre atributos data-*, sin recarga de
pagina, mismo criterio que el resto de la UI: tabs, wizard,
collapsibles). Sin navegador real en este entorno -- estos tests son
estructurales (confirman que el HTML servido trae los ganchos que el
JS necesita: atributos data-*, ids, clases), no ejercitan el
JavaScript en si. La verificacion de que el filtrado/orden funciona
de verdad en un navegador se hizo aparte con Playwright real (ver
docs/roadmap.md)."""

from apate.core import OperationStatus


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba",
        adversary_name="APT ficticio",
        adversary_motivation="espionaje",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046", "T1078"],
        environment="isolated",
        narrative_name="Narrativa base",
        narrative_description="desc",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_toolbar_absent_when_no_operations(client):
    response = client.get("/operations/")

    assert response.status_code == 200
    assert b"Plantilla: inici" in response.data
    assert b'id="operations-search"' not in response.data
    assert b'id="operations-status-filter"' not in response.data
    assert b'id="operations-table"' not in response.data


def test_toolbar_present_when_at_least_one_operation_exists(client):
    _create_operation(client, name="Operacion Q1")

    response = client.get("/operations/")

    assert response.status_code == 200
    assert b'id="operations-search"' in response.data
    assert b'id="operations-status-filter"' in response.data
    assert b'id="operations-result-count"' in response.data
    assert b'id="operations-table"' in response.data
    assert b'id="operations-clear-filters"' in response.data
    assert b'data-status-option="planning"' in response.data
    assert b'aria-live="polite"' in response.data


def test_status_filter_lists_the_four_real_statuses(client):
    _create_operation(client, name="Operacion Q1")

    response = client.get("/operations/")
    text = response.data.decode("utf-8")

    labels = {"planning": "En preparación", "active": "Activa", "compromised": "Comprometida", "closed": "Cerrada"}
    for status in OperationStatus:
        assert f'<option value="{status.value}">{labels[status.value]}</option>' in text
    # "Todos" -- opcion sin filtro, valor vacio.
    assert '<option value="">Todos</option>' in text


def test_row_carries_data_attributes_for_filter_and_sort(client):
    operation_id = _create_operation(client, name="Operacion con TTPs")

    response = client.get("/operations/")
    text = response.data.decode("utf-8")

    assert 'data-status="planning"' in text
    assert 'data-ttp-count="2"' in text  # expected_ttps=["T1046", "T1078"]
    assert "data-created=" in text
    assert operation_id in text


def test_sortable_headers_present_for_name_status_ttpcount_created(client):
    _create_operation(client, name="Operacion Q1")

    response = client.get("/operations/")
    text = response.data.decode("utf-8")

    for key, sort_type, label in (
        ("name", "text", "Nombre"),
        ("status", "text", "Estado"),
        ("ttp-count", "number", "TTPs esperadas"),
        ("created", "text", "Creada"),
    ):
        heading = f'data-sort-key="{key}" data-sort-type="{sort_type}"'
        assert heading in text
        heading_html = text.split(heading, 1)[1].split("</th>", 1)[0]
        assert 'tabindex="0"' in heading_html
        assert 'role="button"' in heading_html
        assert 'aria-sort="none"' in heading_html
        assert label in heading_html


def test_adversary_column_is_not_sortable(client):
    # Decision deliberada: el buscador ya cubre "Adversario" por texto
    # libre, ordenarlo no fue pedido y no suma nada que el buscador no
    # cubra ya.
    _create_operation(client, name="Operacion Q1")

    response = client.get("/operations/")
    text = response.data.decode("utf-8")

    assert "<th>Adversario</th>" in text
    assert 'data-sort-key="adversary"' not in text


def test_no_results_row_present_and_hidden_by_default(client):
    _create_operation(client, name="Operacion Q1")

    response = client.get("/operations/")
    text = response.data.decode("utf-8")

    assert 'id="operations-no-results" class="hidden"' in text
    assert "Ninguna operaci" in text


def test_operations_table_wrapped_in_table_scroll(client):
    # Extiende a esta tabla el fix de .table-scroll (encontrado roto a
    # 390px en la verificacion visual anterior, corregido en Plugins
    # vinculados en la tarea anterior) ya que esta tarea la toca de
    # todas formas y la vuelve a verificar visualmente.
    _create_operation(client, name="Operacion Q1")

    response = client.get("/operations/")
    text = response.data.decode("utf-8")

    scroll_pos = text.index('<div class="table-scroll">')
    table_pos = text.index('<table id="operations-table">')
    assert scroll_pos < table_pos


def test_dashboard_kpis_and_recent_firings_sections_unchanged(client):
    # No se toca la agregacion de KPIs (M13d) ni "Ultimas reglas
    # disparadas" -- solo la tabla de abajo.
    _create_operation(client, name="Operacion Q1")

    response = client.get("/operations/")
    text = response.data.decode("utf-8")

    assert "Activas" in text
    assert "Comprometidas" in text
    assert 'Cobertura de <abbr title="T&aacute;cticas, t&eacute;cnicas y procedimientos">TTPs</abbr>' in text
    assert "ximos cierres" in text  # "Pr&oacute;ximos cierres"
    assert "Actividad reciente del motor" in text


def test_operation_filters_and_sort_are_shareable_by_url(client):
    _create_operation(client, name="URL compartible", adversary_name="Actor")
    text = client.get("/operations/?q=URL&status=planning&sort=name&dir=desc").get_data(as_text=True)
    assert "new URLSearchParams(window.location.search)" in text
    assert "initialParams.get('q')" in text
    assert "params.set('sort', key)" in text


def test_operation_filters_have_quick_chips_and_explicit_reset(client):
    _create_operation(client, name="Filtros profesionales")
    text = client.get("/operations/").get_data(as_text=True)

    assert 'role="group" aria-label="Filtros r&aacute;pidos por estado"' in text
    assert 'data-status-option="" aria-pressed="true"' in text
    assert "clearFiltersButton.addEventListener('click'" in text
    assert "button.setAttribute('aria-pressed', String(active))" in text
    assert "event.key !== 'Enter' && event.key !== ' '" in text


def test_portfolio_sections_are_shareable_by_url(client):
    _create_operation(client, name="Portfolio URL")
    text = client.get("/operations/portfolio?open=heatmap,plugins").get_data(as_text=True)
    assert 'data-portfolio-section="heatmap"' in text
    assert "requestedOpenSections" in text
