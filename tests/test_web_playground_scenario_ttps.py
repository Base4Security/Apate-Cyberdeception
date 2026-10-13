"""Tests de integracion web para la cobertura del escenario fijo del
Playground (M14g) en playground/defender.html -- ver docs/roadmap.md
seccion M14g.

Mismo patron que test_web_playground_expected_vs_observed.py (M14f):
no reimplementa apate.playground.scenario_ttps.match_scenario_ttps()
(ya probada contra el dataset real en test_playground_scenario_ttps.py)
-- ejercita el mismo camino real via el `client`."""


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion Playground M14g",
        adversary_name="APT ficticio",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def _add_scenario(client, operation_id, **overrides):
    data = dict(description="Escenario de prueba", related_ttps="", deception_level="basic")
    data.update(overrides)
    response = client.post(f"/operations/{operation_id}/scenarios", data=data, follow_redirects=False)
    assert response.status_code == 302


def test_defender_view_shows_scenario_coverage_section_heading(client):
    operation_id = _create_operation(client)

    response = client.get(f"/playground/{operation_id}/defender")

    assert response.status_code == 200
    assert b"Cobertura del escenario fijo del Playground" in response.data


def test_defender_view_without_any_scenario_says_so_explicitly(client):
    # Mismo criterio que M12i/M14f: caso vacio explicito, no se omite
    # la seccion en silencio.
    operation_id = _create_operation(client)

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert "no tiene ning" in text
    assert "escenario asociado" in text


def test_defender_view_shows_producible_ttps_for_a_matching_scenario(client):
    # T1046 (Network Service Scanning, fase port_scanning del atacante)
    # esta en el dataset de M14g -- el escenario fijo si la produce.
    operation_id = _create_operation(client)
    _add_scenario(client, operation_id, description="Detectar escaneo interno", related_ttps="T1046")

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert "Detectar escaneo interno" in text
    assert "El escenario fijo s" in text  # "sí puede producir" (acento)
    assert "T1046" in text
    assert "Network Service Scanning" in text


def test_defender_view_shows_not_producible_ttps_honestly(client):
    # T1098 (Account Manipulation) no esta en ninguna de las dos tablas
    # reales investigadas en M14g -- el escenario fijo no la produce.
    operation_id = _create_operation(client)
    _add_scenario(client, operation_id, description="Persistencia esperada", related_ttps="T1098")

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert "Persistencia esperada" in text
    assert "no tiene ninguna chance de producir" in text
    assert "T1098" in text


def test_defender_view_shows_both_producible_and_not_producible_for_the_same_scenario(client):
    operation_id = _create_operation(client)
    _add_scenario(client, operation_id, description="Escenario mixto", related_ttps="T1046,T1098")

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert "El escenario fijo s" in text
    assert "no tiene ninguna chance de producir" in text
    assert "T1046" in text
    assert "T1098" in text


def test_defender_view_shows_coverage_per_scenario_for_multiple_scenarios(client):
    operation_id = _create_operation(client)
    _add_scenario(client, operation_id, description="Primer escenario", related_ttps="T1046")
    _add_scenario(client, operation_id, description="Segundo escenario", related_ttps="T1098")

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert "Primer escenario" in text
    assert "Segundo escenario" in text


def test_defender_view_scenario_without_expected_ttps_says_so_explicitly(client):
    operation_id = _create_operation(client)
    _add_scenario(client, operation_id, description="Escenario sin TTPs", related_ttps="")

    response = client.get(f"/playground/{operation_id}/defender")
    text = response.data.decode()

    assert "Escenario sin TTPs" in text
    assert "no tiene TTPs esperadas cargadas" in text
