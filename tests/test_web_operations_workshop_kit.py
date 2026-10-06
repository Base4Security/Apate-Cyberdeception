"""Tests de integracion web para "Descargar kit de taller" (M12i) --
GET /operations/<id>/workshop-kit. Sigue el mismo patron que
tests/test_web_operations.py (helper _create_operation posteando al
formulario real, sin mockear nada) -- a diferencia de /report (M6),
esta ruta debe responder en cualquier estado de la operacion, no solo
CLOSED."""


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M12i",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046", "T1078"],
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_workshop_kit_responds_for_operation_in_planning(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}/workshop-kit")

    assert response.status_code == 200
    assert response.mimetype == "text/markdown"
    assert "attachment" in response.headers["Content-Disposition"]
    assert b"Kit de taller" in response.data
    assert b"APT ficticio" in response.data


def test_workshop_kit_responds_for_active_operation(client):
    operation_id = _create_operation(client)
    client.post(f"/operations/{operation_id}/transition", data={"to": "active"})

    response = client.get(f"/operations/{operation_id}/workshop-kit")

    assert response.status_code == 200


def test_workshop_kit_responds_for_closed_operation(client):
    operation_id = _create_operation(client)
    client.post(f"/operations/{operation_id}/transition", data={"to": "closed"})

    response = client.get(f"/operations/{operation_id}/workshop-kit")

    assert response.status_code == 200


def test_workshop_kit_404_for_unknown_operation(client):
    response = client.get("/operations/no-existe/workshop-kit")
    assert response.status_code == 404


def test_detail_page_shows_workshop_kit_button_regardless_of_status(client):
    open_operation_id = _create_operation(client)
    response = client.get(f"/operations/{open_operation_id}")
    assert b"Descargar kit de taller" in response.data

    closed_operation_id = _create_operation(client, name="Operacion cerrada M12i")
    client.post(f"/operations/{closed_operation_id}/transition", data={"to": "closed"})
    response = client.get(f"/operations/{closed_operation_id}")
    assert b"Descargar kit de taller" in response.data
