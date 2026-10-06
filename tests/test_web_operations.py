def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba",
        adversary_name="APT ficticio",
        adversary_motivation="espionaje",
        adversary_skill_level="intermediate",
        expected_ttps="T1046, T1078",
        environment="isolated",
        narrative_name="Narrativa base",
        narrative_description="desc",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def test_list_operations_empty_returns_200(client):
    response = client.get("/operations/")
    assert response.status_code == 200
    assert b"Todav" in response.data  # "Todavia no hay operaciones creadas."


def test_new_operation_form_returns_200(client):
    response = client.get("/operations/new")
    assert response.status_code == 200


def test_create_operation_redirects_to_detail(client):
    operation_id = _create_operation(client)
    response = client.get(f"/operations/{operation_id}")
    assert response.status_code == 200


def test_list_operations_shows_created_operation(client):
    _create_operation(client, name="Operacion Q1")
    response = client.get("/operations/")
    assert b"Operacion Q1" in response.data


def test_operation_detail_shows_profile_and_status(client):
    operation_id = _create_operation(client, adversary_name="Actor de ejemplo")
    response = client.get(f"/operations/{operation_id}")

    assert response.status_code == 200
    assert b"Actor de ejemplo" in response.data
    assert b"T1046" in response.data
    assert b"Planificada" in response.data


def test_detail_404_for_unknown_operation(client):
    response = client.get("/operations/no-existe")
    assert response.status_code == 404


def test_transition_404_for_unknown_operation(client):
    response = client.post("/operations/no-existe/transition", data={"to": "active"})
    assert response.status_code == 404


def test_transition_to_active_updates_status(client):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/transition", data={"to": "active"}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"badge-active" in response.data


def test_invalid_transition_flashes_error_and_keeps_status(client):
    operation_id = _create_operation(client)

    # PLANNING -> COMPROMISED no esta permitido (ver _ALLOWED_TRANSITIONS
    # en el Nucleo de Operacion): la UI debe mostrar el error, no
    # romper con un 500, y la operacion debe seguir en planning.
    response = client.post(
        f"/operations/{operation_id}/transition", data={"to": "compromised"}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert b"badge-planning" in response.data


def test_transition_with_unknown_target_flashes_error(client):
    operation_id = _create_operation(client)

    response = client.post(
        f"/operations/{operation_id}/transition", data={"to": "not-a-real-status"}, follow_redirects=True
    )

    assert response.status_code == 200
    assert b"flash-error" in response.data
