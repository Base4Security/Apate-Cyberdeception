"""Fase 1 post-BlackHat (ver docs/roadmap.md): identidad de operador
via sesion de Flask, no autenticacion (M13j se mantiene sin login).
`POST /operator` setea/limpia `session["operator"]`; el context
processor `_inject_current_operator()` lo expone a cualquier
plantilla como `current_operator`."""


def test_index_shows_no_operator_by_default(client):
    # "/" es la landing (M13d+): vacia el bloque de sidebar a proposito
    # (pagina propia sin nav lateral) -- el operador se ve en cualquier
    # otra pantalla, que si usa el sidebar comun de base.html.
    response = client.get("/operations/")
    assert b'placeholder="sin especificar"' in response.data
    assert b'value=""' in response.data


def test_open_instance_notice_is_secondary_and_shows_the_real_setup_command(client):
    body = client.get("/operations/").get_data(as_text=True)

    assert "La instancia est" in body
    assert 'flask --app "apate.web:create_app" create-user &lt;nombre&gt;' in body
    assert body.index('id="operator-input"') < body.index('class="authentication-notice"')


def test_set_operator_persists_across_requests(client):
    response = client.post("/operator", data={"operator": "Federico"}, follow_redirects=True)
    assert response.status_code == 200
    assert b"Operando como 'Federico'." in response.data or b"Operando como &#39;Federico&#39;." in response.data

    again = client.get("/operations/")
    assert b'value="Federico"' in again.data


def test_set_operator_redirects_to_next_url(client):
    response = client.post("/operator", data={"operator": "Federico", "next": "/operations/"}, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/operations/")


def test_clearing_operator_removes_it_from_session(client):
    client.post("/operator", data={"operator": "Federico"})
    response = client.post("/operator", data={"operator": ""}, follow_redirects=True)

    assert b"Nombre de operador limpiado." in response.data
    again = client.get("/operations/")
    assert b'value=""' in again.data


def test_set_operator_strips_whitespace(client):
    client.post("/operator", data={"operator": "  Federico  "})
    again = client.get("/operations/")
    assert b'value="Federico"' in again.data
