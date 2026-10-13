"""Tests de integracion web para "Reoperar" (M12g) -- cierra el ciclo
paso 7 -> paso 1 de la metodologia CTI-a-ciberengano
(docs/analisis-metodologia-cti.md, docs/analisis-engage-integral.md):
GET /operations/<id>/reoperate precarga el formulario de creacion a
partir del informe post-operacion de una operacion cerrada, pero NO
crea nada por si sola -- el operador confirma con el submit normal de
create_operation().

Sigue el mismo patron que tests/test_web_operations.py (helper
_create_operation/_create_closed_operation posteando al formulario
real, sin mockear nada) y tests/test_web_telemetry.py (_seed_event
para inyectar telemetria directo via TELEMETRY_COLLECTOR.handle_event(),
sin pasar por un EventBus/plugin real)."""

from apate.plugins import EventType, PluginEvent


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M12g",
        adversary_name="APT ficticio",
        adversary_motivation="espionaje",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046", "T1078"],
        target_assets="ERP, Active Directory",
        environment="isolated",
        narrative_name="Narrativa base",
        narrative_description="desc",
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


def _is_checked(text: str, ttp_id: str) -> bool:
    start = text.index(f'value="{ttp_id}"')
    tag_end = text.index(">", start)
    return "checked" in text[start:tag_end]


# -- Solo tiene sentido sobre una operacion CLOSED ---------------------------


def test_reoperate_flashes_error_for_non_closed_operation(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}/reoperate", follow_redirects=True)

    assert response.status_code == 200
    assert b"flash-error" in response.data
    assert b"solo se puede reoperar" in response.data.lower()
    # No renderizo el formulario de creacion precargado -- redirigio al detalle.
    assert b"Reoperar (M12g)" not in response.data


def test_reoperate_404_for_unknown_operation(client):
    response = client.get("/operations/no-existe/reoperate")
    assert response.status_code == 404


# -- Precarga: union de TTPs esperadas y observadas-no-esperadas -------------


def test_reoperate_prefills_union_of_expected_and_unexpected_ttps(client, app):
    # T1078/T1005/T1057 estan los tres en el catalogo curado de M12j
    # (apate.attack.list_techniques()) -- el selector de "TTPs
    # esperadas" solo dibuja un checkbox por tecnica del catalogo, asi
    # que un TTP fuera de el (aunque sea un valor valido de
    # AdversaryProfile.expected_ttps, sigue siendo list[str] libre) no
    # tiene forma de aparecer marcado en la UI.
    operation_id = _create_closed_operation(client, expected_ttps=["T1078", "T1005"])
    # T1057 no estaba en expected_ttps: informacion nueva real sobre el
    # adversario, observada mientras la operacion estaba activa.
    _seed_ttp_observed(app, operation_id, "T1057")
    _seed_ttp_observed(app, operation_id, "T1005")  # esta si coincide (matched), no deberia duplicarse

    response = client.get(f"/operations/{operation_id}/reoperate")

    assert response.status_code == 200
    text = response.data.decode()
    assert _is_checked(text, "T1078")
    assert _is_checked(text, "T1005")
    assert _is_checked(text, "T1057")


def test_reoperate_does_not_check_ttps_outside_the_union(client, app):
    operation_id = _create_closed_operation(client, expected_ttps=["T1078"])

    response = client.get(f"/operations/{operation_id}/reoperate")

    assert response.status_code == 200
    text = response.data.decode()
    assert _is_checked(text, "T1078")
    assert not _is_checked(text, "T1005")


# -- Precarga: target_assets y notas -----------------------------------------


def test_reoperate_prefills_target_assets(client):
    operation_id = _create_closed_operation(client, target_assets="ERP, Active Directory")

    response = client.get(f"/operations/{operation_id}/reoperate")

    assert response.status_code == 200
    assert b'value="ERP, Active Directory"' in response.data


def test_reoperate_prefills_notes_with_reference_to_origin_operation(client, app):
    operation_id = _create_closed_operation(client, name="Operacion Origen")

    response = client.get(f"/operations/{operation_id}/reoperate")

    assert response.status_code == 200
    text = response.data.decode()
    # Jinja autoescapa el apostrofe -- confirmamos el HTML real, no una
    # version relajada del texto esperado.
    assert f"Reoperada a partir de &#39;Operacion Origen&#39; (id: {operation_id})." in text


def test_reoperate_concatenates_reference_with_existing_notes(client, app):
    operation_id = _create_closed_operation(client, adversary_notes="Nota original del analista")

    response = client.get(f"/operations/{operation_id}/reoperate")

    assert response.status_code == 200
    text = response.data.decode()
    assert "Nota original del analista" in text
    assert "Reoperada a partir de" in text


# -- Boton "Reoperar" visible solo cuando la operacion esta cerrada ----------


def test_detail_page_shows_reoperate_button_only_when_closed(client):
    open_operation_id = _create_operation(client)
    response = client.get(f"/operations/{open_operation_id}")
    assert b'operations/reoperate' not in response.data

    closed_operation_id = _create_closed_operation(client)
    response = client.get(f"/operations/{closed_operation_id}")
    assert b'Reoperar</a>' in response.data


# -- Confirmar el formulario precargado crea una operacion nueva e independiente --


def test_confirming_prefilled_form_creates_new_independent_operation(client, app):
    origin_id = _create_closed_operation(
        client,
        name="Operacion Origen",
        expected_ttps=["T1078", "T1005"],
        target_assets="ERP, Active Directory",
    )
    _seed_ttp_observed(app, origin_id, "T1057")

    # Lo que el operador ve precargado en /reoperate...
    reoperate_response = client.get(f"/operations/{origin_id}/reoperate")
    text = reoperate_response.data.decode()
    assert _is_checked(text, "T1078") and _is_checked(text, "T1005") and _is_checked(text, "T1057")

    # ...es exactamente lo que confirma via el submit normal de create_operation().
    create_response = client.post(
        "/operations/new",
        data={
            "name": "Operacion Reoperada",
            "adversary_name": "APT ficticio",
            "adversary_skill_level": "intermediate",
            "expected_ttps": ["T1078", "T1005", "T1057"],
            "target_assets": "ERP, Active Directory",
            "environment": "isolated",
            "narrative_name": "Narrativa reoperada",
        },
        follow_redirects=False,
    )
    assert create_response.status_code == 302
    new_id = create_response.headers["Location"].rsplit("/", 1)[-1]

    repo = app.config["OPERATION_REPOSITORY"]
    origin = repo.get(origin_id)
    new_operation = repo.get(new_id)

    # Objeto nuevo e independiente, no una referencia a la operacion vieja.
    assert new_operation.id != origin.id
    assert new_operation.name == "Operacion Reoperada"
    assert sorted(new_operation.adversary_profile.expected_ttps) == ["T1005", "T1057", "T1078"]
    assert new_operation.adversary_profile.target_assets == ["ERP", "Active Directory"]

    # La operacion de origen no se toco.
    assert origin.status.value == "closed"
    assert sorted(origin.adversary_profile.expected_ttps) == ["T1005", "T1078"]
