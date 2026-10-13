"""Tests de integracion web para el selector de MITRE ATT&CK (M12j) en
el formulario de creacion de operaciones -- ver
docs/analisis-engage-integral.md y apate.attack.

La "precarga desde grupo APT" se resuelve del lado del cliente (JS,
ver operations/form.html) -- estos tests no ejecutan JS, asi que
simulan exactamente lo que ese JS produce: marcar los checkboxes
`expected_ttps` con los `technique_ids` reales del grupo (via
apate.attack.get_group()) antes de postear, igual que haria un
navegador real despues de elegir el grupo del <select>."""

from apate.attack import get_group, list_groups, list_techniques
from apate.web._enum_labels import tactic_label


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba M12j",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


# -- formulario ------------------------------------------------------------


def test_new_operation_form_lists_technique_checkboxes_grouped_by_tactic(client):
    response = client.get("/operations/new")

    assert response.status_code == 200
    text = response.data.decode()
    for technique in list_techniques():
        assert f'value="{technique.id}"' in text
        assert technique.name in text
    # Agrupado por tactica: el nombre de la tactica aparece como
    # encabezado visible, no solo dentro de un atributo.
    tactics = {t.tactic for t in list_techniques()}
    for tactic in tactics:
        assert f">{tactic_label(tactic)}<" in text


def test_new_operation_form_lists_attack_groups_in_select(client):
    response = client.get("/operations/new")

    assert response.status_code == 200
    text = response.data.decode()
    assert 'id="attack_group_select"' in text
    for group in list_groups():
        assert f'value="{group.id}"' in text
        assert group.name in text


def test_new_operation_form_includes_notes_field(client):
    response = client.get("/operations/new")
    assert b'name="adversary_notes"' in response.data


def test_new_operation_form_no_longer_has_free_text_ttp_input(client):
    # M12j reemplaza el input de texto libre -- confirmar que
    # realmente desaparecio, no que coexiste con los checkboxes.
    response = client.get("/operations/new")
    assert b'type="text" id="expected_ttps"' not in response.data


# -- creacion: seleccion manual -------------------------------------------


def test_create_operation_with_manually_selected_techniques(client, app):
    operation_id = _create_operation(client, expected_ttps=["T1078", "T1566"])

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.adversary_profile.expected_ttps == ["T1078", "T1566"]


def test_create_operation_without_any_technique_checked(client, app):
    operation_id = _create_operation(client)

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.adversary_profile.expected_ttps == []


def test_create_operation_saves_notes(client, app):
    operation_id = _create_operation(client, adversary_notes="Perfil armado a mano, sin grupo APT.")

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.adversary_profile.notes == "Perfil armado a mano, sin grupo APT."


# -- creacion: precarga desde grupo APT (simulando el JS del cliente) ------


def test_create_operation_preloaded_from_apt_group_matches_group_techniques(client, app):
    group = get_group("G0007")
    assert group is not None

    operation_id = _create_operation(
        client,
        adversary_name=group.name,
        expected_ttps=group.technique_ids,
    )

    operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.adversary_profile.expected_ttps == group.technique_ids
    assert set(operation.adversary_profile.expected_ttps) == set(group.technique_ids)


def test_create_operation_preloaded_from_each_curated_group(client, app):
    for group in list_groups():
        operation_id = _create_operation(
            client,
            name=f"Operacion vs {group.name}",
            adversary_name=group.name,
            expected_ttps=group.technique_ids,
        )
        operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
        assert operation.adversary_profile.expected_ttps == group.technique_ids
