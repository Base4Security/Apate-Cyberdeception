"""Regresiones para las siglas que aparecen en superficies operativas.

Los identificadores tecnicos y valores enviados en formularios se mantienen
intactos; estas pruebas cubren solamente la ayuda visible para el operador.
"""

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement


def _operation() -> Operation:
    return Operation(
        name="Operación con siglas",
        adversary_profile=AdversaryProfile(name="APT de prueba", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa de prueba"),
    )


def test_operation_design_tab_keeps_roe_section_and_expands_the_term(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/operations/{operation.id}")

    assert response.status_code == 200
    assert b'data-tab="tab-design"' in response.data
    assert b'id="tab-roe"' in response.data
    assert b"Reglas de interacci" in response.data
    assert b">RoE <span" not in response.data
    assert b'<abbr title="T&aacute;cticas, t&eacute;cnicas y procedimientos">TTPs esperadas</abbr>' in response.data


def test_telemetry_explains_its_standard_security_terms(client, app):
    operation = _operation()
    app.config["OPERATION_REPOSITORY"].save(operation)

    response = client.get(f"/telemetry/{operation.id}")

    assert response.status_code == 200
    assert b'Indicadores de compromiso' in response.data
    assert b'Traffic Light Protocol' in response.data
    assert b'T&aacute;cticas, t&eacute;cnicas y procedimientos' in response.data
