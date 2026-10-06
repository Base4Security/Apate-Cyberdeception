"""Tests de integracion web para el tab "Preparacion" en
operations/detail.html -- las 8 actividades estrategicas de MITRE
Engage (Prepare/Understand) cruzadas contra los campos reales de la
operacion. La logica de cobertura en si ya esta cubierta en detalle,
sin HTTP, por tests/test_web_engage_preparation.py -- este archivo
confirma que la tabla real se renderiza con esos datos."""

import pytest

from apate.core import AdversaryProfile, ClosureCriteria, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.web import create_app


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion de prueba Preparacion",
        adversary_name="APT ficticio",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def _save(app, operation: Operation) -> Operation:
    app.config["OPERATION_REPOSITORY"].save(operation)
    return operation


def test_detail_page_has_preparation_section_inside_visible_review_tab(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    assert response.status_code == 200
    assert 'data-tab="tab-review"' in text
    assert 'id="tab-review"' in text
    assert 'id="tab-preparation"' in text


def test_preparation_tab_lists_all_eight_activities(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    for sac_id in ("SAC0001", "SAC0002", "SAC0003", "SAC0004", "SAC0005", "SAC0006", "SAC0009", "SAC0012"):
        assert sac_id in text


def test_threat_model_row_shows_no_field_equivalent_text_not_a_status_tag(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    assert "Sin campo equivalente" in text


def test_bare_operation_shows_not_covered_for_operational_objective(client):
    operation_id = _create_operation(client)

    response = client.get(f"/operations/{operation_id}")
    text = response.data.decode()

    row = text.split('mono">SAC0001<')[1].split("</tr>")[0]
    assert "Sin cubrir" in row


def test_incomplete_preparation_has_summary_and_actionable_links(client):
    operation_id = _create_operation(client)

    text = client.get(f"/operations/{operation_id}").data.decode()

    assert "Preparaci&oacute;n incompleta" in text
    assert 'href="#tab-preparation"' in text
    assert "Completar decisiones estratégicas" in text
    assert "Revisar perfil de adversario" in text


def test_detail_shows_relationship_chain_without_claiming_causality(client):
    operation_id = _create_operation(client)

    text = client.get(f"/operations/{operation_id}").data.decode()

    assert 'id="operation-relations"' in text
    for label in ("Escenarios", "Plugins", "Engage cubierto", "Efectos medidos"):
        assert label in text
    assert "no afirman causalidad" in text


def test_operation_with_objectives_shows_covered_for_operational_objective(client, app):
    from apate.core import StrategicDecisions, StrategicObjective

    operation = Operation(
        name="Operacion con objetivos",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
        strategic_decisions=StrategicDecisions(objectives=[StrategicObjective.EARLY_DETECTION]),
    )
    _save(app, operation)

    response = client.get(f"/operations/{operation.id}")
    text = response.data.decode()

    row = text.split('mono">SAC0001<')[1].split("</tr>")[0]
    assert "Cubierta" in row


def test_closed_operation_shows_covered_for_after_action_review(client, app):
    operation = Operation(
        name="Operacion cerrada",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    operation.mark_active()
    operation.close()
    _save(app, operation)

    response = client.get(f"/operations/{operation.id}")
    text = response.data.decode()

    row = text.split('mono">SAC0006<')[1].split("</tr>")[0]
    assert "Cubierta" in row


def test_gating_criteria_covered_when_end_date_set(client, app):
    from datetime import datetime, timedelta, timezone

    operation = Operation(
        name="Operacion con gating criteria",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
        closure_criteria=ClosureCriteria(end_date=datetime.now(timezone.utc) + timedelta(days=10)),
    )
    _save(app, operation)

    response = client.get(f"/operations/{operation.id}")
    text = response.data.decode()

    row = text.split('mono">SAC0005<')[1].split("</tr>")[0]
    assert "Cubierta" in row


# -- Persona Creation, camino completo con BUDA real montado ---------------


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'preparation-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


def _make_buda_narrative_with_profile(app) -> int:
    import datetime

    from BUDA.app import db as buda_db
    from BUDA.models import Narrative as BudaNarrative
    from BUDA.models import UserProfile as BudaUserProfile

    with app.app_context():
        narrative = BudaNarrative(
            title="t",
            objective="o",
            attacker_profile="a",
            deception_activities="d",
            end_date=datetime.date.today(),
            is_running=False,
            percentage_of_similarity=100,
        )
        buda_db.session.add(narrative)
        buda_db.session.flush()
        profile = BudaUserProfile(
            name="Maria", role="HR", behavior_pattern="", winrm_server="10.0.0.5", winrm_username="maria", winrm_password="x"
        )
        narrative.user_profiles.append(profile)
        buda_db.session.add(profile)
        buda_db.session.commit()
        return narrative.id


def test_persona_creation_covered_end_to_end_with_real_buda_profile(mounted_app, mounted_client):
    narrative_id = _make_buda_narrative_with_profile(mounted_app)
    operation = Operation(
        name="Operacion con persona",
        adversary_profile=AdversaryProfile(name="APT ficticio"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="Narrativa base"),
    )
    operation.bind_plugin(
        PluginBinding(plugin_id="buda-1", surface="identity", plugin_kind="buda", config={"narrative_id": narrative_id})
    )
    mounted_app.config["OPERATION_REPOSITORY"].save(operation)

    response = mounted_client.get(f"/operations/{operation.id}")
    text = response.data.decode()

    row = text.split('mono">SAC0002<')[1].split("</tr>")[0]
    assert "Cubierta" in row
    # La atribuci&oacute;n secundaria del proveedor puede existir en
    # Despliegue; la fila de Preparaci&oacute;n sigue siendo funci&oacute;n-primero.
    assert "BUDA" not in row
    assert "DOLOS-T" not in row
