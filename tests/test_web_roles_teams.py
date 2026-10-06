"""Roles fijos y aislamiento de equipos de la Fase 06 comercial."""

import json
import re

from flask import session

from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.identity import IdentityRole
from apate.web.access import machine_scope_for_endpoint, required_role
from apate.web._sessions import marcar_inicio


_PASSWORD = "Clave-de-roles-prueba"


def _operation(name: str, team_id: str | None) -> Operation:
    return Operation(
        name=name,
        adversary_profile=AdversaryProfile(name="APT"),
        roe=RulesOfEngagement(),
        narrative=Narrative(name="N"),
        team_id=team_id,
    )


def _login_as(client, identity):
    with client.session_transaction() as saved:
        saved["identity_id"] = identity.id
        # Sella la sesion con los dos relojes de vencimiento: una sesion sin
        # sello se considera vencida a proposito (ver apate.web._sessions).
        marcar_inicio(saved)


def test_first_local_user_is_administrator_and_later_roles_require_team(app):
    provider = app.config["IDENTITY_PROVIDER"]

    first = provider.create("Administradora", _PASSWORD)
    operator = provider.create("Operadora", _PASSWORD, role=IdentityRole.OPERATION, team_id="azul")

    assert first.role is IdentityRole.ADMINISTRATION
    assert operator.role is IdentityRole.OPERATION
    assert operator.team_id == "azul"


def test_non_admin_roles_without_team_are_rejected(app):
    provider = app.config["IDENTITY_PROVIDER"]
    provider.create("Administradora", _PASSWORD)

    import pytest

    with pytest.raises(ValueError, match="requieren un equipo"):
        provider.create("Lectora", _PASSWORD, role=IdentityRole.READ)


def test_legacy_identity_record_loads_as_administrator_without_team(tmp_path):
    from apate.identity import LocalIdentityProvider
    from werkzeug.security import generate_password_hash

    path = tmp_path / "identities.json"
    path.write_text(
        json.dumps(
            {"identities": [{"id": "legacy", "display_name": "Antigua", "active": True, "password_hash": generate_password_hash(_PASSWORD)}]}
        ),
        encoding="utf-8",
    )

    identity = LocalIdentityProvider(path).get("legacy")
    assert identity is not None
    assert identity.role is IdentityRole.ADMINISTRATION
    assert identity.team_id is None


def test_legacy_operation_json_without_team_is_quarantined_from_teams(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    provider.create("Administradora", _PASSWORD)
    operator = provider.create("Operadora", _PASSWORD, role=IdentityRole.OPERATION, team_id="azul")
    legacy_data = _operation("Operación histórica", None).to_dict()
    legacy_data.pop("team_id")
    legacy = Operation.from_dict(json.loads(json.dumps(legacy_data)))
    app.config["OPERATION_REPOSITORY"].save(legacy)

    _login_as(client, operator)
    response = client.get("/operations/")

    assert legacy.team_id is None
    assert legacy.name.encode() not in response.data


def test_team_members_only_list_and_open_their_operations(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    provider.create("Administradora", _PASSWORD)
    alpha = provider.create("Alpha", _PASSWORD, role=IdentityRole.OPERATION, team_id="azul")
    beta = provider.create("Beta", _PASSWORD, role=IdentityRole.OPERATION, team_id="rojo")
    repo = app.config["OPERATION_REPOSITORY"]
    own = _operation("Operación azul", "azul")
    other = _operation("Operación roja", "rojo")
    legacy = _operation("Operación heredada", None)
    for operation in (own, other, legacy):
        repo.save(operation)

    _login_as(client, alpha)
    listed = client.get("/operations/")
    assert own.name.encode() in listed.data
    assert legacy.name.encode() not in listed.data
    assert other.name.encode() not in listed.data
    assert client.get(f"/operations/{other.id}").status_code == 404
    assert client.get(f"/telemetry/{other.id}").status_code == 404
    assert other.name.encode() not in client.get("/operations/portfolio").data
    assert other.name.encode() not in client.get("/operations/compare").data

    _login_as(client, beta)
    assert client.get(f"/operations/{own.id}").status_code == 404


def test_operation_created_by_team_member_is_assigned_to_its_team(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    provider.create("Administradora", _PASSWORD)
    operator = provider.create("Operadora", _PASSWORD, role=IdentityRole.OPERATION, team_id="azul")
    _login_as(client, operator)

    response = client.post(
        "/operations/new",
        data={
            "name": "Nueva azul",
            "adversary_name": "APT",
            "environment": "isolated",
            "narrative_name": "N",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]
    assert app.config["OPERATION_REPOSITORY"].get(operation_id).team_id == "azul"


def test_administration_assigns_team_and_the_change_is_audited(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    administrator = provider.create("Administradora", _PASSWORD)
    alpha = provider.create("Alpha", _PASSWORD, role=IdentityRole.OPERATION, team_id="azul")
    beta = provider.create("Beta", _PASSWORD, role=IdentityRole.OPERATION, team_id="rojo")
    operation = _operation("Operación a aislar", None)
    app.config["OPERATION_REPOSITORY"].save(operation)

    _login_as(client, administrator)
    detail = client.get(f"/operations/{operation.id}")
    response = client.post(f"/operations/{operation.id}/team", data={"team_id": "azul"})

    assert b"Equipo de la operaci" in detail.data
    assert b'value="azul"' in detail.data
    assert b'value="rojo"' in detail.data
    assert response.status_code == 302
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).team_id == "azul"
    action = app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation.id)[0]
    assert action.action == "assign_team"
    assert "sin equipo" in action.detail
    assert "azul" in action.detail

    _login_as(client, alpha)
    assert client.get(f"/operations/{operation.id}").status_code == 200
    _login_as(client, beta)
    assert client.get(f"/operations/{operation.id}").status_code == 404


def test_only_administration_can_assign_or_remove_an_operation_team(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    administrator = provider.create("Administradora", _PASSWORD)
    operator = provider.create("Operadora", _PASSWORD, role=IdentityRole.OPERATION, team_id="azul")
    reader = provider.create("Auditora", _PASSWORD, role=IdentityRole.READ, team_id="azul")
    operation = _operation("Operación azul", "azul")
    app.config["OPERATION_REPOSITORY"].save(operation)

    _login_as(client, operator)
    assert client.post(f"/operations/{operation.id}/team", data={"team_id": ""}).status_code == 403
    assert b"Equipo de la operaci" not in client.get(f"/operations/{operation.id}").data

    _login_as(client, reader)
    assert client.post(f"/operations/{operation.id}/team", data={"team_id": ""}).status_code == 403

    _login_as(client, administrator)
    response = client.post(f"/operations/{operation.id}/team", data={"team_id": ""})
    assert response.status_code == 302
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).team_id is None

    _login_as(client, reader)
    assert client.get(f"/operations/{operation.id}").status_code == 404

    _login_as(client, administrator)
    assert b"solo administraci" in client.get("/operations/").data


def test_team_assignment_rejects_an_unknown_team(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    administrator = provider.create("Administradora", _PASSWORD)
    provider.create("Alpha", _PASSWORD, role=IdentityRole.OPERATION, team_id="azul")
    operation = _operation("Operación sin equipo", None)
    app.config["OPERATION_REPOSITORY"].save(operation)
    _login_as(client, administrator)

    response = client.post(f"/operations/{operation.id}/team", data={"team_id": "inexistente"}, follow_redirects=True)

    assert b"no existe entre las identidades" in response.data
    assert app.config["OPERATION_REPOSITORY"].get(operation.id).team_id is None


def test_read_role_cannot_mutate_but_administration_can_configure(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    admin = provider.create("Administradora", _PASSWORD)
    reader = provider.create("Auditora", _PASSWORD, role=IdentityRole.READ, team_id="azul")

    _login_as(client, reader)
    denied = client.post("/operations/new", data={})
    assert denied.status_code == 403
    assert b"Nueva operaci" not in client.get("/operations/").data

    _login_as(client, admin)
    assert client.post("/health/configuration/siem-soar", data={}).status_code != 403


def test_siem_webhook_configuration_is_not_visible_to_read_role(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    provider.create("Administradora", _PASSWORD)
    reader = provider.create("Auditora", _PASSWORD, role=IdentityRole.READ, team_id="azul")
    _login_as(client, reader)

    assert client.get("/health/configuration/siem-soar").status_code == 403


def test_every_registered_route_is_classified(app):
    ignored = {"login", "logout", "set_operator", "static"}
    unclassified = sorted(
        f"{rule.endpoint} ({method})"
        for rule in app.url_map.iter_rules()
        for method in rule.methods & {"GET", "POST"}
        if rule.endpoint not in ignored and not rule.endpoint.startswith("api.")
        and required_role(rule.endpoint, method) is None
    )

    assert unclassified == []
    api_endpoints = {rule.endpoint for rule in app.url_map.iter_rules() if rule.endpoint.startswith("api.")}
    assert api_endpoints
    assert all(machine_scope_for_endpoint(endpoint, "refresh" if endpoint == "api.honeyuser_action" else None)
               for endpoint in api_endpoints)


def test_reader_is_denied_from_every_registered_mutating_route(app, client):
    provider = app.config["IDENTITY_PROVIDER"]
    provider.create("Administradora", _PASSWORD)
    reader = provider.create("Auditora", _PASSWORD, role=IdentityRole.READ, team_id="azul")
    _login_as(client, reader)

    def sample_path(rule: str) -> str:
        return re.sub(
            r"<(?:(?P<converter>[^:>]+):)?[^>]+>",
            lambda match: "0" if match.group("converter") == "int" else "inaccesible",
            rule,
        )

    # Las excepciones no son mutaciones de datos de operacion: iniciar y
    # cerrar sesion, la atribucion libre previa al login, los estaticos, y
    # el idioma de la interfaz -- que es una preferencia personal de quien
    # mira, del mismo orden que el tema o la densidad. `set_locale` solo
    # puede tocar el campo `locale` de la identidad de la propia sesion
    # (el id no viaja en el formulario) y solo con un valor de
    # SUPPORTED_LOCALES, asi que no abre ninguna escalada.
    protected = [
        rule
        for rule in app.url_map.iter_rules()
        if "POST" in rule.methods
        and rule.endpoint not in {"login", "logout", "set_operator", "set_locale", "static"}
    ]
    assert protected
    for rule in protected:
        response = client.post(sample_path(rule.rule))
        assert response.status_code == (401 if rule.endpoint.startswith("api.") else 403), rule.endpoint


def test_an_unclassified_route_is_denied_by_default(app, client):
    @app.get("/_route-sin-clasificar")
    def route_sin_clasificar():
        return "no debería verse"

    provider = app.config["IDENTITY_PROVIDER"]
    administrator = provider.create("Administradora", _PASSWORD)
    _login_as(client, administrator)

    assert client.get("/_route-sin-clasificar").status_code == 403


def test_operations_without_team_are_flagged_as_administration_only(app, client):
    """Una operación sin equipo queda en cuarentena hasta ser asignada."""

    provider = app.config["IDENTITY_PROVIDER"]
    administrador = provider.create("Admin de equipos", _PASSWORD)
    _login_as(client, administrador)

    app.config["OPERATION_REPOSITORY"].save(_operation("Heredada sin equipo", None))

    cuerpo = client.get("/operations/").data.decode()

    assert "solo administración" in cuerpo


def test_team_operations_are_not_flagged(app, client):
    """La marca es para el caso sin equipo: una operación con equipo asignado
    no debe llevarla, o el aviso se vuelve ruido y deja de leerse."""

    provider = app.config["IDENTITY_PROVIDER"]
    provider.create("Admin base", _PASSWORD)
    operadora = provider.create(
        "Operadora roja", _PASSWORD, role=IdentityRole.OPERATION.value, team_id="rojo"
    )
    _login_as(client, operadora)

    app.config["OPERATION_REPOSITORY"].save(_operation("Con equipo", "rojo"))

    cuerpo = client.get("/operations/").data.decode()

    assert "Con equipo" in cuerpo
    assert "solo administración" not in cuerpo
