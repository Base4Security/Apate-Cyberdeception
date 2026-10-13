"""Tests para las áreas canónicas de integración global.

Se mockean las acciones destructivas o dependientes de infraestructura
real (Docker, LLM, reset de base, parseo de EVTX) -- nunca Docker/
OpenAI/python-evtx reales. El CRUD de actividades de BUDA se ejercita
contra una base sqlite temporal real (mismo patron que
test_web_operations_panels.py), sin mockear el ORM."""

import io

import pytest

from BUDA.app import db as buda_db
from apate.web import create_app
from apate.web.blueprints import health as health_module


@pytest.fixture
def mounted_app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'buda-tools-test.db'}",
        }
    )


@pytest.fixture
def mounted_client(mounted_app):
    return mounted_app.test_client()


@pytest.fixture
def unmounted_client(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "APATE_MOUNT_EXTERNAL_TOOLS": False,
        }
    )
    return app.test_client()


# -- Nav --------------------------------------------------------------------


def _sidebar_navigation(response) -> str:
    text = response.get_data(as_text=True)
    return text.split('<nav id="sidebar-navigation">', 1)[1].split("</nav>", 1)[0]


def test_nav_removes_legacy_tools_sections_when_mounted(mounted_client):
    response = mounted_client.get("/operations/")
    assert response.status_code == 200
    nav = _sidebar_navigation(response)
    assert "Herramientas" not in nav
    assert 'href="/tools/' not in nav
    assert "Cat&aacute;logo de capacidades" in nav
    assert "Salud y configuraci&oacute;n" in nav


def test_nav_removes_legacy_tools_sections_when_not_mounted(unmounted_client):
    # La taxonomia del sidebar ya no depende del flag: muestra las areas
    # propias de APATE y nunca vuelve a crear categorias por proveedor.
    response = unmounted_client.get("/operations/")
    assert response.status_code == 200
    nav = _sidebar_navigation(response)
    assert "Herramientas" not in nav
    assert 'href="/tools/' not in nav
    assert "Cat&aacute;logo de capacidades" in nav
    assert "Salud y configuraci&oacute;n" in nav


def test_command_search_uses_canonical_configuration_and_capability_routes(mounted_client):
    response = mounted_client.get("/operations/")
    text = response.get_data(as_text=True)
    for route in (
        "/telemetry/live",
        "/operations/portfolio#portfolio-operational-metrics",
        "/capabilities/behavior-activities",
        "/capabilities/identity-profiles",
        "/capabilities/behavior-context",
        "/health/configuration/network-host-runtime",
        "/health/configuration/content-generation",
    ):
        assert f'href="{route}"' in text
    assert 'data-command-keywords="salud configuraci&oacute;n red host docker"' in text
    assert 'data-command-keywords="cat&aacute;logo capacidades identidad winrm"' in text


def test_canonical_areas_explain_unavailable_providers_when_not_mounted(unmounted_client):
    response = unmounted_client.get("/capabilities/behavior-activities")
    assert response.status_code == 200
    assert b"necesita los recursos de librer" in response.data
    assert unmounted_client.get("/capabilities/behavior-context").status_code == 200
    for route in [
        "/health/configuration/network-host-runtime",
        "/health/configuration/content-generation",
    ]:
        response = unmounted_client.get(route)
        assert response.status_code == 200
        assert b"integraci" in response.data and b"deshabilitada" in response.data


def test_canonical_pages_share_context_navigation(mounted_client):
    for route in ["/capabilities/behavior-activities", "/capabilities/identity-profiles"]:
        text = mounted_client.get(route, follow_redirects=True).get_data(as_text=True)
        assert 'class="tools-context-nav" aria-label="Secciones del catálogo"' in text
        assert 'aria-current="page"' in text
    for route in [
        "/health/configuration/network-host-runtime",
        "/health/configuration/content-generation",
    ]:
        text = mounted_client.get(route, follow_redirects=True).get_data(as_text=True)
        assert 'class="tools-context-nav" aria-label="Salud y configuración"' in text
        assert 'aria-current="page"' in text


def test_canonical_breadcrumbs_point_to_their_destination_area(mounted_client):
    cases = {
        "/telemetry/live": ('href="/telemetry/"', "Telemetr&iacute;a"),
        "/health/configuration/network-host-runtime": ('href="/health/"', "Salud y configuración"),
            "/capabilities/behavior-activities": ('href="/capabilities/"', "Catálogo de capacidades"),
    }
    for route, expected in cases.items():
        text = mounted_client.get(route, follow_redirects=True).get_data(as_text=True)
        breadcrumbs = text.split('class="breadcrumbs"', 1)[1].split("</nav>", 1)[0]
        assert all(value in breadcrumbs for value in expected)


def test_catalog_unifies_engines_profiles_and_activities(mounted_app, mounted_client):
    _create_user_profile(mounted_client)
    mounted_client.post(
        "/capabilities/behavior-activities",
        data={"activity_type": "Navegar intranet", "details": "Abrir SharePoint"},
    )

    text = mounted_client.get("/capabilities/").get_data(as_text=True)
    assert "Navegar intranet" in text
    assert "alice" in text
    assert "Motor" in text and "Perfil" in text and "Actividad" in text
    assert "Identidad / comportamiento" in text
    # El proveedor de lo nativo se muestra con el nombre del producto, pero su
    # valor sigue siendo "APATE": viaja en la URL del filtro y en las vistas
    # guardadas del operador (ver _enum_labels.provider_label, fase 4 del
    # renombre). Se verifican las dos mitades, no solo el texto.
    assert "Apate" in text
    assert 'value="APATE"' in text
    assert "Usar en una operaci" in text or "Creá una operaci" in text


def test_catalog_filters_by_type_provider_and_availability(mounted_app, mounted_client):
    _create_user_profile(mounted_client)
    text = mounted_client.get(
        "/capabilities/?type=perfil&provider=APATE&availability=available"
    ).get_data(as_text=True)

    assert "alice" in text
    assert "Mock honeypot" not in text
    assert "Actividad" not in text.split("<tbody>", 1)[1].split("</tbody>", 1)[0]


def test_use_capability_only_redirects_to_operation_context(mounted_app, mounted_client):
    create_response = mounted_client.post(
        "/operations/new",
        data={
            "name": "Operación destino",
            "adversary_name": "APT ficticio",
            "narrative_name": "Narrativa base",
        },
    )
    operation_id = create_response.headers["Location"].rsplit("/", 1)[-1]

    response = mounted_client.get(
        "/capabilities/use",
        query_string={
            "operation_id": operation_id,
            "resource_type": "motor",
            "resource_id": "buda",
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith(
        f"/operations/{operation_id}?catalog_kind=buda#tab-plugins"
    )
    operation = mounted_app.config["OPERATION_REPOSITORY"].get(operation_id)
    assert operation.plugins == []

    detail = mounted_client.get(response.headers["Location"]).get_data(as_text=True)
    assert "Nada fue aplicado autom" in detail
    assert '<option value="buda" data-surface="Identidad / comportamiento" selected>' in detail


# -- DOLOS-T: actividad en vivo -----------------------------------------


def test_live_selector_keeps_activity_scoped_by_operation(mounted_client):
    text = mounted_client.get("/telemetry/live").get_data(as_text=True)
    assert "La telemetr&iacute;a se organiza por operaci&oacute;n" in text
    assert "/tools/dolost/activity" not in text


# -- DOLOS-T: config de Docker --------------------------------------------


@pytest.fixture
def dolost_docker_calls(monkeypatch):
    calls = {"check": [], "configure": [], "check_connection": []}
    monkeypatch.setattr(
        health_module._docker_manager,
        "check_client_configuration",
        lambda docker_client: (calls["check"].append(docker_client), True)[1],
    )
    monkeypatch.setattr(
        health_module._docker_manager,
        "configure_client",
        lambda docker_client: calls["configure"].append(docker_client),
    )
    monkeypatch.setattr(
        health_module._docker_manager, "check_connection", lambda: calls["check_connection"].append(True)
    )
    monkeypatch.setattr(health_module._docker_manager, "get_current_client_config", lambda: {})
    return calls


def test_dolost_docker_config_page_renders(mounted_client, dolost_docker_calls):
    response = mounted_client.get("/health/configuration/network-host-runtime")
    assert response.status_code == 200
    assert b"Docker" in response.data


def test_dolost_docker_uses_progressive_mode_panels(mounted_client, dolost_docker_calls):
    text = mounted_client.get("/health/configuration/network-host-runtime").get_data(as_text=True)

    assert text.count('class="docker-mode-fields" hidden') == 3
    assert "apateToggleDockerFields" in text
    assert "Material sensible" in text


def test_dolost_docker_config_env_mode(mounted_client, dolost_docker_calls):
    response = mounted_client.post("/health/configuration/network-host-runtime", data={"type": "env"}, follow_redirects=True)
    assert response.status_code == 200
    assert dolost_docker_calls["check"] == [{"from_env": True}]
    assert dolost_docker_calls["configure"] == [{"from_env": True}]
    assert len(dolost_docker_calls["check_connection"]) == 1
    assert b"flash-success" in response.data


def test_dolost_docker_config_tcp_mode(mounted_client, dolost_docker_calls):
    response = mounted_client.post(
        "/health/configuration/network-host-runtime", data={"type": "tcp", "host": "10.0.0.5", "port": "2375"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert dolost_docker_calls["check"] == [{"tcp": "tcp://10.0.0.5:2375"}]


def test_dolost_docker_config_socket_mode(mounted_client, dolost_docker_calls):
    response = mounted_client.post(
        "/health/configuration/network-host-runtime", data={"type": "socket", "socketPath": "unix:///var/run/docker.sock"}, follow_redirects=True
    )
    assert response.status_code == 200
    assert dolost_docker_calls["check"] == [{"socket": "unix:///var/run/docker.sock"}]


def test_dolost_docker_config_tcp_ssl_mode_adds_vendor_ssl_marker(mounted_app, mounted_client, dolost_docker_calls, monkeypatch, tmp_path):
    monkeypatch.setattr(health_module._DolostContext, "CONFIG_FOLDER", str(tmp_path / "docker_client_config"))

    data = {
        "type": "tcp_ssl",
        "host": "10.0.0.9",
        "port": "2376",
        "sslCert": (io.BytesIO(b"cert content"), "cert.pem"),
        "sslKey": (io.BytesIO(b"key content"), "key.pem"),
        "sslCa": (io.BytesIO(b"ca content"), "ca.pem"),
    }
    response = mounted_client.post(
        "/health/configuration/network-host-runtime", data=data, content_type="multipart/form-data", follow_redirects=True
    )
    assert response.status_code == 200
    assert len(dolost_docker_calls["check"]) == 1
    submitted = dolost_docker_calls["check"][0]
    assert set(submitted.keys()) == {"ssl", "tcp_ssl"}
    assert submitted["ssl"] is True
    assert submitted["tcp_ssl"]["host"] == "10.0.0.9"
    assert submitted["tcp_ssl"]["port"] == "2376"


def test_dolost_docker_config_unknown_type_flashes_error_without_calling_docker(mounted_client, dolost_docker_calls):
    response = mounted_client.post("/health/configuration/network-host-runtime", data={"type": "bogus"}, follow_redirects=True)
    assert b"flash-error" in response.data
    assert dolost_docker_calls["check"] == []


# -- BUDA: settings -----------------------------------------------------


@pytest.fixture
def buda_settings_calls(monkeypatch):
    calls = {"save": [], "recreate": []}
    monkeypatch.setattr(health_module, "_buda_load_llm_config", lambda: {})
    monkeypatch.setattr(
        health_module,
        "_buda_save_llm_config",
        lambda config: (calls["save"].append(config), {"message": "Settings updated successfully"})[1],
    )
    monkeypatch.setattr(
        health_module,
        "_buda_recreate_database",
        lambda: (calls["recreate"].append(True), {"message": "Database reset successfully"})[1],
    )
    return calls


def test_buda_settings_page_renders_without_leaking_missing_api_key(mounted_client, buda_settings_calls):
    response = mounted_client.get("/health/configuration/content-generation")
    assert response.status_code == 200
    assert b"no configurada" in response.data


def test_buda_settings_save_calls_save_llm_config(mounted_client, buda_settings_calls):
    response = mounted_client.post(
        "/health/configuration/content-generation",
        data={"provider": "openai", "model_name": "gpt-4o-mini", "api_key": "sk-secret", "lmstudio_url": ""},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert buda_settings_calls["save"] == [
        {"provider": "openai", "model_name": "gpt-4o-mini", "api_key": "sk-secret", "lmstudio_url": ""}
    ]
    assert b"sk-secret" not in response.data


def test_buda_settings_save_with_blank_api_key_keeps_existing_value(mounted_client, monkeypatch):
    calls = {"save": []}
    monkeypatch.setattr(health_module, "_buda_load_llm_config", lambda: {"api_key": "sk-already-configured"})
    monkeypatch.setattr(
        health_module,
        "_buda_save_llm_config",
        lambda config: (calls["save"].append(config), {"message": "ok"})[1],
    )

    response = mounted_client.post(
        "/health/configuration/content-generation",
        data={"provider": "openai", "model_name": "gpt-4o-mini", "api_key": "", "lmstudio_url": ""},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert calls["save"][0]["api_key"] == "sk-already-configured"


def test_buda_settings_reset_calls_recreate_database(mounted_client, buda_settings_calls):
    response = mounted_client.post(
        "/health/configuration/behavior-data/reset",
        data={"confirmation": "REINICIAR DATOS"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert buda_settings_calls["recreate"] == [True]
    assert b"flash-success" in response.data


def test_buda_settings_reset_rejects_missing_confirmation(mounted_client, buda_settings_calls):
    response = mounted_client.post("/health/configuration/behavior-data/reset", follow_redirects=True)
    assert response.status_code == 200
    assert buda_settings_calls["recreate"] == []
    assert b"flash-error" in response.data


def test_portfolio_metrics_do_not_render_legacy_buda_aggregates(mounted_client):
    text = mounted_client.get("/operations/portfolio").get_data(as_text=True)
    assert "M&eacute;tricas operacionales" in text
    assert "Actividades por narrativa" not in text
    assert "Narrativas por perfil" not in text


# -- BUDA: catalogo de actividades -----------------------------------------


def test_buda_activities_page_renders_empty(mounted_client):
    response = mounted_client.get("/capabilities/behavior-activities")
    assert response.status_code == 200
    assert b"Sin tipos de actividad" in response.data


def test_buda_catalogs_use_split_workspaces_and_keep_ai_assisted(mounted_client):
    activities = mounted_client.get("/capabilities/behavior-activities").get_data(as_text=True)
    profiles = mounted_client.get("/capabilities/identity-profiles").get_data(as_text=True)

    assert 'class="tools-workspace"' in activities
    assert 'class="tools-workspace"' in profiles
    assert "La IA solo propone un borrador" in activities
    assert 'role="status" aria-live="polite"' in activities


def test_activity_ai_suggestion_requires_explicit_copy_and_separate_save(mounted_client):
    text = mounted_client.get("/capabilities/behavior-activities").get_data(as_text=True)

    assert 'id="buda-suggestion"' in text
    assert "generatedSuggestion = JSON.parse(result.message)" in text
    assert "buda-apply-suggestion" in text
    apply_index = text.index("buda-apply-suggestion').addEventListener")
    assert text.index("typeInput.value = generatedSuggestion.activity_type", apply_index) > apply_index
    assert 'action="/capabilities/behavior-activities"' in text


def test_buda_activities_create_persists_to_real_db(mounted_app, mounted_client):
    response = mounted_client.post(
        "/capabilities/behavior-activities",
        data={"activity_type": "Navegar intranet", "details": "Abrir SharePoint interno"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Navegar intranet" in response.data

    with mounted_app.app_context():
        from BUDA.models import Activity as BudaActivity

        activities = BudaActivity.query.all()
        assert len(activities) == 1
        assert activities[0].activity_type == "Navegar intranet"


def test_buda_activities_page_shows_assigned_profiles_as_tags(mounted_app, mounted_client):
    # Pulido visual: la columna "Perfiles" de "Tipos existentes" pasa de
    # texto separado por comas a .tag-list/.tag (mismo patron que el
    # resto de listas cortas desde M13).
    profile_response = _create_user_profile(mounted_client)
    assert profile_response.status_code == 200
    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile_id = BudaUserProfile.query.first().id

    response = mounted_client.post(
        "/capabilities/behavior-activities",
        data={"activity_type": "Navegar intranet", "details": "d", "user_profiles": [str(profile_id)]},
        follow_redirects=True,
    )
    text = response.data.decode()

    assert response.status_code == 200
    assert '<span class="tag-list">' in text
    assert '<span class="tag">alice</span>' in text


def test_buda_activities_edit_updates_existing_row(mounted_app, mounted_client):
    mounted_client.post("/capabilities/behavior-activities", data={"activity_type": "Original", "details": "d"})
    with mounted_app.app_context():
        from BUDA.models import Activity as BudaActivity

        activity_id = BudaActivity.query.first().id

    response = mounted_client.post(
        f"/capabilities/behavior-activities/{activity_id}/edit",
        data={"activity_type": "Editado", "details": "d2"},
        follow_redirects=True,
    )
    assert response.status_code == 200

    with mounted_app.app_context():
        from BUDA.models import Activity as BudaActivity

        assert buda_db.session.get(BudaActivity, activity_id).activity_type == "Editado"


def test_buda_activities_delete_removes_row(mounted_app, mounted_client):
    mounted_client.post("/capabilities/behavior-activities", data={"activity_type": "A borrar", "details": ""})
    with mounted_app.app_context():
        from BUDA.models import Activity as BudaActivity

        activity_id = BudaActivity.query.first().id

    response = mounted_client.post(f"/capabilities/behavior-activities/{activity_id}/delete", follow_redirects=True)
    assert response.status_code == 200

    with mounted_app.app_context():
        from BUDA.models import Activity as BudaActivity

        assert buda_db.session.get(BudaActivity, activity_id) is None


def test_buda_activities_edit_unknown_id_404(mounted_client):
    response = mounted_client.post("/capabilities/behavior-activities/999999/edit", data={"activity_type": "x"})
    assert response.status_code == 404


# -- BUDA: generacion de actividad asistida por LLM (M14e) -----------------
#
# Hasta M14e, buda_activities.html llamaba a /buda/ai/generate/
# activitytype (ai_bp, montado por mount_buda()) via fetch() del lado
# del cliente. Con ai_bp retirado, la ruta canónica de Catálogo llama
# directo a BUDA.routes.ai_integration.generate_activity() -- estos
# tests ejercitan esa ruta nativa de punta a punta (perfil real en la
# base sqlite temporal, get_llm_response() mockeado, sin red real).


def test_buda_activities_generate_returns_parsed_fields(mounted_app, mounted_client, monkeypatch):
    from BUDA.app import db as buda_db
    from BUDA.models import UserProfile as BudaUserProfile
    from BUDA.routes import ai_integration

    with mounted_app.app_context():
        profile = BudaUserProfile(
            name="alice",
            role="Analyst",
            behavior_pattern="normal office hours",
            winrm_server="10.0.0.5",
            winrm_username="svc_alice",
            winrm_password="pw",
        )
        buda_db.session.add(profile)
        buda_db.session.commit()
        profile_id = profile.id

    monkeypatch.setattr(
        ai_integration,
        "get_llm_response",
        lambda messages: '{"activity_type": "Navegar intranet", "details": "Abrir SharePoint"}',
    )

    response = mounted_client.post(
        "/capabilities/behavior-activities/generate",
        json={"user_profile_id": profile_id, "activity_type": "", "details": ""},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["message"] == '{"activity_type": "Navegar intranet", "details": "Abrir SharePoint"}'


def test_buda_activities_generate_without_user_profile_id_returns_400(mounted_client):
    response = mounted_client.post("/capabilities/behavior-activities/generate", json={})
    assert response.status_code == 400


def test_buda_activities_generate_unknown_profile_returns_404(mounted_client):
    response = mounted_client.post(
        "/capabilities/behavior-activities/generate", json={"user_profile_id": 999999}
    )
    assert response.status_code == 404


def test_buda_activities_generate_returns_503_when_not_mounted(unmounted_client):
    response = unmounted_client.post("/capabilities/behavior-activities/generate", json={"user_profile_id": 1})
    assert response.status_code == 503


# -- BUDA: perfiles de usuario (WinRM) -- M14d, gap mas grande de M14 ------

_SECRET_PASSWORD = "S3cr3t-WinRM-Passw0rd!"


def _create_user_profile(client, **overrides):
    data = dict(
        name="alice",
        role="Analyst",
        behavior_pattern="normal office hours",
        winrm_server="10.0.0.5",
        winrm_username="svc_alice",
        winrm_password=_SECRET_PASSWORD,
    )
    data.update(overrides)
    return client.post("/capabilities/identity-profiles", data=data, follow_redirects=True)


def test_buda_user_profiles_page_renders_empty(mounted_client):
    response = mounted_client.get("/capabilities/identity-profiles")
    assert response.status_code == 200
    assert b"Sin perfiles de usuario todav" in response.data


def test_buda_user_profiles_create_persists_to_real_db(mounted_app, mounted_client):
    response = _create_user_profile(mounted_client)
    assert response.status_code == 200
    assert b"alice" in response.data

    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profiles = BudaUserProfile.query.all()
        assert len(profiles) == 1
        assert profiles[0].name == "alice"
        assert profiles[0].winrm_username == "svc_alice"
        assert profiles[0].winrm_password == _SECRET_PASSWORD


def test_buda_user_profiles_create_without_password_is_rejected(mounted_app, mounted_client):
    response = _create_user_profile(mounted_client, winrm_password="")

    assert response.status_code == 200
    assert b"flash-error" in response.data

    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        assert BudaUserProfile.query.count() == 0


def test_buda_user_profiles_edit_updates_fields_and_can_change_password(mounted_app, mounted_client):
    _create_user_profile(mounted_client)
    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile_id = BudaUserProfile.query.first().id

    new_password = "another-secret-entirely"
    response = mounted_client.post(
        f"/capabilities/identity-profiles/{profile_id}/edit",
        data={
            "name": "alice-renamed",
            "role": "Senior Analyst",
            "behavior_pattern": "night shift",
            "winrm_server": "10.0.0.9",
            "winrm_username": "svc_alice2",
            "winrm_password": new_password,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        reloaded = buda_db.session.get(BudaUserProfile, profile_id)
        assert reloaded.name == "alice-renamed"
        assert reloaded.winrm_server == "10.0.0.9"
        assert reloaded.winrm_username == "svc_alice2"
        assert reloaded.winrm_password == new_password


def test_buda_user_profiles_edit_blank_password_keeps_existing_one(mounted_app, mounted_client):
    _create_user_profile(mounted_client)
    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile_id = BudaUserProfile.query.first().id

    response = mounted_client.post(
        f"/capabilities/identity-profiles/{profile_id}/edit",
        data={
            "name": "alice",
            "role": "Analyst",
            "behavior_pattern": "normal office hours",
            "winrm_server": "10.0.0.5",
            "winrm_username": "svc_alice",
            "winrm_password": "",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        assert buda_db.session.get(BudaUserProfile, profile_id).winrm_password == _SECRET_PASSWORD


def test_buda_user_profiles_edit_blank_credentials_keep_both_existing_values(
    mounted_app, mounted_client
):
    _create_user_profile(mounted_client)
    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile_id = BudaUserProfile.query.first().id

    response = mounted_client.post(
        f"/capabilities/identity-profiles/{profile_id}/edit",
        data={
            "name": "alice",
            "role": "Analyst",
            "behavior_pattern": "normal office hours",
            "winrm_server": "10.0.0.5",
            "winrm_username": "",
            "winrm_password": "",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile = buda_db.session.get(BudaUserProfile, profile_id)
        assert profile.winrm_username == "svc_alice"
        assert profile.winrm_password == _SECRET_PASSWORD


def test_buda_user_profiles_delete_removes_row(mounted_app, mounted_client):
    _create_user_profile(mounted_client)
    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile_id = BudaUserProfile.query.first().id

    response = mounted_client.post(f"/capabilities/identity-profiles/{profile_id}/delete", follow_redirects=True)
    assert response.status_code == 200

    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        assert buda_db.session.get(BudaUserProfile, profile_id) is None


def test_buda_user_profiles_edit_unknown_id_404(mounted_client):
    response = mounted_client.post("/capabilities/identity-profiles/999999/edit", data={"name": "x"})
    assert response.status_code == 404


# -- Regresion explicita: la contraseña WinRM nunca viaja al cliente --------


def test_buda_user_profiles_password_never_appears_in_create_response(mounted_client):
    response = _create_user_profile(mounted_client)
    assert _SECRET_PASSWORD.encode() not in response.data


def test_buda_user_profiles_password_never_appears_in_list_page(mounted_app, mounted_client):
    _create_user_profile(mounted_client)
    response = mounted_client.get("/capabilities/identity-profiles")
    assert response.status_code == 200
    assert _SECRET_PASSWORD.encode() not in response.data


def test_buda_user_profiles_password_never_appears_in_edit_page(mounted_app, mounted_client):
    _create_user_profile(mounted_client)
    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile_id = BudaUserProfile.query.first().id

    response = mounted_client.get(f"/capabilities/identity-profiles/{profile_id}/edit")
    assert response.status_code == 200
    assert _SECRET_PASSWORD.encode() not in response.data


def test_buda_user_profiles_username_never_appears_in_list_or_edit_html(
    mounted_app, mounted_client
):
    secret_username = "USUARIO-WINRM-NO-RETORNABLE"
    _create_user_profile(mounted_client, winrm_username=secret_username)
    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile_id = BudaUserProfile.query.first().id

    list_response = mounted_client.get("/capabilities/identity-profiles")
    edit_response = mounted_client.get(f"/capabilities/identity-profiles/{profile_id}/edit")
    assert secret_username.encode() not in list_response.data
    assert secret_username.encode() not in edit_response.data


def test_buda_user_profiles_password_never_appears_after_edit_response(mounted_app, mounted_client):
    _create_user_profile(mounted_client)
    with mounted_app.app_context():
        from BUDA.models import UserProfile as BudaUserProfile

        profile_id = BudaUserProfile.query.first().id

    response = mounted_client.post(
        f"/capabilities/identity-profiles/{profile_id}/edit",
        data={
            "name": "alice",
            "role": "Analyst",
            "winrm_server": "10.0.0.5",
            "winrm_username": "svc_alice",
            "winrm_password": "brand-new-secret-value",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"brand-new-secret-value" not in response.data
    assert _SECRET_PASSWORD.encode() not in response.data


# -- BUDA: contexto UEBA ---------------------------------------------------


def test_buda_context_page_renders_empty_context(mounted_client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    response = mounted_client.get("/capabilities/behavior-context")
    assert response.status_code == 200
    assert b"Todav" in response.data and b"no hay fuentes" in response.data


def test_buda_context_upload_preserves_post_and_creates_pending_candidate(mounted_app, mounted_client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    from apate.web import _behavior_context as context_service
    from apate.web.blueprints import plugins as plugins_module

    calls = {"extract": []}
    fake_extracted = {"usernames": ["leonardo"]}
    monkeypatch.setattr(plugins_module, "count_evtx_records", lambda _path: 2)
    monkeypatch.setattr(context_service, "_extract_ueba_from_evtx", lambda path: (calls["extract"].append(path), fake_extracted)[1])

    response = mounted_client.post(
        "/capabilities/behavior-context/upload",
        data={"file": (io.BytesIO(b"fake evtx bytes"), "audit.evtx")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    # Response streaming (stream_with_context): el generador solo
    # corre al consumir el body -- forzarlo antes de mirar los mocks.
    body = response.get_data()

    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    assert len(calls["extract"]) == 1
    assert b"records:2" in body and b"candidate:" in body
    sources = list(mounted_app.config["BEHAVIOR_CONTEXT_REPOSITORY"].list())
    assert len(sources) == 1
    assert sources[0].status.value == "pending"


def test_buda_context_upload_without_file_flashes_error(mounted_client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    response = mounted_client.post("/capabilities/behavior-context/upload", data={}, follow_redirects=True)
    assert b"flash-error" in response.data


def test_provider_label_is_cosmetic_and_the_filter_value_still_works(mounted_client):
    """El renombre del producto no puede romper un filtro ni un enlace.

    El renombre separo etiqueta de valor justo para esto: `provider=APATE` viaja en URLs y en las vistas de
    filtros que el operador guarda en su navegador. Si alguna vez se traduce el
    valor y no solo el texto, este test lo detecta.
    """

    todos = mounted_client.get("/capabilities/").get_data(as_text=True)
    nativas = mounted_client.get("/capabilities/?provider=APATE").get_data(as_text=True)
    terceros = mounted_client.get("/capabilities/?provider=Tercero").get_data(as_text=True)

    def filas(html: str) -> int:
        cuerpo = html.split("<tbody>", 1)[1].split("</tbody>", 1)[0]
        return cuerpo.count("<tr")

    assert filas(nativas) and filas(terceros), "El filtro tiene que devolver filas reales."
    assert filas(nativas) + filas(terceros) == filas(todos), "El filtro dejo de discriminar."
    assert "Apate" in nativas
    assert "APATE</td>" not in nativas, "El valor crudo no deberia mostrarse como texto."
