import pytest

from apate.web import create_app
from apate.web.blueprints import health as health_module


@pytest.fixture
def mounted_client(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "APATE_DATA_DIR": tmp_path / "data",
            "APATE_RULES_PATH": tmp_path / "rules.yaml",
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'health-buda.db'}",
        }
    )
    return app.test_client()


def test_health_page_is_read_only_and_explains_status(client):
    text = client.get("/health/").get_data(as_text=True)
    assert "Salud y configuraci" in text
    assert "Docker CLI" in text and "Playground" in text
    assert "decoys de red" in text and "comportamiento simulado" in text
    assert "solo lectura" in text
    assert "APATE_MOUNT_EXTERNAL_TOOLS" in text


def test_health_is_linked_from_global_navigation(client):
    assert 'href="/health/"' in client.get("/operations/").get_data(as_text=True)


def test_health_has_executive_summary_and_semantic_timestamp(client):
    text = client.get("/health/").get_data(as_text=True)

    assert 'class="panel-grid health-summary" aria-label="Resumen de salud"' in text
    assert "7 preparadas" in text or "/7 preparadas" in text
    assert "Requieren atenci" in text
    assert "<time datetime=" in text
    assert text.count("health-card-") >= 5
    assert ">disponible</span>" in text or ">no disponible</span>" in text


def test_health_links_to_canonical_configuration_routes(client):
    text = client.get("/health/").get_data(as_text=True)
    assert 'href="/health/configuration/network-host-runtime"' in text
    assert 'href="/health/configuration/content-generation"' in text
    assert 'href="/health/configuration/threat-intelligence"' in text
    assert 'href="/tools/dolost/docker"' not in text
    assert 'href="/tools/buda/settings"' not in text


def test_docker_connection_test_uses_saved_configuration_without_applying_it(
    mounted_client, monkeypatch
):
    calls = {"check": [], "configure": []}
    stored = {"tcp": "tcp://10.0.0.5:2375"}
    monkeypatch.setattr(health_module._docker_manager, "get_current_client_config", lambda: stored)
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

    response = mounted_client.post(
        "/health/configuration/network-host-runtime/test", follow_redirects=True
    )

    assert response.status_code == 200
    assert calls == {"check": [stored], "configure": []}
    assert b"flash-success" in response.data


def test_docker_connection_test_adapts_historical_tls_configuration(mounted_client, monkeypatch):
    calls = []
    stored = {"tcp_ssl": {"host": "docker.local", "port": "2376"}}
    monkeypatch.setattr(health_module._docker_manager, "get_current_client_config", lambda: stored)
    monkeypatch.setattr(
        health_module._docker_manager,
        "check_client_configuration",
        lambda docker_client: (calls.append(docker_client), True)[1],
    )

    mounted_client.post("/health/configuration/network-host-runtime/test")

    assert calls == [{"ssl": True, **stored}]


def test_openai_diagnostic_checks_model_without_generating_content(mounted_client, monkeypatch):
    calls = []

    class FakeModels:
        def retrieve(self, model):
            calls.append(model)

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["api_key"] == "sk-write-only"
            self.models = FakeModels()

    monkeypatch.setattr(
        health_module,
        "_buda_load_llm_config",
        lambda: {"provider": "openai", "model_name": "gpt-test", "api_key": "sk-write-only"},
    )
    monkeypatch.setattr(health_module, "OpenAI", FakeClient)

    response = mounted_client.post(
        "/health/configuration/content-generation/test", follow_redirects=True
    )

    assert calls == ["gpt-test"]
    assert b"sk-write-only" not in response.data
    assert b"flash-success" in response.data


def test_lmstudio_diagnostic_uses_models_endpoint_without_posting(mounted_client, monkeypatch):
    calls = []

    class FakeResponse:
        def raise_for_status(self):
            return None

    monkeypatch.setattr(
        health_module,
        "_buda_load_llm_config",
        lambda: {
            "provider": "lmstudio",
            "model_name": "local-model",
            "lmstudio_url": "http://127.0.0.1:1234/v1/chat/completions",
        },
    )
    monkeypatch.setattr(
        health_module.requests,
        "get",
        lambda url, timeout: (calls.append((url, timeout)), FakeResponse())[1],
    )

    response = mounted_client.post(
        "/health/configuration/content-generation/test", follow_redirects=True
    )

    assert calls == [("http://127.0.0.1:1234/v1/models", 8.0)]
    assert b"flash-success" in response.data


def test_content_generation_page_never_returns_api_key(mounted_client, monkeypatch):
    monkeypatch.setattr(
        health_module,
        "_buda_load_llm_config",
        lambda: {
            "provider": "openai",
            "model_name": "gpt-test",
            "api_key": "sk-never-render",
            "lmstudio_url": "",
        },
    )
    text = mounted_client.get("/health/configuration/content-generation").get_data(as_text=True)
    assert "sk-never-render" not in text
    assert "apate-fernet:v1:" not in text
    assert "configurada (su valor no se muestra)" in text
    assert 'name="confirmation"' in text and "REINICIAR DATOS" in text


def test_virustotal_configuration_is_write_only(client, app):
    response = client.post(
        "/health/configuration/threat-intelligence",
        data={"api_key": "vt-never-render"},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "vt-never-render" not in text
    assert "apate-fernet:v1:" not in text
    assert "configurada (su valor no se muestra)" in text
    assert app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].load()["api_key"] == "vt-never-render"
    raw = (app.config["APATE_DATA_DIR"] / "virustotal_config.json").read_text(encoding="utf-8")
    assert "vt-never-render" not in raw


def test_blank_virustotal_key_preserves_existing_value(client, app):
    app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].save_api_key("vt-existing")

    client.post("/health/configuration/threat-intelligence", data={"api_key": ""})

    assert app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].load()["api_key"] == "vt-existing"
