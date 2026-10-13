"""Integración manual de bundles STIX con un webhook SIEM/SOAR."""

import json
from unittest.mock import Mock, patch


def _create_operation(client, **overrides):
    form = dict(
        name="Operacion SIEM/SOAR",
        adversary_name="APT ficticio",
        adversary_skill_level="intermediate",
        expected_ttps=["T1046"],
        environment="isolated",
        narrative_name="Narrativa base",
    )
    form.update(overrides)
    response = client.post("/operations/new", data=form, follow_redirects=False)
    assert response.status_code == 302
    return response.headers["Location"].rsplit("/", 1)[-1]


def _create_closed_operation(client, **overrides):
    operation_id = _create_operation(client, **overrides)
    client.post(f"/operations/{operation_id}/transition", data={"to": "closed"})
    return operation_id


def test_siem_soar_configuration_persists_url_without_rendering_token(client, app):
    response = client.post(
        "/health/configuration/siem-soar",
        data={"webhook_url": "https://siem.example/hooks/stix", "auth_token": "secret-never-render"},
        follow_redirects=True,
    )

    text = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "secret-never-render" not in text
    assert "apate-fernet:v1:" not in text
    assert "configurado (su valor no se muestra)" in text
    assert app.config["SIEM_SOAR_CONFIG_REPOSITORY"].load() == {
        "webhook_url": "https://siem.example/hooks/stix",
        "auth_token": "secret-never-render",
    }
    raw = (app.config["APATE_DATA_DIR"] / "siem_soar_config.json").read_text(encoding="utf-8")
    assert "https://siem.example/hooks/stix" not in raw
    assert "secret-never-render" not in raw


def test_closed_operation_sends_stix_bundle_with_bearer_token(client, app):
    operation_id = _create_closed_operation(client)
    app.config["SIEM_SOAR_CONFIG_REPOSITORY"].save("https://siem.example/hooks/stix", "token-123")
    response = Mock()
    response.raise_for_status.return_value = None

    with patch("apate.web.blueprints.operations.requests.post", return_value=response) as post:
        result = client.post(f"/operations/{operation_id}/report/send-siem-soar", follow_redirects=True)

    assert result.status_code == 200
    assert b"Bundle STIX 2.1 enviado a SIEM/SOAR." in result.data
    post.assert_called_once()
    args, kwargs = post.call_args
    assert args == ("https://siem.example/hooks/stix",)
    assert kwargs["headers"] == {
        "Content-Type": "application/stix+json",
        "Authorization": "Bearer token-123",
    }
    assert kwargs["timeout"] == 8.0
    assert json.loads(kwargs["data"])["type"] == "bundle"


def test_siem_soar_send_reports_real_http_failure(client, app):
    operation_id = _create_closed_operation(client)
    app.config["SIEM_SOAR_CONFIG_REPOSITORY"].save("https://siem.example/hooks/stix", "")

    with patch(
        "apate.web.blueprints.operations.requests.post",
        side_effect=__import__("requests").ConnectionError("inaccesible"),
    ):
        response = client.post(f"/operations/{operation_id}/report/send-siem-soar", follow_redirects=True)

    assert response.status_code == 200
    assert b"No se pudo enviar el bundle STIX a SIEM/SOAR." in response.data


def test_closed_operation_without_webhook_offers_configuration_instead_of_send(client):
    operation_id = _create_closed_operation(client)

    response = client.get(f"/operations/{operation_id}")

    siem_soar = b'<abbr title="gesti&oacute;n de informaci&oacute;n y eventos de seguridad / orquestaci&oacute;n, automatizaci&oacute;n y respuesta de seguridad">SIEM/SOAR</abbr>'
    assert b"Configurar webhook " + siem_soar in response.data
    assert b"Enviar a " + siem_soar not in response.data
