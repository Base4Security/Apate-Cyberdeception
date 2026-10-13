"""Tests para `apate.plugins.canarytoken_client` (cliente HTTP para un
servidor Canarytokens self-hosted). Ver docstring del módulo para el
diseño completo y qué quedó verificado contra una instancia real."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from apate.plugins.canarytoken_client import (
    CanarytokenCreated,
    CanarytokenHit,
    create_token,
    delete_token,
    fetch_hits,
)
from apate.plugins.exceptions import CanarytokenAPIError


def _response(status_code: int, json_body: dict) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_body
    return response


# -- create_token(): forma real verificada contra una instancia real --------


def test_create_token_success_matches_real_verified_response_shape():
    """Forma real, verificada con curl contra una instancia local real
    (tipo 'dns') -- ver docstring del módulo."""

    real_response = {
        "token": "vo0s0u7t8odtlwsagbu9r367u",
        "hostname": "vo0s0u7t8odtlwsagbu9r367u.localhost",
        "token_url": "http://localhost/stuff/vo0s0u7t8odtlwsagbu9r367u/payments.js",
        "auth_token": "6a7d3dae3cdb86e35508f0c63b4c0fa5",
        "email": "soc@example.com",
        "webhook_url": "",
        "url_components": [["stuff"], ["payments.js"]],
        "error": None,
        "error_message": None,
        "Url": None,
        "token_type": "dns",
    }
    with patch("requests.post", return_value=_response(200, real_response)) as mock_post:
        created = create_token("http://localhost:8082/rootpath", token_type="dns", memo="m", email="soc@example.com")

    assert created == CanarytokenCreated(
        token="vo0s0u7t8odtlwsagbu9r367u",
        auth_token="6a7d3dae3cdb86e35508f0c63b4c0fa5",
        token_url="http://localhost/stuff/vo0s0u7t8odtlwsagbu9r367u/payments.js",
        hostname="vo0s0u7t8odtlwsagbu9r367u.localhost",
    )
    mock_post.assert_called_once()
    _, kwargs = mock_post.call_args
    assert kwargs["json"] == {"token_type": "dns", "memo": "m", "email": "soc@example.com"}


def test_create_token_never_sends_webhook_url():
    """Decisión de arquitectura (ver docstring del módulo): APATE nunca
    registra un webhook -- el cuerpo de /generate no debe traer esa
    clave en ningún caso."""

    with patch("requests.post", return_value=_response(200, {"token": "t", "auth_token": "a"})) as mock_post:
        create_token("http://x", token_type="dns", memo="m", email="e@example.com")

    assert "webhook_url" not in mock_post.call_args.kwargs["json"]


def test_create_token_merges_extra_fields_into_request_body():
    with patch("requests.post", return_value=_response(200, {"token": "t", "auth_token": "a"})) as mock_post:
        create_token(
            "http://x", token_type="fast_redirect", memo="m", email="e@example.com",
            extra_fields={"redirect_url": "https://example.com"},
        )

    assert mock_post.call_args.kwargs["json"]["redirect_url"] == "https://example.com"


def test_create_token_malformed_request_error_matches_real_response():
    """Forma real de un 400, verificada contra una instancia real
    (memo/email faltante)."""

    real_error = {
        "error": "1",
        "error_message": "Malformed request, invalid data supplied.",
        "url": "",
        "url_components": None,
        "token": "",
        "email": "",
        "hostname": "",
        "auth": "",
    }
    with patch("requests.post", return_value=_response(400, real_error)):
        with pytest.raises(CanarytokenAPIError, match="Malformed request"):
            create_token("http://x", token_type="dns", memo="", email="")


def test_create_token_missing_token_or_auth_in_success_response_raises():
    with patch("requests.post", return_value=_response(200, {"token": "t"})):  # sin auth_token
        with pytest.raises(CanarytokenAPIError):
            create_token("http://x", token_type="dns", memo="m", email="e@example.com")


def test_create_token_connection_error_wrapped():
    with patch("requests.post", side_effect=requests.ConnectionError("rechazado")):
        with pytest.raises(CanarytokenAPIError):
            create_token("http://x", token_type="dns", memo="m", email="e@example.com")


def test_create_token_non_json_response_raises():
    response = MagicMock()
    response.status_code = 200
    response.json.side_effect = ValueError("not json")
    with patch("requests.post", return_value=response):
        with pytest.raises(CanarytokenAPIError):
            create_token("http://x", token_type="dns", memo="m", email="e@example.com")


def test_create_token_strips_trailing_slash_from_base_url():
    with patch("requests.post", return_value=_response(200, {"token": "t", "auth_token": "a"})) as mock_post:
        create_token("http://x/root/", token_type="dns", memo="m", email="e@example.com")

    assert mock_post.call_args.args[0] == "http://x/root/generate"


# -- delete_token(): forma real verificada -----------------------------------


def test_delete_token_success_matches_real_verified_response():
    with patch("requests.post", return_value=_response(200, {"message": "success"})) as mock_post:
        delete_token("http://x", token="t", auth_token="a")

    assert mock_post.call_args.kwargs["json"] == {"token": "t", "auth": "a"}


def test_delete_token_non_200_raises():
    with patch("requests.post", return_value=_response(403, {"detail": "Token not found."})):
        with pytest.raises(CanarytokenAPIError):
            delete_token("http://x", token="t", auth_token="wrong")


def test_delete_token_connection_error_wrapped():
    with patch("requests.post", side_effect=requests.ConnectionError("rechazado")):
        with pytest.raises(CanarytokenAPIError):
            delete_token("http://x", token="t", auth_token="a")


# -- fetch_hits(): allowlist estructural, el hallazgo bloqueante ------------


def _real_history_response_with_secrets() -> dict:
    """Fiel a la forma real verificada con curl contra /history: el
    'canarydrop' completo, incluido su propio 'auth' en texto plano, y
    (según el tipo de token) los campos con secretos que ESTE test
    confirma que nunca llegan al resultado de fetch_hits()."""

    return {
        "canarydrop": {
            "auth": "6a7d3dae3cdb86e35508f0c63b4c0fa5",
            "aws_secret_access_key": "FAKEsecretAWSkeyvalue1234567890",
            "webdav_password": "FAKEwebdavpass",
            "slack_api_key": "xoxb-FAKE-slack-key",
            "crowdstrike_client_secret": "FAKEcrowdstrikesecret",
            "cc_number": "4111111111111111",
            "memo": "nota",
        },
        "history": {
            "token_type": "dns",
            "hits": [
                {
                    "time_of_hit": 1755780000.5,
                    "src_ip": "203.0.113.20",
                    "input_channel": "DNS",
                    "token_type": "dns",
                    "is_tor_relay": False,
                    "useragent": "",
                    "geo_info": {"country": "AR"},
                    # Un hit real puede traer campos no listados en el
                    # allowlist -- src_data puede incluir contenido no
                    # confiable (ej. de un token de tipo credit_card_v2).
                    "src_data": {"raw": "contenido no confiable arbitrario"},
                }
            ],
        },
        "google_api_key": "FAKE-google-key",
    }


def test_fetch_hits_never_leaks_any_secret_field():
    with patch("requests.get", return_value=_response(200, _real_history_response_with_secrets())):
        hits = fetch_hits("http://x", token="t", auth_token="a")

    assert len(hits) == 1
    hit = hits[0]
    hit_dump = repr(hit)
    for secret in (
        "6a7d3dae3cdb86e35508f0c63b4c0fa5",
        "FAKEsecretAWSkeyvalue1234567890",
        "FAKEwebdavpass",
        "xoxb-FAKE-slack-key",
        "FAKEcrowdstrikesecret",
        "4111111111111111",
        "FAKE-google-key",
        "contenido no confiable arbitrario",
    ):
        assert secret not in hit_dump


def test_fetch_hits_only_exposes_allowlisted_fields():
    """La allowlist es estructural (los campos que declara el
    dataclass), no una lista de exclusión -- confirmado enumerando los
    campos reales de CanarytokenHit."""

    import dataclasses

    field_names = {f.name for f in dataclasses.fields(CanarytokenHit)}
    assert field_names == {"time_of_hit", "source_ip", "input_channel", "token_type", "is_tor_relay", "useragent"}


def test_fetch_hits_maps_real_fields_correctly():
    with patch("requests.get", return_value=_response(200, _real_history_response_with_secrets())):
        hits = fetch_hits("http://x", token="t", auth_token="a")

    hit = hits[0]
    assert hit.time_of_hit == 1755780000.5
    assert hit.source_ip == "203.0.113.20"
    assert hit.input_channel == "DNS"
    assert hit.token_type == "dns"
    assert hit.is_tor_relay is False


def test_fetch_hits_sends_token_and_auth_as_query_params():
    with patch("requests.get", return_value=_response(200, {"history": {"hits": []}})) as mock_get:
        fetch_hits("http://x", token="t", auth_token="a")

    assert mock_get.call_args.kwargs["params"] == {"token": "t", "auth": "a"}


def test_fetch_hits_empty_history_returns_empty_list():
    with patch("requests.get", return_value=_response(200, {"history": {"hits": []}})):
        assert fetch_hits("http://x", token="t", auth_token="a") == []


def test_fetch_hits_403_deleted_token_raises():
    """Forma real verificada: consultar /history de un token ya
    borrado da 403 con {"detail": "Token not found..."}."""

    with patch("requests.get", return_value=_response(403, {"detail": "Token not found. Invalid `auth` and `token` pair."})):
        with pytest.raises(CanarytokenAPIError):
            fetch_hits("http://x", token="t", auth_token="a")


def test_fetch_hits_skips_non_dict_hit_entries():
    with patch("requests.get", return_value=_response(200, {"history": {"hits": ["no es un dict", None]}})):
        assert fetch_hits("http://x", token="t", auth_token="a") == []


def test_fetch_hits_connection_error_wrapped():
    with patch("requests.get", side_effect=requests.ConnectionError("rechazado")):
        with pytest.raises(CanarytokenAPIError):
            fetch_hits("http://x", token="t", auth_token="a")
