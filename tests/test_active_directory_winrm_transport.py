from __future__ import annotations

import base64
import json
import re
import sys
from types import SimpleNamespace

import pytest

from apate.deployment import (
    DeploymentExecutionError,
    DeploymentTarget,
    DeploymentValidationError,
    WinRMActiveDirectoryTransport,
)


def _target(address="dc.example.test", **config):
    return DeploymentTarget(
        name="AD",
        connector_kind="active-directory-honeyuser",
        address=address,
        credential_ref="secret://ad/admin",
        config=config,
    )


def _response(payload, *, status=0, stderr=b""):
    return SimpleNamespace(
        status_code=status,
        std_out=json.dumps(payload).encode("utf-8") if payload is not None else b"",
        std_err=stderr,
    )


def test_winrm_uses_https_and_keeps_both_passwords_out_of_the_script(monkeypatch):
    calls = []
    user = {
        "sid": "S-1-5-21-100",
        "distinguished_name": "CN=Laura,OU=Deception,DC=example,DC=test",
        "sam_account_name": "laura.fernandez",
        "user_principal_name": "laura.fernandez@example.test",
        "description": "marker",
        "enabled": True,
    }

    class Session:
        def __init__(self, endpoint, **kwargs):
            calls.append((endpoint, kwargs))

        def run_ps(self, script):
            calls.append(script)
            return _response(user)

    monkeypatch.setitem(sys.modules, "winrm", SimpleNamespace(Session=Session))
    transport = WinRMActiveDirectoryTransport()
    created = transport.create_or_update_user(
        _target(),
        {"username": "DOMAIN\\svc-apate", "password": "AdministrativeSecret!"},
        {
            "sam_account_name": "laura.fernandez",
            "display_name": "Laura Fernández",
            "user_principal_name": "laura.fernandez@example.test",
            "ou_dn": "OU=Deception,DC=example,DC=test",
            "management_marker": "marker",
            "given_name": "Laura",
            "surname": "Fernández",
        },
        "HoneyuserSecret!",
    )

    endpoint, kwargs = calls[0]
    script = calls[1]
    assert endpoint == "https://dc.example.test:5986/wsman"
    assert kwargs["transport"] == "ntlm"
    assert kwargs["server_cert_validation"] == "validate"
    assert kwargs["message_encryption"] == "auto"
    assert "AdministrativeSecret!" not in script
    assert "HoneyuserSecret!" not in script
    encoded = re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
    assert json.loads(base64.b64decode(encoded))["password"] == "HoneyuserSecret!"
    assert created.sid == "S-1-5-21-100"


def test_http_requires_an_explicit_unsafe_opt_in():
    with pytest.raises(DeploymentValidationError, match="HTTP"):
        WinRMActiveDirectoryTransport().get_user(
            _target("http://dc.example.test:5985/wsman"),
            {"username": "u", "password": "p"},
            "user",
        )


@pytest.mark.parametrize(
    "config,expected",
    [({"transport": "basic"}, "transporte"), ({"server_cert_validation": "maybe"}, "server_cert_validation")],
)
def test_winrm_rejects_unknown_security_options_before_opening_a_session(config, expected):
    with pytest.raises(DeploymentValidationError, match=expected):
        WinRMActiveDirectoryTransport().get_user(
            _target(**config), {"username": "u", "password": "p"}, "user"
        )


def test_remote_errors_redact_the_encoded_payload(monkeypatch):
    class Session:
        def __init__(self, *args, **kwargs):
            pass

        def run_ps(self, script):
            encoded = re.search(r"FromBase64String\('([^']+)'\)", script).group(1)
            return _response(None, status=1, stderr=f"failure near {encoded}".encode())

    monkeypatch.setitem(sys.modules, "winrm", SimpleNamespace(Session=Session))
    with pytest.raises(DeploymentExecutionError) as captured:
        WinRMActiveDirectoryTransport().set_password_and_enable(
            _target(), {"username": "admin", "password": "AdminSecret!"}, "S-1-5-21-100", "HoneySecret!"
        )

    message = str(captured.value)
    assert "[REDACTED]" in message
    assert "HoneySecret!" not in message
    assert "AdminSecret!" not in message


def test_invalid_json_response_does_not_echo_remote_output(monkeypatch):
    class Session:
        def __init__(self, *args, **kwargs):
            pass

        def run_ps(self, script):
            return SimpleNamespace(status_code=0, std_out=b"not-json SECRET", std_err=b"")

    monkeypatch.setitem(sys.modules, "winrm", SimpleNamespace(Session=Session))
    with pytest.raises(DeploymentExecutionError, match="respuesta no válida") as captured:
        WinRMActiveDirectoryTransport().get_user(
            _target(), {"username": "admin", "password": "secret"}, "laura.fernandez"
        )
    assert "SECRET" not in str(captured.value)
