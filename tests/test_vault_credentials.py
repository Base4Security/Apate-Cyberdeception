"""Vault KV v2 conserva referencias opacas, TLS y control CAS."""

import pytest

from apate.deployment import VaultCredentialStore


class _Response:
    def __init__(self, status, body=None):
        self.status_code = status
        self.body = body or {}

    def json(self):
        return self.body


class _Session:
    def __init__(self):
        self.calls = []
        self.secret = None
        self.version = 0

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if method == "GET":
            return _Response(404) if self.secret is None else _Response(200, {"data": {"data": self.secret, "metadata": {"version": self.version}}})
        assert kwargs["json"]["options"]["cas"] == self.version
        self.secret = kwargs["json"]["data"]
        self.version += 1
        return _Response(200, {"data": {"version": self.version}})


def test_vault_store_reads_and_rotates_without_local_secret(tmp_path):
    session = _Session()
    token_file = tmp_path / "vault-agent-token"
    token_file.write_text("agent-token", encoding="utf-8")
    store = VaultCredentialStore(address="https://vault.example.test", token_file=token_file,
                                 mount="secret", session=session)
    reference = "secret://deployment-target/abc/administrative"
    store.save(reference, {"username": "svc-apate", "password": "primera"})
    assert store.get(reference)["password"] == "primera"
    store.save(reference, {"username": "svc-apate", "password": "segunda"})
    assert store.get(reference)["password"] == "segunda"
    assert session.version == 2
    assert all(call[2]["verify"] is True and call[2]["timeout"] == 8 for call in session.calls)
    assert all("secret://" not in call[1] and "primera" not in call[1] for call in session.calls)
    assert not list(tmp_path.glob("*.json"))


def test_vault_store_rejects_http_and_ambiguous_token():
    with pytest.raises(ValueError, match="HTTPS"):
        VaultCredentialStore(address="http://vault.test", token="token")
    with pytest.raises(ValueError, match="exactamente"):
        VaultCredentialStore(address="https://vault.test", token="token", token_file="token-file")
