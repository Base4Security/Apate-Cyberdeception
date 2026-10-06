from cryptography.fernet import Fernet
import pytest

from apate.deployment import (
    DeploymentValidationError,
    EncryptedJSONCredentialStore,
    MappingCredentialStore,
)
from apate.secrets import SecretCipher


def test_mapping_store_copies_values_and_reports_missing_reference():
    original = {"username": "admin", "password": "secret"}
    store = MappingCredentialStore({"secret://ad/admin": original})
    original["password"] = "changed"

    assert store.get("secret://ad/admin")["password"] == "secret"
    with pytest.raises(DeploymentValidationError, match="secret://missing"):
        store.get("secret://missing")


def test_encrypted_store_never_writes_reference_or_values_in_filename_or_plaintext(tmp_path):
    store = EncryptedJSONCredentialStore(tmp_path, SecretCipher(Fernet.generate_key()))
    reference = "secret://ad/production-admin"
    store.save(reference, {"username": "DOMAIN\\svc-apate", "password": "VerySecret!1"})

    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    raw = files[0].read_text(encoding="utf-8")
    assert "production-admin" not in files[0].name
    assert "VerySecret!1" not in raw
    assert "DOMAIN\\\\svc-apate" not in raw
    assert store.get(reference) == {"username": "DOMAIN\\svc-apate", "password": "VerySecret!1"}


@pytest.mark.parametrize("reference", ["", "ad/admin", "../secret"])
def test_stores_only_accept_opaque_secret_references(reference):
    store = MappingCredentialStore()
    with pytest.raises(DeploymentValidationError):
        store.save(reference, {"password": "value"})
