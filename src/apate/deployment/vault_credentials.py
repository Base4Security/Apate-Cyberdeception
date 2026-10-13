"""Bóveda de credenciales en HashiCorp Vault KV v2, sin clave local."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

import requests

from .credentials import _validate_secret
from .exceptions import DeploymentExecutionError, DeploymentValidationError

_MOUNT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")


class VaultCredentialStore:
    """Guarda referencias opacas bajo un mount KV v2 versionado."""

    def __init__(self, *, address: str, mount: str = "secret", token: str | None = None,
                 token_file: str | Path | None = None, namespace: str = "", session=None) -> None:
        parsed = urlsplit(address)
        if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.path not in {"", "/"}:
            raise ValueError("Vault requiere una URL HTTPS base sin credenciales ni path.")
        if not _MOUNT.fullmatch(mount) or ".." in mount.split("/"):
            raise ValueError("Mount KV v2 inválido.")
        if bool(token) == bool(token_file):
            raise ValueError("Declarar exactamente un token Vault o archivo de token.")
        self.address = address.rstrip("/")
        self.mount = mount.strip("/")
        self._token = token
        self._token_file = Path(token_file) if token_file else None
        self.namespace = namespace.strip()
        self.session = session or requests.Session()

    @classmethod
    def from_environment(cls) -> "VaultCredentialStore":
        return cls(address=os.environ["APATE_VAULT_ADDR"], mount=os.environ.get("APATE_VAULT_MOUNT", "secret"),
                   token=os.environ.get("APATE_VAULT_TOKEN"), token_file=os.environ.get("APATE_VAULT_TOKEN_FILE"),
                   namespace=os.environ.get("APATE_VAULT_NAMESPACE", ""))

    def _headers(self) -> dict[str, str]:
        token = self._token or self._token_file.read_text(encoding="utf-8").strip()
        if not token:
            raise DeploymentValidationError("El token Vault está vacío.")
        headers = {"X-Vault-Token": token}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        return headers

    def _url(self, reference: str) -> str:
        _validate_secret(reference, {"reference": "present"})
        digest = hashlib.sha256(reference.encode("utf-8")).hexdigest()
        return f"{self.address}/v1/{self.mount}/data/apate/{digest}"

    def _request(self, method: str, reference: str, **kwargs):
        try:
            response = self.session.request(method, self._url(reference), headers=self._headers(),
                                            timeout=8, verify=True, **kwargs)
        except requests.RequestException as exc:
            raise DeploymentExecutionError("Vault no está disponible.") from exc
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise DeploymentExecutionError(f"Vault rechazó la operación (HTTP {response.status_code}).")
        try:
            result = response.json()
        except ValueError as exc:
            raise DeploymentExecutionError("Vault devolvió una respuesta JSON inválida.") from exc
        if not isinstance(result, dict):
            raise DeploymentExecutionError("Vault devolvió una respuesta inesperada.")
        return result

    def get(self, reference: str) -> dict[str, str]:
        result = self._request("GET", reference)
        if result is None:
            raise DeploymentValidationError("La referencia de credenciales no existe en Vault.")
        data = result.get("data", {}).get("data", {})
        if data.get("reference") != reference:
            raise DeploymentValidationError("La referencia almacenada en Vault no coincide.")
        values = dict(data.get("values", {}))
        _validate_secret(reference, values)
        return values

    def save(self, reference: str, values: Mapping[str, str]) -> None:
        _validate_secret(reference, values)
        current = self._request("GET", reference)
        version = 0 if current is None else int(current.get("data", {}).get("metadata", {}).get("version", 0))
        result = self._request("POST", reference, json={"options": {"cas": version},
                                                         "data": {"reference": reference, "values": dict(values)}})
        if result is None:
            raise DeploymentExecutionError("Vault no confirmó la escritura de la credencial.")

    def exists(self, reference: str) -> bool:
        return self._request("GET", reference) is not None
