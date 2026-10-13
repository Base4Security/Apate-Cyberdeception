"""Resolución y almacenamiento cifrado de credenciales de conectores."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping, Protocol

from ..i18n import gettext as _
from ..atomic_write import write_json_atomically
from ..secrets import SecretCipher
from .exceptions import DeploymentValidationError


class CredentialStore(Protocol):
    """Bóveda mínima usada por conectores sin acoplarlos a Flask."""

    def get(self, reference: str) -> dict[str, str]: ...

    def save(self, reference: str, values: Mapping[str, str]) -> None: ...

    def exists(self, reference: str) -> bool: ...


class MappingCredentialStore:
    """Implementación en memoria para pruebas e integraciones embebidas."""

    def __init__(self, values: Mapping[str, Mapping[str, str]] | None = None) -> None:
        self._values = {key: dict(value) for key, value in (values or {}).items()}

    def get(self, reference: str) -> dict[str, str]:
        try:
            return dict(self._values[reference])
        except KeyError as exc:
            raise DeploymentValidationError(
                _("No existe la referencia de credenciales '%(reference)s'.", reference=reference)
            ) from exc

    def save(self, reference: str, values: Mapping[str, str]) -> None:
        _validate_secret(reference, values)
        self._values[reference] = dict(values)

    def exists(self, reference: str) -> bool:
        return reference in self._values


class EncryptedJSONCredentialStore:
    """Bóveda local cifrada; el nombre de archivo nunca revela la referencia."""

    def __init__(self, directory: str | Path, cipher: SecretCipher) -> None:
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)
        self._cipher = cipher

    def _path(self, reference: str) -> Path:
        digest = hashlib.sha256(reference.encode("utf-8")).hexdigest()
        return self._directory / f"{digest}.json"

    def get(self, reference: str) -> dict[str, str]:
        path = self._path(reference)
        if not path.is_file():
            raise DeploymentValidationError(
                _("No existe la referencia de credenciales '%(reference)s'.", reference=reference)
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("reference") != reference:
            raise DeploymentValidationError(_("La referencia de credenciales almacenada no coincide."))
        values = {
            str(key): self._cipher.decrypt(str(value))
            for key, value in dict(data.get("values", {})).items()
        }
        _validate_secret(reference, values)
        return values

    def save(self, reference: str, values: Mapping[str, str]) -> None:
        _validate_secret(reference, values)
        path = self._path(reference)
        data = {
            "reference": reference,
            "values": {str(key): self._cipher.encrypt(value) for key, value in values.items()},
        }
        write_json_atomically(path, data, mode=0o600)

    def exists(self, reference: str) -> bool:
        return self._path(reference).is_file()


def _validate_secret(reference: str, values: Mapping[str, str]) -> None:
    if not reference.strip() or not reference.startswith("secret://"):
        raise DeploymentValidationError(_("La referencia de credenciales debe comenzar con 'secret://'."))
    if not values or any(not isinstance(value, str) or not value for value in values.values()):
        raise DeploymentValidationError(_("La credencial no puede estar vacía."))
