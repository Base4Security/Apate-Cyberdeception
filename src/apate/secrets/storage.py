"""Adaptadores cifrados para configuraciones globales de integraciones."""

from __future__ import annotations

import json
from pathlib import Path

from ..core.models import Operation
from ..core.repository import JSONFileOperationRepository
from .vault import SecretCipher
from ..atomic_write import write_text_atomically
import logging

_logger = logging.getLogger(__name__)


class EncryptedVirusTotalConfigRepository:
    """Mantiene el contrato de VirusTotal y cifra la API key en disco."""

    def __init__(self, path: str | Path, cipher: SecretCipher):
        self._path = Path(path)
        self._cipher = cipher

    def load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return {"api_key": self._cipher.decrypt(str(data.get("api_key", "")))}

    def save_api_key(self, api_key: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomically(self._path, json.dumps({"api_key": self._cipher.encrypt(api_key)}, indent=2))


class EncryptedSiemSoarConfigRepository:
    """Mantiene el contrato SIEM/SOAR y cifra sus dos secretos en disco."""

    def __init__(self, path: str | Path, cipher: SecretCipher):
        self._path = Path(path)
        self._cipher = cipher

    def load(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return {
            "webhook_url": self._cipher.decrypt(str(data.get("webhook_url", ""))),
            "auth_token": self._cipher.decrypt(str(data.get("auth_token", ""))),
        }

    def save(self, webhook_url: str, auth_token: str) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomically(self._path, json.dumps(
                {
                    "webhook_url": self._cipher.encrypt(webhook_url),
                    "auth_token": self._cipher.encrypt(auth_token),
                },
                indent=2,
            ))


class EncryptedJSONFileOperationRepository(JSONFileOperationRepository):
    """Repositorio de operaciones que cifra el ``auth_token`` de Canarytoken.

    La operación que entrega al dominio conserva el token en claro para que el
    plugin no dependa del cifrador. El único límite criptográfico es el JSON
    en disco; al volver a guardar una operación heredada, un token en claro se
    migra automáticamente al formato cifrado.
    """

    def __init__(self, directory: str | Path, cipher: SecretCipher):
        super().__init__(directory)
        self._cipher = cipher

    def save(self, operation: Operation) -> None:
        data = operation.to_dict()
        self._encrypt_canarytoken_auth_tokens(data)
        path = self._path_for(operation.id)
        write_text_atomically(path, json.dumps(data, indent=2, ensure_ascii=False))

    def get(self, operation_id: str) -> Operation:
        path = self._path_for(operation_id)
        if not path.exists():
            from ..core.exceptions import OperationNotFoundError

            raise OperationNotFoundError(operation_id)
        data = json.loads(path.read_text(encoding="utf-8"))
        self._decrypt_canarytoken_auth_tokens(data)
        return Operation.from_dict(data)

    def list(self):
        """Igual que la version sin cifrar: un archivo roto se saltea y se anota.

        Aca el motivo extra es el descifrado: una clave rotada sin migrar los
        datos hace fallar `_decrypt_canarytoken_auth_tokens()` en cada
        operacion que tenga un token guardado. Que eso deje la instalacion en
        500 permanente, en vez de mostrar el resto y decir cuantas no se
        pudieron leer, es la peor respuesta posible.
        """

        self.unreadable = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._decrypt_canarytoken_auth_tokens(data)
                yield Operation.from_dict(data)
            except Exception as error:  # incluye fallos de descifrado
                self.unreadable.append((path.name, str(error)))
                _logger.warning("No se pudo leer la operacion %s: %s", path.name, error)

    def _encrypt_canarytoken_auth_tokens(self, data: dict) -> None:
        for binding in data.get("plugins", []):
            config = binding.get("config", {})
            auth_token = config.get("auth_token")
            if isinstance(auth_token, str):
                config["auth_token"] = self._cipher.encrypt(auth_token)

    def _decrypt_canarytoken_auth_tokens(self, data: dict) -> None:
        for binding in data.get("plugins", []):
            config = binding.get("config", {})
            auth_token = config.get("auth_token")
            if isinstance(auth_token, str):
                config["auth_token"] = self._cipher.decrypt(auth_token)
