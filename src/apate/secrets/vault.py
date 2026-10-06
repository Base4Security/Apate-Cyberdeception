"""Cifrado de secretos recuperables almacenados por APATE.

Protege una copia de ``.apate_data``, un backup, un directorio compartido o
un JSON pegado en un ticket: esos artefactos no contienen credenciales
utilizables sin la clave. No protege frente a alguien con acceso al host:
quien puede leer el directorio de datos también puede leer la clave local.
La protección frente a ese atacante requiere una bóveda externa, una mejora
futura de la edición libre.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from ..i18n import gettext as _

SECRET_MARKER = "apate-fernet:v1:"
_KEY_FILENAME = "secret_encryption.key"
_default_cipher: "SecretCipher | None" = None


class SecretDecryptionError(ValueError):
    """Un secreto marcado como cifrado no pudo verificarse o descifrarse."""


class SecretCipher:
    """Cifra valores de texto con Fernet y conserva valores heredados legibles."""

    def __init__(self, key: str | bytes):
        try:
            self._fernet = Fernet(key.encode("ascii") if isinstance(key, str) else key)
        except (TypeError, ValueError) as exc:
            raise ValueError(_("APATE_SECRET_ENCRYPTION_KEY no es una clave Fernet válida.")) from exc

    @classmethod
    def from_environment_or_data_dir(
        cls, data_dir: str | Path, *, logger: logging.Logger | None = None
    ) -> "SecretCipher":
        """Obtiene la clave de entorno o crea una clave local para el primer arranque."""

        return cls(
            cls.fernet_key_from_environment_or_data_dir(
                data_dir,
                environment_variable="APATE_SECRET_ENCRYPTION_KEY",
                key_filename=_KEY_FILENAME,
                logger=logger,
            )
        )

    @staticmethod
    def fernet_key_from_environment_or_data_dir(
        data_dir: str | Path,
        *,
        environment_variable: str,
        key_filename: str,
        logger: logging.Logger | None = None,
    ) -> bytes:
        """Obtiene una clave Fernet del entorno o crea una local persistente.

        Centraliza el mismo patrón para secretos propios y para recursos
        vendorizados que APATE monta dentro de su proceso. La variable de
        entorno siempre tiene prioridad; el archivo solo facilita el primer
        arranque local y debe vivir en un directorio de datos gitignorado.
        """

        configured_key = os.environ.get(environment_variable)
        if configured_key:
            try:
                Fernet(configured_key.encode("ascii"))
            except (TypeError, ValueError) as exc:
                raise ValueError(
            _("%(variable)s no es una clave Fernet válida.", variable=environment_variable)
        ) from exc
            return configured_key.encode("ascii")

        key_path = Path(data_dir) / key_filename
        if key_path.exists():
            key = key_path.read_bytes().strip()
            try:
                Fernet(key)
            except (TypeError, ValueError) as exc:
                raise ValueError(
            _("La clave local '%(filename)s' no es una clave Fernet válida.", filename=key_filename)
        ) from exc
            return key

        key_path.parent.mkdir(parents=True, exist_ok=True)
        generated_key = Fernet.generate_key()
        try:
            descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return SecretCipher.fernet_key_from_environment_or_data_dir(
                data_dir,
                environment_variable=environment_variable,
                key_filename=key_filename,
                logger=logger,
            )
        try:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(generated_key)
            # En Windows chmod es de alcance limitado, pero no perjudica y deja
            # el modo correcto en plataformas POSIX.
            os.chmod(key_path, 0o600)
        except Exception:
            if key_path.exists():
                key_path.unlink()
            raise

        if logger is not None:
            logger.warning(
                "%s no está configurada: se generó una clave local en el directorio de datos. "
                "Protege copias de los datos, pero no a quien tenga acceso al host.",
                environment_variable,
            )
        return generated_key

    @staticmethod
    def is_encrypted(value: object) -> bool:
        return isinstance(value, str) and value.startswith(SECRET_MARKER)

    def encrypt(self, value: str) -> str:
        """Cifra ``value``; evita volver a cifrar un valor ya marcado."""

        if not value or self.is_encrypted(value):
            return value
        return SECRET_MARKER + self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str:
        """Descifra un valor marcado; conserva texto plano para migración gradual."""

        if not self.is_encrypted(value):
            return value
        try:
            return self._fernet.decrypt(value.removeprefix(SECRET_MARKER).encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError, ValueError) as exc:
            raise SecretDecryptionError(_("No se pudo descifrar un secreto almacenado.")) from exc


def configure_default_secret_cipher(cipher: SecretCipher) -> None:
    """Define el cifrador del proceso para utilidades vendorizadas integradas."""

    global _default_cipher
    _default_cipher = cipher


def get_default_secret_cipher() -> SecretCipher:
    """Devuelve el cifrador activo o inicializa el directorio de datos por defecto."""

    global _default_cipher
    if _default_cipher is None:
        _default_cipher = SecretCipher.from_environment_or_data_dir(Path(".apate_data"))
    return _default_cipher
