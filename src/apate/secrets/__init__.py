"""Cifrado local de secretos recuperables de APATE."""

from .storage import (
    EncryptedJSONFileOperationRepository,
    EncryptedSiemSoarConfigRepository,
    EncryptedVirusTotalConfigRepository,
)
from .vault import (
    SECRET_MARKER,
    SecretCipher,
    SecretDecryptionError,
    configure_default_secret_cipher,
    get_default_secret_cipher,
)

__all__ = [
    "EncryptedJSONFileOperationRepository",
    "EncryptedSiemSoarConfigRepository",
    "EncryptedVirusTotalConfigRepository",
    "SECRET_MARKER",
    "SecretCipher",
    "SecretDecryptionError",
    "configure_default_secret_cipher",
    "get_default_secret_cipher",
]
