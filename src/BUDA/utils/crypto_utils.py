"""
At-rest encryption for sensitive UserProfile columns (APATE roadmap
milestone M8b -- see docs/analisis-repos-existentes.md in the APATE repo
for the original finding: winrm_username/winrm_password stored as plaintext
columns in models/user.py).

Uses `cryptography`'s Fernet (symmetric, authenticated encryption --
AES-128-CBC plus HMAC-SHA256 under the hood) rather than a homemade scheme:
it's a widely reviewed, actively maintained library, and Fernet specifically
is a deliberately narrow, hard-to-misuse API (one key, encrypt/decrypt, no
mode or IV choices to get wrong) -- a good fit for a single-key,
few-columns use case like this one, rather than reaching for the
lower-level `cryptography` primitives directly.

Key management: BUDA standalone reads the key only from the
BUDA_CREDENTIAL_ENCRYPTION_KEY environment variable. It does **not** load a
`.env` file itself. When APATE mounts BUDA as an in-process library,
`create_app()` supplies a stable local fallback stored in APATE's gitignored
data directory; the environment variable still has priority. Generate an
explicit production key with:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

and export it as BUDA_CREDENTIAL_ENCRYPTION_KEY in the service environment.
If BUDA runs without APATE and the variable isn't set, this module fails fast
(RuntimeError) the first time something needs to read or write an encrypted
column, rather than silently storing plaintext or producing a ciphertext
nothing can decrypt later.

If you already have data encrypted under an old key and need to rotate to a
new one, decrypt every value with the old key and re-encrypt with the new
one (see scripts/migrate_encrypt_credentials.py for the equivalent
plaintext -> ciphertext pattern) -- there is no key-versioning scheme here,
by design, to keep this module simple; add one if this project ever needs
to rotate keys without downtime.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app, has_app_context
from sqlalchemy.types import Text, TypeDecorator

ENV_VAR = "BUDA_CREDENTIAL_ENCRYPTION_KEY"

_fernet: Optional[Fernet] = None
_fernet_key: Optional[bytes] = None
_logger = logging.getLogger(__name__)


class UnrecoverableCredential:
    """Marcador no utilizable para una credencial WinRM indescifrable."""

    def __str__(self) -> str:
        return "[credencial WinRM no recuperable]"

    def __repr__(self) -> str:
        return "UnrecoverableCredential()"


def is_unrecoverable_credential(value: object) -> bool:
    """Indica si el valor degradado no puede enviarse a WinRM."""

    return isinstance(value, UnrecoverableCredential)


def _get_fernet() -> Fernet:
    global _fernet, _fernet_key

    configured_key = os.environ.get(ENV_VAR)
    if configured_key is not None:
        key = configured_key.encode("ascii")
    elif has_app_context():
        key = current_app.config.get(ENV_VAR)
    else:
        key = None
    if isinstance(key, str):
        key = key.encode("ascii")
    if not key:
        raise RuntimeError(
            f"{ENV_VAR} is not set. Generate one with "
            '`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` '
            "and export it before storing or reading WinRM credentials."
        )
    if _fernet is not None and _fernet_key == key:
        return _fernet

    _fernet = Fernet(key)
    _fernet_key = key
    return _fernet


def reset_fernet_cache() -> None:
    """Clears the cached Fernet instance so a later call to _get_fernet()
    re-reads BUDA_CREDENTIAL_ENCRYPTION_KEY from the environment. Only
    needed by tests that change the key mid-run; application code never
    needs to call this."""

    global _fernet, _fernet_key
    _fernet = None
    _fernet_key = None


def encrypt_value(plaintext: str) -> str:
    """Encrypts a plaintext string, returning a base64 ciphertext token
    safe to store as text. Used directly by the migration script
    (scripts/migrate_encrypt_credentials.py) and indirectly, via
    EncryptedString, by ORM-mapped columns."""

    return _get_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_value(ciphertext: str) -> str:
    """Decrypts a Fernet token produced by encrypt_value(). Raises
    cryptography.fernet.InvalidToken if `ciphertext` isn't a valid token
    for the configured key -- most likely a value that hasn't been
    migrated yet (see scripts/migrate_encrypt_credentials.py) or a
    wrong/rotated key."""

    return _get_fernet().decrypt(ciphertext.encode("utf-8")).decode("utf-8")


class EncryptedString(TypeDecorator):
    """SQLAlchemy column type: transparently encrypts on write, decrypts on
    read, so a mapped attribute (e.g. UserProfile.winrm_password) behaves
    like a plain string everywhere else in the codebase that reads it
    directly -- orchestrator.py's WinRM session, most notably -- none of
    that needs to change to use this.

    Precisely BECAUSE this is transparent, code that turns a mapped
    attribute into a value meant to leave the process (an API response, a
    rendered template, a log line) still has to decide for itself whether
    that value belongs there -- this type has no way to know. See the
    APATE roadmap M14c fix in models/user.py::UserProfile.to_dict(): that
    method used to include winrm_username/winrm_password precisely
    because reading them here returns real plaintext, not because
    anything about serialization was safe by default.

    Stored as TEXT rather than a bounded VARCHAR: a Fernet token is always
    noticeably longer than its plaintext input (~60 bytes of fixed
    overhead, then base64 expansion on top), so the original String(100)
    columns would have silently truncated most real values."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return encrypt_value(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        try:
            return decrypt_value(value)
        except InvalidToken:
            _logger.warning(
                "No se pudo descifrar una credencial WinRM almacenada; el perfil queda en modo no recuperable."
            )
            return UnrecoverableCredential()
