"""Proveedor OIDC de referencia con usuarios aprovisionados previamente.

**Sobre el acceso de emergencia.** Existe para no quedarse afuera si el IdP se
cae, que es una necesidad real. Pero es tambien una contrasenia local que
**evita el inicio de sesion corporativo con su MFA y su revocacion**, asi que
esta acotado en tres sentidos, y ninguno era cierto antes:

* **Es opcional.** Sin `APATE_OIDC_EMERGENCY_PASSWORD_HASH` no hay cuenta de
  emergencia. Antes era obligatorio: toda instalacion con SSO estaba forzada a
  tener ademas una puerta que lo evita.
* **Vence.** `APATE_OIDC_EMERGENCY_EXPIRES_AT` es obligatorio cuando la cuenta
  existe, y el vencimiento se revalida en cada pedido, no solo al entrar: una
  sesion abierta se corta sola cuando la ventana se cierra.
* **Se puede expulsar.** Su `credential_version` se deriva del hash, asi que
  rotar la variable invalida la sesion que estuviera abierta. Antes quedaba
  fija en 0 y ninguna rotacion la alcanzaba.

Lo que sigue sin poder resolverse en esta capa es que sea una credencial
local: quien la tenga entra sin pasar por el IdP. Por eso la interfaz la
muestra como una advertencia mientras este activa (ver la pantalla de
usuarios) y cada uso queda en la auditoria.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlencode
from uuid import uuid4

import jwt
import requests
from werkzeug.security import check_password_hash

from ..atomic_write import write_text_atomically
from ..i18n import gettext as _
from .models import Identity, IdentityRole
from .providers import IdentityProvider, RedirectIdentityProvider

#: Identificador de la cuenta de rescate. Constante y no literal suelto para
#: que el resto del sistema (auditoria, interfaz) pueda reconocerla.
EMERGENCY_IDENTITY_ID = "oidc-emergency"


def _vencimiento_de_emergencia(crudo: str) -> datetime | None:
    """Interpreta `APATE_OIDC_EMERGENCY_EXPIRES_AT`, o `None` si no sirve.

    Una fecha sin zona horaria se toma como UTC: es lo unico que se puede
    asumir sin inventar la del servidor, y equivocarse hacia UTC acorta la
    ventana en vez de alargarla.
    """

    texto = (crudo or "").strip()
    if not texto:
        return None
    try:
        momento = datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        return None
    return momento if momento.tzinfo else momento.replace(tzinfo=timezone.utc)


class OIDCIdentityProvider(IdentityProvider, RedirectIdentityProvider):
    """OIDC Authorization Code; nunca crea usuarios a partir de claims.

    Hereda `RedirectIdentityProvider` explicitamente aunque el `Protocol` sea
    estructural: es la implementacion de referencia del contrato, y quien la
    lea para escribir la suya tiene que ver cual esta implementando.
    """

    authentication_mode = "redirect"

    def __init__(self, path: Path):
        self._path = Path(path)
        self.issuer = os.environ.get("APATE_OIDC_ISSUER", "")
        self.client_id = os.environ.get("APATE_OIDC_CLIENT_ID", "")
        self.client_secret = os.environ.get("APATE_OIDC_CLIENT_SECRET", "")
        self.authorization_endpoint = os.environ.get("APATE_OIDC_AUTHORIZATION_ENDPOINT", "")
        self.token_endpoint = os.environ.get("APATE_OIDC_TOKEN_ENDPOINT", "")
        self.jwks_uri = os.environ.get("APATE_OIDC_JWKS_URI", "")
        self.emergency_username = os.environ.get("APATE_OIDC_EMERGENCY_USERNAME", "emergency")
        self.emergency_password_hash = os.environ.get("APATE_OIDC_EMERGENCY_PASSWORD_HASH", "")
        self.emergency_expires_at = _vencimiento_de_emergencia(
            os.environ.get("APATE_OIDC_EMERGENCY_EXPIRES_AT", "")
        )
        if not all((self.issuer, self.client_id, self.client_secret, self.authorization_endpoint, self.token_endpoint, self.jwks_uri)):
            raise ValueError(_("La configuración OIDC está incompleta."))
        # El acceso de emergencia es **opcional**, y esa es la correccion de
        # fondo: antes era obligatorio, o sea que toda instalacion con SSO
        # estaba forzada a tener ademas una contrasenia local que lo evita.
        # Sin hash no hay cuenta de emergencia y `authenticate()` no admite a
        # nadie; el rescate, si el IdP se cae, es configurar el hash y
        # reiniciar, que es una accion deliberada y con registro.
        if self.emergency_password_hash and self.emergency_expires_at is None:
            raise ValueError(
                _(
                    "El acceso de emergencia de OIDC requiere "
                    "APATE_OIDC_EMERGENCY_EXPIRES_AT con una fecha ISO-8601: una credencial "
                    "que evita el inicio de sesión corporativo no puede ser válida para siempre."
                )
            )

    def has_identities(self) -> bool:
        return True

    def authorization_url(self, redirect_uri: str, state: str) -> str:
        return f"{self.authorization_endpoint}?{urlencode({'response_type':'code','client_id':self.client_id,'redirect_uri':redirect_uri,'scope':'openid','state':state})}"

    def complete_authorization(self, code: str, redirect_uri: str) -> Identity | None:
        response = requests.post(self.token_endpoint, data={'grant_type':'authorization_code','code':code,'redirect_uri':redirect_uri,'client_id':self.client_id,'client_secret':self.client_secret}, timeout=10)
        response.raise_for_status()
        token = response.json()['id_token']
        key = jwt.PyJWKClient(self.jwks_uri).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=['RS256'], audience=self.client_id, issuer=self.issuer, options={'require':['exp','iss','aud','sub']})
        return next((item for item in self.list() if item.id == str(claims['sub']) and item.active), None)

    @property
    def emergency_enabled(self) -> bool:
        """`True` mientras el acceso de emergencia exista y no haya vencido.

        Lo consulta tambien la interfaz, para poder decirle al operador que
        esa puerta esta abierta en vez de dejarla invisible.
        """

        if not self.emergency_password_hash or self.emergency_expires_at is None:
            return False
        return datetime.now(timezone.utc) < self.emergency_expires_at

    def _emergency_identity(self) -> Identity:
        """La identidad de rescate, con version de credencial derivada del hash.

        `credential_version` sale de la propia credencial y no de un contador:
        asi, **rotar el hash expulsa la sesion de emergencia que estuviera
        abierta**, igual que resetear la contrasenia de una identidad local.
        Antes quedaba fija en 0 y la sesion sobrevivia a cualquier rotacion.
        """

        version = int.from_bytes(
            sha256(self.emergency_password_hash.encode("utf-8")).digest()[:4], "big"
        )
        return Identity(
            id=EMERGENCY_IDENTITY_ID,
            display_name=self.emergency_username,
            role=IdentityRole.ADMINISTRATION,
            credential_version=version,
        )

    def authenticate(self, display_name: str, password: str) -> Identity | None:
        if not self.emergency_enabled:
            return None
        if display_name != self.emergency_username or not check_password_hash(self.emergency_password_hash, password):
            return None
        return self._emergency_identity()

    def get(self, identity_id: str) -> Identity | None:
        if identity_id == EMERGENCY_IDENTITY_ID:
            # Se revalida el vencimiento en cada pedido, no solo al entrar:
            # una sesion de emergencia abierta se corta sola cuando la ventana
            # se cierra, sin necesidad de reiniciar el proceso.
            return self._emergency_identity() if self.emergency_enabled else None
        return next((item for item in self.list() if item.id == identity_id and item.active), None)

    def provision(self, subject: str, display_name: str, role: str, team_id: str | None) -> Identity:
        parsed_role = IdentityRole(role)
        if parsed_role is not IdentityRole.ADMINISTRATION and not team_id:
            raise ValueError(_("Los usuarios no administrativos requieren un equipo."))
        records = self._records()
        if any(item['id'] == subject for item in records): raise ValueError(_("El sujeto ya está aprovisionado."))
        record = {'id':subject, 'display_name':display_name, 'active':True, 'role':parsed_role.value, 'team_id':team_id}
        records.append(record); self._save(records); return self._identity(record)

    def list(self) -> list[Identity]: return [self._identity(item) for item in self._records()]
    def _records(self):
        return json.loads(self._path.read_text(encoding='utf-8')).get('identities', []) if self._path.exists() else []
    def _save(self, records):
        write_text_atomically(self._path, json.dumps({'identities':records}, ensure_ascii=False, indent=2)+'\n')
    @staticmethod
    def _identity(record): return Identity(id=str(record['id']), display_name=str(record['display_name']), active=bool(record['active']), role=IdentityRole(record['role']), team_id=record.get('team_id'))
