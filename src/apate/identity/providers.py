"""Contrato y proveedor local de identidades.

Las contraseñas solo viven como hashes en el archivo privado del proveedor;
no forman parte de :class:`Identity` ni se devuelven desde ningún método.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Protocol, runtime_checkable
from uuid import uuid4

from werkzeug.security import check_password_hash, generate_password_hash

from ..i18n import gettext as _
from .models import Identity, IdentityRole
from ..atomic_write import write_text_atomically


class IdentityProvider(ABC):
    """Interfaz mínima para un proveedor intercambiable de identidad."""

    authentication_mode = "credentials"

    def authenticate(self, display_name: str, password: str) -> Identity | None:
        """Autentica credenciales cuando el proveedor usa ese modo."""

        raise NotImplementedError

    @abstractmethod
    def get(self, identity_id: str) -> Identity | None:
        """Resuelve una identidad activa por su identificador estable."""


@runtime_checkable
class RedirectIdentityProvider(Protocol):
    """Contrato **opcional**: el proveedor autentica fuera de APATE.

    Es el segundo punto de extension de identidad, y hasta ahora no existia
    como contrato: `apate.web` llamaba a estos dos metodos por duck typing
    —`getattr(provider, "authentication_mode", ...)` y despues la llamada
    directa—, de modo que la unica forma de saber que tenia que implementar
    un proveedor de directorio corporativo era leer `create_app()`. Un
    tercero no puede programar contra eso, y una excepcion de licencia no
    puede tener por alcance una interfaz que no esta declarada (ver
    `docs/frontera-obra-derivada.md`).

    **Por que un `Protocol` y no una clase base abstracta**, a diferencia de
    `IdentityProvider`: esto es una capacidad opcional que se suma a la
    obligatoria. Con un `Protocol` estructural, un proveedor la satisface por
    implementar los dos metodos, sin herencia multiple y sin tener que
    importar nada de APATE mas alla de lo que ya importa. Heredarlo
    explicitamente tambien vale, y es lo que hace `OIDCIdentityProvider`
    para que la intencion quede escrita.

    **Limite conocido de `runtime_checkable`:** `isinstance()` comprueba que
    los metodos existan, no sus firmas. Es lo mismo que verificaba el
    `hasattr` implicito de antes; lo que cambia es que ahora hay un nombre,
    un docstring y un unico lugar donde se decide. La coherencia entre el
    modo declarado y los metodos si se verifica, y temprano:
    `IdentityProviderRegistry.create()` falla al construir un proveedor que
    declare `authentication_mode = "redirect"` sin implementarlos.

    Quien lo implemente tiene que respetar dos cosas que la aplicacion da por
    sentadas, porque son las que hacen seguro el flujo:

    1. `authorization_url()` recibe el `state` que APATE genero y lo tiene
       que propagar tal cual al proveedor. APATE lo guarda en la sesion y lo
       compara al volver; sin esa propagacion el retorno es falsificable.
    2. `complete_authorization()` devuelve `None` —no una identidad nueva—
       cuando el sujeto autenticado no esta aprovisionado en APATE. Que el
       IdP autentique a alguien no alcanza para entrar: con que rol y que
       equipo entraria seria una decision tomada por omision.
    """

    def authorization_url(self, redirect_uri: str, state: str) -> str:
        """URL del proveedor a la que se envia a la persona para autenticarse.

        `state` viaja sin modificar; `redirect_uri` es la ruta de retorno de
        APATE, ya absoluta.
        """
        ...

    def complete_authorization(self, code: str, redirect_uri: str) -> Identity | None:
        """Cierra el retorno y resuelve la identidad **ya aprovisionada**.

        Devuelve `None` si el sujeto no corresponde a ninguna identidad
        activa de APATE. Lanzar una excepcion tambien es valido para un fallo
        real de verificacion: la ruta de retorno lo registra y responde 401,
        mientras que `None` responde 403 — la distincion entre "no pude
        verificarte" y "te verifique y no estas dado de alta".
        """
        ...


def supports_redirect_login(provider: object) -> bool:
    """Indica si la aplicacion debe ofrecer el inicio por redireccion.

    Un unico lugar de decision, en vez de los tres `getattr` sueltos que
    tenia `apate.web`. Exige las dos cosas a la vez —el modo declarado y el
    contrato implementado— porque cada una responde algo distinto: el modo
    dice que el proveedor *quiere* ese camino, y el contrato dice que *puede*.
    Un proveedor que implementa los metodos pero declara `credentials` esta
    pidiendo que no se ofrezca el boton, y se respeta.
    """

    return (
        getattr(provider, "authentication_mode", "credentials") == "redirect"
        and isinstance(provider, RedirectIdentityProvider)
    )


class LocalIdentityProvider(IdentityProvider):
    """Usuarios locales persistidos en JSON con contraseñas hasheadas.

    Es la implementación local incluida. `has_identities()` y los
    métodos de gestión son deliberadamente extras de esta implementación,
    no del contrato de proveedor: autenticación y resolución siguen siendo
    las únicas operaciones que una integración externa debe implementar.
    """

    def __init__(self, path: Path):
        self._path = Path(path)

    def authenticate(self, display_name: str, password: str) -> Identity | None:
        """Autentica sin diferenciar usuario desconocido de clave inválida."""

        record = self._find_by_display_name(display_name)
        if record is None or not record["active"]:
            return None
        if not check_password_hash(record["password_hash"], password):
            return None
        return self._identity(record)

    def get(self, identity_id: str) -> Identity | None:
        """Resuelve solo identidades activas para invalidar sesiones bajas."""

        for record in self._records():
            if record["id"] == identity_id and record["active"]:
                return self._identity(record)
        return None

    def has_identities(self) -> bool:
        """Indica si ya existe algún usuario local, aun si fue desactivado.

        Una vez creado el primero, la aplicación no vuelve silenciosamente a
        modo abierto por desactivar el último: eso dejaría expuesta una
        instancia que su operador esperaba protegida.
        """

        return bool(self._records())

    def create(
        self,
        display_name: str,
        password: str,
        *,
        role: IdentityRole | str | None = None,
        team_id: str | None = None,
    ) -> Identity:
        """Crea un usuario local, sin guardar ni exponer la contraseña plana."""

        normalized_name = display_name.strip()
        if not normalized_name:
            raise ValueError(_("El nombre visible no puede estar vacío."))
        if not password:
            raise ValueError(_("La contraseña no puede estar vacía."))
        if self._find_by_display_name(normalized_name) is not None:
            raise ValueError(_("Ya existe una identidad con ese nombre visible."))

        assigned_role = IdentityRole(role) if role is not None else (
            IdentityRole.ADMINISTRATION if not self._records() else IdentityRole.OPERATION
        )
        normalized_team = team_id.strip() if team_id else None
        if assigned_role is not IdentityRole.ADMINISTRATION and not normalized_team:
            raise ValueError(_("Los usuarios de lectura u operación requieren un equipo."))
        record = {
            "id": str(uuid4()),
            "display_name": normalized_name,
            "active": True,
            "role": assigned_role.value,
            "team_id": normalized_team,
            "password_hash": generate_password_hash(password),
        }
        records = self._records()
        records.append(record)
        self._save(records)
        return self._identity(record)

    def list(self) -> list[Identity]:
        """Lista identidades sin incluir hashes ni otros secretos."""

        return [self._identity(record) for record in self._records()]

    def deactivate(self, identity_id: str) -> Identity:
        """Desactiva una identidad y conserva su registro para auditoría.

        No se puede desactivar el último administrador activo: eso
        bloquearía el retorno a un estado autenticable sin salida desde la
        consola, y la consola recupera acceso solo con operaciones sobre esa
        misma cuenta.
        """

        records = self._records()
        active_administrators = [
            record
            for record in records
            if record["active"] and str(record.get("role", IdentityRole.ADMINISTRATION.value)) == IdentityRole.ADMINISTRATION.value
        ]
        for record in records:
            if record["id"] == identity_id:
                if bool(record["active"]) and str(record.get("role", IdentityRole.ADMINISTRATION.value)) == IdentityRole.ADMINISTRATION.value:
                    if len(active_administrators) <= 1:
                        raise ValueError(_("No se puede desactivar al último administrador activo."))
                record["active"] = False
                self._save(records)
                return self._identity(record)
        raise KeyError(identity_id)

    def change_password(self, identity_id: str, password: str) -> Identity:
        """Actualiza la contraseña hasheada de una identidad existente."""

        if not password:
            raise ValueError(_("La contraseña no puede estar vacía."))

        records = self._records()
        for record in records:
            if record["id"] == identity_id:
                record["password_hash"] = generate_password_hash(password)
                # Invalida cualquier sesion abierta de esa persona: ver
                # Identity.credential_version.
                record["credential_version"] = int(record.get("credential_version", 0)) + 1
                self._save(records)
                return self._identity(record)
        raise KeyError(identity_id)

    def set_locale(self, identity_id: str, locale: str | None) -> Identity:
        """Persiste el idioma preferido de una identidad.

        Es un extra de esta implementacion, no del contrato de
        `IdentityProvider`: un proveedor externo (OIDC) no tiene por que
        saber guardar preferencias de interfaz, y la ruta que cambia el
        idioma lo consulta con `getattr` antes de llamarlo -- si no esta,
        la preferencia queda solo en la sesion. No toca
        `credential_version`: cambiar de idioma no es un evento de
        seguridad y no debe expulsar a nadie de su sesion.
        """

        records = self._records()
        for record in records:
            if record["id"] == identity_id:
                if locale:
                    record["locale"] = locale
                else:
                    record.pop("locale", None)
                self._save(records)
                return self._identity(record)
        raise KeyError(identity_id)

    def _records(self) -> list[dict[str, object]]:
        if not self._path.exists():
            return []
        document = json.loads(self._path.read_text(encoding="utf-8"))
        records = document.get("identities", [])
        if not isinstance(records, list):
            raise ValueError(_("El almacén de identidades tiene un formato inválido."))
        return records

    def _save(self, records: list[dict[str, object]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        write_text_atomically(self._path, json.dumps({"identities": records}, ensure_ascii=False, indent=2) + "\n")

    def _find_by_display_name(self, display_name: str) -> dict[str, object] | None:
        normalized_name = display_name.strip().casefold()
        for record in self._records():
            if str(record["display_name"]).casefold() == normalized_name:
                return record
        return None

    @staticmethod
    def _identity(record: dict[str, object]) -> Identity:
        return Identity(
            id=str(record["id"]),
            display_name=str(record["display_name"]),
            active=bool(record["active"]),
            role=IdentityRole(str(record.get("role", IdentityRole.ADMINISTRATION.value))),
            team_id=(str(record["team_id"]) if record.get("team_id") else None),
            credential_version=int(record.get("credential_version", 0)),
            locale=(str(record["locale"]) if record.get("locale") else None),
        )
