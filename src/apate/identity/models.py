"""Tipos de dominio para identidad de operador y alcance de equipo."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IdentityRole(str, Enum):
    """Los tres roles operativos fijos de APATE.

    No son permisos configurables: representan lectura, ejecución de
    operaciones y administración de la instalación.
    """

    READ = "read"
    OPERATION = "operation"
    ADMINISTRATION = "administration"


@dataclass(frozen=True)
class Identity:
    """Identidad autenticable y mostrable a un operador.

    `display_name` se usa también como identificador de inicio de sesión en
    el proveedor local. ``team_id`` es opcional para conservar identidades
    históricas; ``role`` tiene un default administrativo para que una
    instalación existente no quede bloqueada al actualizar.
    """

    id: str
    display_name: str
    active: bool = True
    role: IdentityRole = IdentityRole.ADMINISTRATION
    team_id: str | None = None
    credential_version: int = 0
    """Cuántas veces cambió la credencial de esta identidad.

    La sesión guarda la versión que tenía al iniciarse, y cada pedido la
    compara: si no coincide, la sesión se descarta. Es lo que hace que
    resetear la contraseña de alguien **expulse** a quien ya estaba dentro,
    en vez de solo impedirle volver a entrar -- el caso real es una cuenta
    comprometida, y ahí bloquear el próximo login no sirve de nada.

    Arranca en 0 para que las identidades ya persistidas (sin este campo en
    el JSON) y los proveedores que no lo usan sigan funcionando igual.
    """

    locale: str | None = None
    """Idioma preferido de esta persona, o ``None`` para heredar el de la
    instalacion.

    La preferencia es por usuario y no por instalacion: el equipo puede
    trabajar en espanol mientras la demo comercial se muestra en ingles,
    sin que uno pise al otro. Es opcional para que las identidades ya
    persistidas (sin este campo en el JSON) sigan cargando igual, y un
    proveedor externo que no sepa guardarlo simplemente no lo devuelve --
    la preferencia vive entonces solo en la sesion.
    """
