"""Procedencia del programa en ejecucion: version, commit y fuente correspondiente.

**Por que existe.** APATE se distribuye bajo AGPLv3, cuyo articulo 13 obliga
a quien ofrece el programa a traves de una red a darle a sus usuarios remotos
una oportunidad de recibir el *Corresponding Source*. Esa obligacion es de
**quien despliega**, no del autor original: si una organizacion modifica APATE
y lo expone a su equipo, el fuente que tiene que ofrecer es el suyo, no el de
este repositorio. Por eso la URL no esta hardcodeada, sino que sale de
`APATE_SOURCE_URL`.

**Que hace este modulo y que no.** Reune los tres datos que un aviso de
licencia honesto necesita -- que version corre, de que commit se construyo y
donde esta su fuente -- y los deja disponibles para la interfaz. No verifica
nada: no puede saber si quien despliega modifico el codigo, ni comprobar que
la URL declarada sirva realmente el fuente correspondiente. Declarar eso
correctamente es responsabilidad del operador, y `docs/instalacion-produccion.md`
se lo dice explicitamente.

**Sin URL declarada no se inventa una.** Una instalacion modificada debe
ofrecer su propio fuente correspondiente. Apuntar por defecto al repositorio
publico de referencia podria señalar otra version y aparentar cumplimiento.
Sin `APATE_SOURCE_URL`, `source_url` queda en `None` y la interfaz indica que
esta instalacion aun no declaro donde esta su fuente.

Capa 0: sin dependencias internas ni externas, igual que `apate.i18n`. La
interfaz lo consume, pero la informacion es del programa, no de la web.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

# `role` es texto visible en /about. Va con `lazy_gettext` y no `gettext` por
# la misma razon que `DeceptionPlugin.plugin_description`: la tupla se
# construye al importar el modulo, antes de que exista ninguna request, asi
# que una traduccion normal quedaria congelada en el idioma del arranque.
from .i18n import lazy_gettext

#: Identificador SPDX de la licencia bajo la que se distribuye APATE.
#: `-or-later` refleja la clausula "either version 3 ... or (at your option)
#: any later version" del encabezado oficial, no una eleccion propia.
LICENSE_SPDX = "AGPL-3.0-or-later"
# Nombre canonico de la FSF: no se traduce ni se localiza, igual que
# no se traduce "MIT" ni "Apache-2.0".
LICENSE_NAME = "GNU Affero General Public License v3.0 or later"
LICENSE_URL = "https://www.gnu.org/licenses/agpl-3.0.html"

_UNKNOWN_VERSION = "0.0.0+desconocida"


@dataclass(frozen=True)
class BuildInfo:
    """Que binario esta corriendo y donde esta su fuente correspondiente."""

    version: str
    commit: Optional[str]
    source_url: Optional[str]
    license_spdx: str = LICENSE_SPDX
    license_name: str = LICENSE_NAME
    license_url: str = LICENSE_URL

    @property
    def short_commit(self) -> Optional[str]:
        """Los primeros 12 caracteres, que es como se cita un commit."""

        return self.commit[:12] if self.commit else None

    @property
    def declares_source(self) -> bool:
        """`False` obliga a la interfaz a decir que falta declararla."""

        return bool(self.source_url)


def _version() -> str:
    """La version instalada del paquete, o un marcador explicito.

    `importlib.metadata` lee la distribucion instalada, que es la unica
    fuente correcta cuando la aplicacion corre desde una imagen: el
    `pyproject.toml` puede no estar presente.
    """

    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("apate")
    except Exception:  # PackageNotFoundError, o un backend de metadata roto
        return _UNKNOWN_VERSION


def _commit_from_environment() -> Optional[str]:
    """El commit que inyecta el build. Vacio o ausente cuentan como ausente."""

    value = (os.environ.get("APATE_BUILD_COMMIT") or "").strip()
    return value or None


def _commit_from_git() -> Optional[str]:
    """Ultimo recurso, solo util en un checkout de desarrollo.

    Se lee `.git/HEAD` a mano en vez de invocar `git`: no hay que asumir
    que el binario exista (la imagen de la demo no lo trae) ni pagar un
    subproceso en cada arranque. Cualquier forma inesperada del archivo
    devuelve `None` en lugar de romper el arranque de la aplicacion.
    """

    from pathlib import Path

    try:
        git = Path(__file__).resolve().parents[2] / ".git"
        if git.is_file():
            # Worktree: `.git` es un archivo `gitdir: <ruta>` que apunta al
            # directorio real. Es el caso normal de trabajo en este proyecto,
            # no una rareza -- sin esto, cualquier ejecucion desde un worktree
            # reportaria "sin commit" teniendo uno perfectamente legible.
            apuntador = git.read_text(encoding="utf-8").strip()
            if not apuntador.startswith("gitdir:"):
                return None
            git = Path(apuntador.split(":", 1)[1].strip())
        head = git / "HEAD"
        if not head.is_file():
            return None
        contenido = head.read_text(encoding="utf-8").strip()
        if not contenido.startswith("ref:"):
            # HEAD desacoplado: el propio archivo ya tiene el sha.
            return contenido or None
        objetivo = contenido.split(" ", 1)[1].strip()
        # En un worktree las refs compartidas viven en el directorio comun,
        # no en el del worktree; `commondir` dice cual es.
        comun = git
        archivo_comun = git / "commondir"
        if archivo_comun.is_file():
            comun = (git / archivo_comun.read_text(encoding="utf-8").strip()).resolve()
        for base in (git, comun):
            referencia = base / objetivo
            if referencia.is_file():
                return referencia.read_text(encoding="utf-8").strip() or None
        # Referencia empaquetada: `git gc` mueve las refs a packed-refs.
        empaquetadas = comun / "packed-refs"
        if not empaquetadas.is_file():
            return None
        for linea in empaquetadas.read_text(encoding="utf-8").splitlines():
            if linea.startswith("#") or not linea.strip():
                continue
            partes = linea.split(" ", 1)
            if len(partes) == 2 and partes[1].strip() == objetivo:
                return partes[0].strip() or None
        return None
    except Exception:
        return None


@dataclass(frozen=True)
class ThirdPartyComponent:
    """Un componente de terceros que viaja en la misma distribucion.

    Sin `version`: la de una dependencia la fija la instalacion, no este
    inventario, y escribirla aca la dejaria desactualizada en cuanto
    alguien actualice un paquete. `installed_version()` la resuelve al
    vuelo cuando hace falta mostrarla.
    """

    name: str
    license_spdx: str
    role: str
    distribution: Optional[str] = None
    url: Optional[str] = None
    vendored: bool = False

    def installed_version(self) -> Optional[str]:
        """La version realmente instalada, o `None` si no aplica.

        Los componentes vendorizados y los que se cargan por CDN no son
        distribuciones de Python: para esos no hay nada que resolver.
        """

        if not self.distribution:
            return None
        try:
            from importlib.metadata import version

            return version(self.distribution)
        except Exception:
            return None


#: Inventario de licencias de terceros, base del archivo `NOTICE`.
#:
#: `tests/test_provenance.py` verifica que `NOTICE` mencione cada entrada,
#: para que las dos no puedan divergir -- mismo criterio que los tests de
#: sincronizacion del catalogo de traduccion (`tests/test_i18n.py`).
#:
#: **La unica copyleft de la lista es fpdf2 (LGPL-3.0-only)**, y esta
#: senialada a proposito: es la primera que mira un area legal. LGPLv3 es
#: compatible con AGPLv3 y se usa como libreria, sin modificarla.
THIRD_PARTY_COMPONENTS: tuple[ThirdPartyComponent, ...] = (
    # Vendorizados: viajan como codigo fuente dentro de esta distribucion.
    ThirdPartyComponent(
        "DOLOS-T", "AGPL-3.0-or-later", lazy_gettext("Capacidad de decoys de red y host"),
        url="https://github.com/Base4Security/DOLOS-T", vendored=True,
    ),
    ThirdPartyComponent(
        "BUDA", "AGPL-3.0-or-later", lazy_gettext("Capacidad de comportamiento de usuario simulado"),
        url="https://github.com/Base4Security/BUDA", vendored=True,
    ),
    ThirdPartyComponent(
        "Cyber Deception Playground", "MIT", lazy_gettext("Entorno de ejercicio (stack Docker)"),
        url="https://github.com/Base4Security/cyberdeception-playground", vendored=True,
    ),
    # Dependencias de ejecucion.
    ThirdPartyComponent("Flask", "BSD-3-Clause", lazy_gettext("Servidor web"), "Flask"),
    ThirdPartyComponent("Flask-SocketIO", "MIT", lazy_gettext("Notificaciones en vivo"), "Flask-SocketIO"),
    ThirdPartyComponent("Flask-SQLAlchemy", "BSD-3-Clause", lazy_gettext("Persistencia de identidades simuladas"), "Flask-SQLAlchemy"),
    ThirdPartyComponent("Flask-Babel", "BSD-3-Clause", lazy_gettext("Catálogos de traducción"), "Flask-Babel"),
    ThirdPartyComponent("PyYAML", "MIT", lazy_gettext("Lectura del YAML de reglas"), "PyYAML"),
    ThirdPartyComponent("fpdf2", "LGPL-3.0-only", lazy_gettext("Exportación de informes a PDF"), "fpdf2"),
    ThirdPartyComponent("pypdf", "BSD-3-Clause", lazy_gettext("Lectura de informes de CTI en PDF"), "pypdf"),
    ThirdPartyComponent("docker", "Apache-2.0", lazy_gettext("Control del runtime de contenedores"), "docker"),
    ThirdPartyComponent("requests", "Apache-2.0", lazy_gettext("Llamadas HTTP salientes"), "requests"),
    ThirdPartyComponent("openai", "Apache-2.0", lazy_gettext("Generación de contenido asistida"), "openai"),
    ThirdPartyComponent("python-dotenv", "BSD-3-Clause", lazy_gettext("Carga de variables de entorno"), "python-dotenv"),
    ThirdPartyComponent("python-evtx", "Apache-2.0", lazy_gettext("Lectura de registros de eventos de Windows"), "python-evtx"),
    ThirdPartyComponent("pywinrm", "MIT", lazy_gettext("Ejecución remota vía WinRM"), "pywinrm"),
    ThirdPartyComponent("cryptography", "Apache-2.0 OR BSD-3-Clause", lazy_gettext("Cifrado de secretos en reposo"), "cryptography"),
    ThirdPartyComponent("PyJWT", "MIT", lazy_gettext("Validación de tokens OIDC"), "PyJWT"),
    # Cargados por CDN desde el navegador: no viajan en la distribucion,
    # pero el usuario los recibe igual al abrir la interfaz.
    ThirdPartyComponent(
        "CodeMirror 5", "MIT", lazy_gettext("Editor de reglas con resaltado (se carga desde CDN)"),
        url="https://codemirror.net/5/",
    ),
    ThirdPartyComponent(
        "Socket.IO", "MIT", lazy_gettext("Cliente de notificaciones en vivo (se carga desde CDN)"),
        url="https://socket.io/",
    ),
)


@lru_cache(maxsize=1)
def build_info() -> BuildInfo:
    """Resuelve la procedencia una sola vez por proceso.

    Cacheado a proposito: los tres valores se fijan al desplegar y no
    cambian mientras el proceso vive. Un test que necesite variarlos tiene
    que llamar a `build_info.cache_clear()`, igual que haria con cualquier
    otro valor memoizado.
    """

    return BuildInfo(
        version=_version(),
        commit=_commit_from_environment() or _commit_from_git(),
        source_url=(os.environ.get("APATE_SOURCE_URL") or "").strip() or None,
    )
