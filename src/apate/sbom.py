"""Inventario de materiales de software (SBOM) en formato CycloneDX 1.6.

**Por que existe.** `NOTICE` y `/about` responden una pregunta legal: que
licencias viajan en esta distribucion y donde esta el fuente correspondiente.
Un SBOM responde una pregunta distinta, que es la que hace un area de
seguridad del lado del cliente: *que versiones exactas corren, para poder
cruzarlas contra los CVE publicados*. Son dos documentos porque son dos
preguntas; comparten la misma fuente de verdad, `THIRD_PARTY_COMPONENTS`.

**La version se resuelve al generar, no se escribe a mano.** Es la misma
decision que ya toma `ThirdPartyComponent`, y por la misma razon: una version
escrita en el inventario queda vieja en cuanto alguien actualiza un paquete, y
un SBOM con versiones viejas es peor que ninguno -- el escaner del cliente
concluye que no hay vulnerabilidades porque esta mirando numeros que no
corresponden a lo que corre. Por eso este modulo describe **la instalacion
desde la que se lo llama**, no el repositorio en abstracto.

**Y por eso mismo hay que generarlo en la maquina correcta.** El SBOM de un
checkout de desarrollo no es el de la imagen que se le entrega al cliente. Lo
correcto es generarlo como paso del build, contra el entorno ya instalado:

    python -m apate.sbom > apate.cdx.json

**Salida determinista, a proposito.** Sin marca de tiempo aleatoria y con un
`serialNumber` derivado de la version y el commit: dos SBOM del mismo build
son byte a byte iguales, asi que se pueden comparar, firmar y versionar. Un
timestamp distinto en cada corrida haria que cualquier diff mienta. Quien
necesite la fecha puede pasarla explicitamente a `build_document()`.

Capa 0 como `apate.provenance`, del que depende: ninguna dependencia externa.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Iterable, Optional

from .provenance import (
    LICENSE_SPDX,
    THIRD_PARTY_COMPONENTS,
    BuildInfo,
    ThirdPartyComponent,
    build_info,
)

#: Version del esquema que se emite. No es la version del documento (esa es
#: `version`, que cuenta revisiones del mismo SBOM), sino la del formato.
CYCLONEDX_SPEC_VERSION = "1.6"

#: Tipo de medio registrado en IANA para CycloneDX en JSON. Lo que espera un
#: escaner que consume el documento por HTTP.
CYCLONEDX_MEDIA_TYPE = "application/vnd.cyclonedx+json"

#: Prefijo de las propiedades propias. CycloneDX pide que toda extension vaya
#: en `properties` con un nombre de espacio propio, justamente para que un
#: consumidor generico pueda ignorarlas sin romperse.
_PROPIEDAD = "apate:"

# Un identificador SPDX simple ("MIT") va como `license.id`; una expresion
# ("Apache-2.0 OR BSD-3-Clause") va como `expression`. Meter una expresion en
# el campo `id` es el error tipico: valida contra el esquema pero el escaner
# no la reconoce como licencia conocida y la reporta como desconocida.
_OPERADORES_SPDX = re.compile(r"\s(?:OR|AND|WITH)\s")


def _slug(texto: str) -> str:
    """Identificador estable para `bom-ref`, derivado del nombre."""

    return re.sub(r"[^a-z0-9]+", "-", texto.lower()).strip("-")


def _nombre_pypi(distribucion: str) -> str:
    """Normaliza el nombre como exige el tipo `pypi` de la especificacion purl."""

    return re.sub(r"[-_.]+", "-", distribucion).lower()


def _purl(componente: ThirdPartyComponent, version: Optional[str]) -> Optional[str]:
    """El identificador de paquete, o `None` si el componente no es uno.

    El purl es lo que hace util al SBOM: es la clave con la que un escaner
    busca en las bases de vulnerabilidades. Un componente sin purl se puede
    leer pero no se puede cruzar automaticamente, asi que vale la pena
    emitirlo siempre que exista una coordenada real.
    """

    if componente.distribution:
        purl = f"pkg:pypi/{_nombre_pypi(componente.distribution)}"
        return f"{purl}@{version}" if version else purl

    # Vendorizado desde GitHub: hay coordenada de repositorio aunque no haya
    # distribucion de Python. Sin version, porque la copia esta congelada al
    # momento de vendorizarla y no se corresponde con ningun tag del origen
    # (ver "Atribucion" en README.md).
    if componente.vendored and componente.url:
        coincidencia = re.match(
            r"https?://github\.com/([^/]+)/([^/#?]+)", componente.url.rstrip("/")
        )
        if coincidencia:
            espacio, nombre = coincidencia.group(1).lower(), coincidencia.group(2).lower()
            return f"pkg:github/{espacio}/{nombre}"

    # Los de CDN no son paquetes: el navegador los recibe de un tercero que
    # este proyecto no empaqueta. Se listan igual, sin coordenada.
    return None


def _licencias(spdx: str) -> list[dict[str, Any]]:
    """Traduce el identificador SPDX a la forma que pide CycloneDX."""

    if _OPERADORES_SPDX.search(spdx):
        return [{"expression": spdx}]
    return [{"license": {"id": spdx}}]


def _entrega(componente: ThirdPartyComponent) -> str:
    """Como llega el componente al usuario final. Es la distincion de `NOTICE`."""

    if componente.vendored:
        return "vendorizado"
    if componente.distribution:
        return "pypi"
    return "cdn"


def _descripcion(componente: ThirdPartyComponent) -> str:
    """El rol en texto fuente, no traducido.

    `role` es un `LazyString` porque en `/about` tiene que seguir el idioma
    del operador. Aca no: el SBOM es un documento de maquina, y que su
    contenido cambie segun quien lo pidio lo volveria imposible de comparar.
    """

    return getattr(componente.role, "source_text", None) or str(componente.role)


def _componente(componente: ThirdPartyComponent) -> dict[str, Any]:
    version = componente.installed_version()
    entrada: dict[str, Any] = {
        "bom-ref": f"componente/{_slug(componente.name)}",
        "type": "library",
        "name": componente.name,
        "description": _descripcion(componente),
        "licenses": _licencias(componente.license_spdx),
        "properties": [{"name": f"{_PROPIEDAD}entrega", "value": _entrega(componente)}],
    }
    if version:
        entrada["version"] = version
    purl = _purl(componente, version)
    if purl:
        entrada["purl"] = purl
    if componente.url:
        entrada["externalReferences"] = [
            {"type": "vcs" if componente.vendored else "website", "url": componente.url}
        ]
    return entrada


def _serial_number(build: BuildInfo) -> str:
    """URN estable para este build.

    Derivado y no aleatorio para que el documento sea reproducible. Dos builds
    distintos del mismo commit comparten serial, que es exactamente lo que se
    quiere: identifican al mismo software, no a la corrida que genero el
    archivo.
    """

    semilla = f"urn:apate:sbom:{build.version}:{build.commit or 'sin-commit'}"
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, semilla)}"


def build_document(
    componentes: Iterable[ThirdPartyComponent] = THIRD_PARTY_COMPONENTS,
    build: Optional[BuildInfo] = None,
    timestamp: Optional[str] = None,
) -> dict[str, Any]:
    """Arma el documento CycloneDX de la instalacion actual.

    `timestamp` queda fuera salvo que se lo pase: ver el docstring del modulo.
    """

    build = build or build_info()

    propiedades: list[dict[str, str]] = []
    if build.commit:
        propiedades.append({"name": f"{_PROPIEDAD}build:commit", "value": build.commit})

    # El fuente correspondiente que exige el articulo 13 de la AGPLv3 tiene
    # lugar propio en CycloneDX: una referencia externa de tipo
    # `distribution-source`. Que este dato viaje en el SBOM y no solo en
    # `/about` es util justamente para el area legal del cliente, que suele
    # recibir el SBOM y no visitar la aplicacion.
    referencias: list[dict[str, str]] = []
    if build.source_url:
        referencias.append({"type": "distribution-source", "url": build.source_url})

    aplicacion: dict[str, Any] = {
        "bom-ref": "componente/apate",
        "type": "application",
        "name": "apate",
        "version": build.version,
        "description": "Capa de orquestacion y decision para operaciones de ciberengano.",
        "licenses": _licencias(LICENSE_SPDX),
    }
    if propiedades:
        aplicacion["properties"] = propiedades
    if referencias:
        aplicacion["externalReferences"] = referencias

    metadata: dict[str, Any] = {"component": aplicacion}
    if timestamp:
        metadata["timestamp"] = timestamp

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": _serial_number(build),
        "version": 1,
        "metadata": metadata,
        "components": [_componente(c) for c in componentes],
    }


def build_json(**kwargs: Any) -> str:
    """El documento serializado, con la forma estable que espera un diff."""

    return json.dumps(build_document(**kwargs), indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    """`python -m apate.sbom` -- escribe el SBOM en la salida estandar."""

    import sys

    sys.stdout.write(build_json())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
