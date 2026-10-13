"""Configuracion del modo Playground (M5) - documento de diseno,
seccion 6.2.

**Corregido post-M14 (vendorizacion, ver docs/roadmap.md):** hasta
entonces, el repositorio Cyber Deception Playground (frontend/backend
Node.js, MySQL, honeypot SSH, contenedor atacante, stack Elastic) vivia
aparte de APATE y no se vendorizaba -- exigia un checkout local
obligatorio via `APATE_PLAYGROUND_PATH`. Ahora un subconjunto funcional
de ese repo (`docker-compose.yml`, Dockerfiles, scripts de cada
servicio -- MIT license, ver `playground-stack/LICENSE` y "Atribucion"
en README.md) vive vendorizado en `playground-stack/`, en la raiz del
repo (no bajo `src/`, porque no es codigo Python que se importa: sigue
siendo un stack docker-compose invocado por subprocess, ver
lifecycle.py). `APATE_PLAYGROUND_PATH` sigue existiendo para quien
prefiera apuntar a otro checkout (ej. una version mas nueva del repo
real) -- si no esta definida, se usa esta copia vendorizada por
defecto en vez de fallar pidiendo la variable.

**Docker en si sigue siendo un requisito de todos modos** -- vendorizar
los archivos del stack no elimina la necesidad de tener Docker
instalado y corriendo para efectivamente levantarlo; eso lo sigue
validando lifecycle.py recien al invocar un comando real, para que la
configuracion en si sea testeable sin Docker.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

from ..i18n import gettext as _
from .exceptions import PlaygroundConfigError

# Variable de entorno que apunta a un checkout local del repositorio
# Cyber Deception Playground, para quien quiera usar uno distinto del
# vendorizado en playground-stack/ (ej. una version mas nueva). Se
# elige una variable de entorno (en vez de, por ejemplo, un valor fijo
# en pyproject.toml) porque esa ruta puede variar por maquina.
ENV_VAR = "APATE_PLAYGROUND_PATH"

# playground-stack/ vive en la raiz del repo, no bajo src/ (no es un
# paquete Python) -- parents[3] desde este archivo
# (src/apate/playground/config.py) es la raiz del repo:
# playground -> apate -> src -> raiz.
_SOURCE_STACK = Path(__file__).resolve().parents[3] / "playground-stack"
_PACKAGED_STACK = Path(__file__).resolve().parent / "_stack"
# El checkout conserva su ruta histórica; la wheel incluye una copia propia.
VENDORED_PLAYGROUND_PATH = _SOURCE_STACK if _SOURCE_STACK.is_dir() else _PACKAGED_STACK

_DEFAULT_COMPOSE_COMMAND = ("docker", "compose")
_COMPOSE_FILE_CANDIDATES = ("docker-compose.yml", "docker-compose.yaml")


@dataclass(frozen=True)
class PlaygroundConfig:
    """Ruta a un checkout local del repositorio Playground, mas el
    comando de docker compose a invocar sobre ella. No valida por si
    sola que Docker este disponible: eso es responsabilidad de
    lifecycle.py al ejecutar un comando real."""

    path: Path
    compose_command: Sequence[str] = _DEFAULT_COMPOSE_COMMAND

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "PlaygroundConfig":
        """Construye la configuracion a partir de la variable de
        entorno APATE_PLAYGROUND_PATH -- si no esta definida, usa por
        defecto la copia vendorizada en `playground-stack/` (ver
        docstring del modulo) en vez de fallar pidiendola. Lanza
        PlaygroundConfigError igual si, definida o no, la ruta
        resultante no apunta a un directorio existente con un
        docker-compose.yml/.yaml -- fallar aca, antes de intentar
        invocar Docker, da un mensaje claro en vez de un error crudo
        de subprocess."""

        env = env if env is not None else os.environ
        raw_path = env.get(ENV_VAR) or VENDORED_PLAYGROUND_PATH
        return cls.from_path(raw_path)

    @classmethod
    def from_path(cls, raw_path: str | os.PathLike[str]) -> "PlaygroundConfig":
        path = Path(raw_path)
        if not path.is_dir():
            raise PlaygroundConfigError(
                _(
                    "La ruta configurada para el Playground no es un directorio existente: "
                    "'%(path)s'.",
                    path=path,
                )
            )
        if not any((path / candidate).is_file() for candidate in _COMPOSE_FILE_CANDIDATES):
            raise PlaygroundConfigError(
                _(
                    "'%(path)s' no contiene ningun %(candidates)s: no parece ser un checkout "
                    "del repositorio Cyber Deception Playground.",
                    path=path,
                    candidates="/".join(_COMPOSE_FILE_CANDIDATES),
                )
            )
        return cls(path=path)
