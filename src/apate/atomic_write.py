"""Escritura de archivos que no puede dejar el contenido a medias.

**El modo de falla que esto cierra.** `Path.write_text()` **trunca el archivo
antes de escribir**. Si el proceso muere, el servicio se reinicia o el disco se
llena entre esas dos cosas, lo que queda en el disco es un archivo vacio o un
JSON cortado -- no el contenido viejo. En los repositorios que guardan *la
lista completa* de una operacion (acciones de operador, incidentes,
clasificaciones TLP) eso no pierde un registro: pierde el historial entero de
esa operacion de un saque.

**Como se evita.** Se escribe en un temporal del **mismo directorio** -- tiene
que ser el mismo sistema de archivos para que el reemplazo sea atomico --, se
fuerza el volcado a disco, y recien ahi se reemplaza el destino con
`os.replace()`, que es atomico tanto en POSIX como en Windows. En cualquier
momento del proceso, quien lea el destino ve la version vieja completa o la
nueva completa, nunca una mezcla.

**El `fsync` no es decorativo.** Sin el, el reemplazo puede llegar al disco
antes que los datos que renombra: el sistema queda con el nombre nuevo
apuntando a contenido no escrito, que es exactamente el archivo vacio que se
queria evitar. Es la trampa clasica de "renombre atomico" mal implementado.

Este patron ya estaba bien resuelto en `apate.deployment` (el codigo mas
nuevo del proyecto). Este modulo lo hace comun para que los repositorios
anteriores dejen de ser la excepcion.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def write_text_atomically(
    path: Path | str,
    text: str,
    *,
    encoding: str = "utf-8",
    mode: int | None = None,
) -> None:
    """Escribe `text` en `path` sin dejarlo nunca a medias."""

    destino = Path(path)
    destino.parent.mkdir(parents=True, exist_ok=True)
    # El PID en el nombre evita que dos procesos que escriben el mismo archivo
    # se pisen el temporal. No los sincroniza -- para eso haria falta un lock,
    # que es otro problema -- pero impide que uno reemplace con el contenido
    # a medio escribir del otro.
    temporal = destino.with_name(f"{destino.name}.{os.getpid()}.tmp")
    try:
        with open(temporal, "w", encoding=encoding, newline="\n") as archivo:
            archivo.write(text)
            archivo.flush()
            os.fsync(archivo.fileno())
        if mode is not None:
            try:
                os.chmod(temporal, mode)
            except OSError:
                # Algunos volúmenes y Windows no ofrecen permisos POSIX.
                pass
        os.replace(temporal, destino)
        _sincronizar_directorio(destino.parent)
    except BaseException:
        # Incluye KeyboardInterrupt y SystemExit a proposito: un temporal
        # huerfano en el directorio de datos confunde a cualquiera que mire.
        try:
            temporal.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def write_json_atomically(
    path: Path | str,
    data: Any,
    *,
    indent: int = 2,
    mode: int | None = None,
) -> None:
    """El caso comun: un JSON legible, con acentos sin escapar."""

    write_text_atomically(
        path,
        json.dumps(data, indent=indent, ensure_ascii=False),
        mode=mode,
    )


def _sincronizar_directorio(directorio: Path) -> None:
    """Hace durable la entrada de directorio que creo `os.replace()`.

    Silencioso si el sistema no lo permite: Windows no deja abrir un
    directorio como archivo, y ahi `os.replace()` ya es atomico por si mismo.
    """

    try:
        descriptor = os.open(directorio, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)
