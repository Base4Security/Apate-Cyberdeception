"""Donde escriben las herramientas vendorizadas su estado de ejecucion.

**Por que existe.** DOLOS-T y BUDA guardaban su estado con rutas **relativas
al directorio de trabajo**: `logs/`, `buda.db`, `docker_client_config/`,
`context.json`, `config_llm.json`. En el checkout de desarrollo eso coincide
con la raiz del repositorio y no se nota; en una instalacion real el directorio
de trabajo lo decide quien arranca el proceso, y dejo tres modos de falla que
solo aparecen en la maquina de otro:

* Un `gunicorn` bajo systemd sin `WorkingDirectory` arranca en `/`, y la
  primera escritura muere con `PermissionError` -- en el caso de `logs/`, en el
  **import**, antes de que exista la aplicacion.
* Con un directorio escribible pero efimero, el estado se pierde en la proxima
  reinstalacion mientras las referencias a el sobreviven en `APATE_DATA_DIR`.
* Y con dos instalaciones en la misma maquina, las dos escriben en el mismo
  lugar segun desde donde se las haya arrancado.

**La regla.** Todo estado persistente vive bajo `APATE_DATA_DIR`, que es el
directorio que el operador ya declara y ya monta como volumen. Este modulo es
el unico lugar que resuelve esa ruta, para que no vuelva a haber cinco
convenciones distintas.

**Y por que el directorio de trabajo sigue siendo el respaldo.** `src/DOLOST/`
y `src/BUDA/` son copias congeladas de proyectos que tambien corren solos. Si
no hay `APATE_DATA_DIR` -- que es el caso de esos proyectos fuera de APATE --
se conserva exactamente el comportamiento anterior. La correccion no los
rompe; les da un lugar mejor cuando APATE se los ofrece.

**La variable se exporta al entorno, no solo a la configuracion.** `create_app()`
la publica con `os.environ` porque el codigo vendorizado no tiene forma de leer
`app.config`: no conoce a Flask ni a APATE. Es un puente deliberado y esta
documentado como tal.
"""

from __future__ import annotations

import os
from pathlib import Path

#: Nombre de la variable. La misma que ya usa el resto de APATE.
VARIABLE = "APATE_DATA_DIR"


def runtime_dir() -> Path:
    """El directorio de estado, o el de trabajo si no se declaro ninguno."""

    declarado = (os.environ.get(VARIABLE) or "").strip()
    return Path(declarado) if declarado else Path.cwd()


def runtime_path(*partes: str) -> Path:
    """Una ruta dentro del directorio de estado. No crea nada."""

    return runtime_dir().joinpath(*partes)


def ensure_runtime_path(*partes: str) -> Path:
    """Igual, pero se asegura de que el directorio contenedor exista.

    Devuelve la ruta. Deja propagar el error de permisos a proposito: quien
    llama decide si eso es fatal (una base de datos) o degradable (un log).
    """

    destino = runtime_path(*partes)
    destino.parent.mkdir(parents=True, exist_ok=True)
    return destino


def publish(data_dir: Path | str) -> None:
    """Publica el directorio en el entorno, para el codigo vendorizado.

    Se llama temprano en `create_app()`. Sin esto, una instalacion que fija
    `APATE_DATA_DIR` por configuracion y no por entorno -- los tests, y
    cualquier uso programatico de `create_app()` -- dejaria a DOLOS-T y BUDA
    escribiendo otra vez en el directorio de trabajo.
    """

    os.environ[VARIABLE] = str(Path(data_dir).resolve())
