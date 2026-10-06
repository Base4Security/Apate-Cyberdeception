"""Con que version de formato se escribio este directorio de datos.

**Por que hace falta un numero.** Los deserializadores usan `.get()` con
valores por defecto, asi que **agregar** un campo es seguro y una instalacion
vieja se sigue leyendo. Lo que no se puede detectar sin un sello es todo lo
demas:

* **Renombrar** un campo pierde el dato en silencio: el lector ignora la clave
  vieja, el primer `save()` reescribe el documento completo sin ella, y nadie
  se entera.
* **Cambiar el valor de un enum** rompe la lectura de golpe, porque los enums
  se construyen estrictos.
* **Cambiar un tipo** es peor que silencioso: `list(data.get(...))` sobre un
  texto lo convierte en una lista de caracteres.

En los tres casos el codigo no puede saber con que version se escribio lo que
esta leyendo, y quien mira el directorio de datos tampoco.

**Por que el sello es del directorio y no de cada documento.** Porque varios
documentos de APATE son **listas** en la raiz (`operator_actions`,
`incidents`, `tlp_classifications`, telemetria), y una lista no tiene donde
llevar una clave. Meterlas en un sobre `{"_schema": 1, "items": [...]}`
obligaria a cambiar cada lector y cada archivo ya escrito, a cambio de una
granularidad que nadie necesita: el directorio de datos es lo que se copia,
se restaura y se actualiza **como una unidad**. La pregunta real nunca es "de
que version es este archivo" sino "de que version es esta instalacion".

**Que NO es esto.** No es un motor de migraciones. Es el dato que cualquier
migracion va a necesitar, puesto antes de que haga falta -- porque ponerlo
despues significa que ya hay datos en el mundo sin el, y esa primera
migracion es justamente la que no se puede escribir.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Version del formato de los documentos JSON que escribe APATE.
#:
#: Se sube cuando un cambio **no** es compatible hacia atras: renombrar o
#: borrar un campo, cambiar un tipo, o cambiar el valor de un enum persistido.
#: Agregar un campo con default no la sube, porque no rompe nada.
SCHEMA_VERSION = 1

#: Version de los esquemas SQLite, en `PRAGMA user_version`. Va aparte: son
#: formatos distintos y evolucionan por su cuenta.
SQLITE_SCHEMA_VERSION = 1

#: El archivo que lleva el sello, dentro del directorio de datos.
ARCHIVO = ".apate-schema.json"


class SchemaTooNewError(RuntimeError):
    """Los datos vienen de una version mas nueva que la que corre.

    Es el caso de un downgrade, o de dos instalaciones compartiendo volumen.
    Se falla en vez de leer a medias: lo que sigue despues de leer es un
    `save()` que reescribe el documento entero en el formato viejo, o sea que
    continuar seria destruir datos, no solo malinterpretarlos.
    """


class SchemaInvalidError(RuntimeError):
    """El sello existe, pero no puede interpretarse de forma segura."""


class SchemaMigrationRequiredError(RuntimeError):
    """Un formato anterior necesita una migración explícita y respaldada."""


def read_version(data_dir: Path | str) -> int:
    """La version sellada, o 0 si el directorio es anterior a este sello."""

    archivo = Path(data_dir) / ARCHIVO
    if not archivo.exists():
        return 0
    try:
        documento = json.loads(archivo.read_text(encoding="utf-8"))
        valor = documento["schema_version"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SchemaInvalidError("El sello de esquema no es válido; restaurá una copia verificada.") from exc
    if type(valor) is not int or valor < 1:
        raise SchemaInvalidError("El sello de esquema no es válido; restaurá una copia verificada.")
    return valor


def write_version(data_dir: Path | str, version: int = SCHEMA_VERSION) -> None:
    """Sella el directorio. Atomico, como todo lo demas que escribe APATE."""

    from .atomic_write import write_json_atomically

    write_json_atomically(Path(data_dir) / ARCHIVO, {"schema_version": version})


def ensure_compatible(data_dir: Path | str) -> int:
    """Verifica el sello al arrancar y lo pone si falta. Devuelve la version.

    * **Mas nuevo que esta version**: se levanta `SchemaTooNewError`. Arrancar
      igual terminaria reescribiendo los documentos en un formato viejo.
    * **Sin sello**: se adopta únicamente cuando la versión actual es 1,
      porque el formato anterior al sello es exactamente ese formato.
    * **Más viejo o ilegible**: se detiene antes de escribir. Un cambio de
      formato futuro necesita una migración explícita y una copia verificada.
    """

    encontrada = read_version(data_dir)
    if encontrada > SCHEMA_VERSION:
        raise SchemaTooNewError(
            f"El directorio de datos ({data_dir}) fue escrito con la version de formato "
            f"{encontrada}, y esta instalacion entiende hasta la {SCHEMA_VERSION}. "
            "Actualiza APATE, o apunta APATE_DATA_DIR a un directorio de esta version."
        )
    if encontrada == 0 and SCHEMA_VERSION == 1:
        write_version(data_dir)
    elif encontrada < SCHEMA_VERSION:
        raise SchemaMigrationRequiredError(
            f"El directorio de datos usa el formato {encontrada} y esta instalación requiere "
            f"el {SCHEMA_VERSION}. Respaldá APATE_DATA_DIR y ejecutá una migración explícita."
        )
    return encontrada


def apply_sqlite_version(connection) -> int:
    """Sella una base SQLite y devuelve la version que tenia antes.

    `PRAGMA user_version` es un entero que SQLite guarda en la cabecera del
    archivo justamente para esto, y que no ocupa ninguna tabla. Los
    `ALTER TABLE` que ya hay en el proyecto resuelven columnas faltantes pero
    no pueden ver un cambio de significado: el sello si.
    """

    anterior = connection.execute("PRAGMA user_version").fetchone()[0]
    if anterior > SQLITE_SCHEMA_VERSION:
        raise SchemaTooNewError(
            f"Esta base fue escrita con la version de esquema {anterior}, y esta "
            f"instalacion entiende hasta la {SQLITE_SCHEMA_VERSION}."
        )
    if anterior == 0 and SQLITE_SCHEMA_VERSION == 1:
        connection.execute(f"PRAGMA user_version = {SQLITE_SCHEMA_VERSION}")
    elif anterior < SQLITE_SCHEMA_VERSION:
        raise SchemaMigrationRequiredError(
            f"La base SQLite usa el esquema {anterior} y esta instalación requiere "
            f"el {SQLITE_SCHEMA_VERSION}; falta una migración explícita."
        )
    return anterior
