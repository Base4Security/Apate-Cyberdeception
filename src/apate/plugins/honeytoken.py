"""Plugin de honeytokens/breadcrumbs (M7) - superficie de datos,
documento de diseno, seccion 4.1 y 4.4.

Primer plugin *no simulado* del roadmap: no depende de DOLOS-T ni de
BUDA (a diferencia de esas dos, que se integran recien en M8), se
construye desde cero implementando la misma interfaz de M2
(deploy()/rotate()/retire()) que ya usa MockHoneypotPlugin, pero
opera sobre el sistema de archivos en lugar de contenedores o WinRM:
coloca archivos senuelo con contenido plausible (credenciales o
connection strings ficticias) en rutas configuradas, y expone
check_access() para detectar cuando alguien los toco.

Deteccion de acceso -- decision de diseno explicita (seccion 1 del
diseno, filosofia minimalista): se eligio polling sobre
os.stat().st_atime/st_mtime, sin ninguna dependencia nueva (nada de
`watchdog` ni inotify/ReadDirectoryChangesW), porque alcanza para el
caso de uso ("¿alguien toco este archivo?") y mantiene el nucleo del
proyecto sin dependencias mas alla de las ya justificadas por hito. El
trade-off frente a `watchdog` es real y se documenta a proposito en
vez de asumir que el polling funciona siempre:

- **st_atime no es confiable en todos los entornos.** Si el
  filesystem esta montado con `noatime` (comun en servidores Linux por
  rendimiento), una lectura NO actualiza st_atime y check_access() no
  la va a detectar -- es una limitacion conocida, no un bug. Con el
  default de Linux (`relatime`), la primera lectura despues de
  deploy()/rotate() si actualiza st_atime (la condicion de relatime es
  que el atime actual sea <= mtime, y eso vale justo despues de
  escribir el archivo), asi que el caso comun funciona. Windows/NTFS
  tiene una limitacion analoga: desde Vista, `NtfsDisableLastAccessUpdate`
  esta activado por defecto en muchas instalaciones, con el mismo
  efecto que `noatime`.
- **Windows/NTFS tampoco da una señal suficiente para lecturas repetidas.**
  Aunque actualice `st_atime`, dos lecturas dentro del mismo tick pueden quedar
  indistinguibles. El re-armado no puede recuperar un acceso que el filesystem
  no registro; para una demo en Windows usar `MockHoneypotPlugin` como plan B
  de la misma cadena evento -> regla -> transicion, y no afirmar que un cero
  de `check_access()` demostro ausencia de acceso.
- **Es polling, no un evento en tiempo real.** check_access() hay que
  llamarlo desde un loop externo (igual que RuleEngine.check_closure()
  en M3) -- la latencia de deteccion depende de cada cuanto se llama,
  no hay notificacion push.
- **Sin re-armado, un senuelo detectaria una sola lectura en toda su
  vida** (E2 de docs/improvements.md). La condicion de `relatime` es que
  `atime <= mtime`: se cumple justo despues de escribir el archivo, pero
  deja de cumplirse en cuanto la primera lectura mueve `atime` por
  delante de `mtime`, y desde ahi ninguna lectura posterior vuelve a
  tocar `atime`. Medido: la lectura #1 se detecta y las #2, #3 y #4 no.
  Por eso `check_access()` reescribe el senuelo con su contenido actual
  al detectar una lectura, que devuelve `mtime` por delante de `atime` y
  lo deja armado de nuevo. Una *modificacion* no necesita ese paso (ya
  movio `mtime`) y ademas no se reescribe nunca: el contenido que dejo
  el adversario es evidencia.
- **Es evadible por un atacante que lo sepa.** Restaurar el atime
  original con `touch -a` (o el equivalente en Windows) despues de
  leer el archivo derrota esta deteccion. Es un riesgo aceptado, en
  linea con la seccion 8 del documento de diseno: el honeytoken sigue
  siendo utilidad de bajo costo, no una garantia de deteccion.

Si en algun momento estas limitaciones resultan inaceptables para un
caso de uso real, `watchdog` (inotify en Linux, ReadDirectoryChangesW
en Windows, FSEvents en macOS) da deteccion basada en eventos del
kernel en vez de polling y no depende de atime -- pero es una
dependencia nueva y un modelo de ejecucion distinto (un observer en
background, no una llamada sincronica desde un loop externo), asi que
se preferio no sumarla todavia y dejar la puerta abierta a evaluarlo
si el polling resulta insuficiente en la practica.

Credenciales sinteticas -- revision de M9 (hardening, seccion 8 del
diseno: "proteccion de credenciales y datos sinteticos utilizados en
honeytokens"). Hay una tension real e irreductible aca, no un
descuido: para que el honeytoken funcione, su contenido tiene que
parecerle real a un atacante -- si el archivo dijera explicitamente
"esto es falso", nadie lo usaria y check_access() nunca dispararia.
Por eso `_DEFAULT_FAKE_CREDENTIALS` (y cualquier `fake_credentials` de
`config`) se escriben en el archivo tal cual, sin ninguna marca de
"sintetico" en el contenido. Lo que si se garantiza, en el nivel donde
no compromete la deception:

- **Identificacion en el codigo, no en el senuelo.** El nombre de la
  constante, este docstring y los comentarios dejan sin ambiguedad que
  son valores sinteticos generados por APATE -- cualquiera que lea el
  codigo (no el archivo senuelo) lo sabe de inmediato.
- **Nunca se loguean ni se publican como parte de un evento.** deploy()/
  rotate()/check_access() publican `path`/`kind`/`detail`/`ttp_id` en
  el payload de sus eventos -- nunca el valor de `username`/`password`/
  `connection_string` (ver test_plugins_honeytoken.py,
  test_events_never_carry_credential_values). Eso es lo que evita el
  riesgo concreto de logueo inseguro: la credencial vive solo en el
  archivo que este plugin escribe, nunca en el bus de eventos ni en la
  telemetria (M4) ni en ningun mensaje de excepcion.
- **Responsabilidad del operador para `config["fake_credentials"]`.**
  Si un operador configura sus propias credenciales de senuelo, tienen
  que ser sinteticas tambien -- nunca una credencial real dada de baja
  "total, ya no se usa": si todavia es valida en algun sistema, colocarla
  como cebo la expone igual. Esto no se puede validar por codigo (no
  hay forma confiable de distinguir un secreto real de uno sintetico
  por su forma), asi que queda como responsabilidad documentada del
  operador, no como un chequeo automatico.
"""

from __future__ import annotations

import os
import secrets
import uuid
from pathlib import Path
from typing import Any, Optional

from ..i18n import gettext as _
from ..i18n import lazy_gettext
from .base import DeceptionPlugin, EventType, PluginEvent, PluginLifecycleState
from .exceptions import HoneytokenFileError
from .registry import PluginDescription

# Nombres de archivo por defecto (superficie de datos, seccion 4.4 del
# diseno): dos senuelos "tentadores" tipicos, uno de planilla y uno de
# backup de contrasenas en texto plano.
_DEFAULT_FILENAMES = ["credenciales.csv", "passwords_backup.txt"]

# Vocabulario para generar credenciales ficticias plausibles. Puramente
# sinteticas -- no corresponden a ningun sistema real -- pensadas para que
# un atacante que las encuentre las considere creibles y las use,
# disparando check_access().
#
# **Se generan por despliegue, no son un literal fijo** -- E5 de
# docs/improvements.md. Antes habia una unica constante
# (`svc_backup`/`B4ckup_2024!` y su connection string), y este
# repositorio es publico: cualquiera podia buscar esa contrasena y
# reconocer un honeytoken de esta herramienta por su contenido, sin
# tocarlo. El contenido senuelo por defecto era un IOC de la propia
# herramienta.
#
# El vocabulario en si sigue siendo publico, y eso esta bien: lo que un
# adversario no puede predecir es la combinacion concreta desplegada. Con
# ~6x6x6 nombres mas 4 digitos de sufijo, buscar el valor exacto deja de
# ser una busqueda de texto.
_CREDENTIAL_VOCABULARY = {
    "accounts": ["svc_backup", "svc_sqlagent", "svc_reporting", "backup_admin", "sql_service", "svc_etl"],
    "hosts": ["db-prod-01", "sql-fin-02", "srv-backup-01", "db-core-03", "mssql-prod-02", "db-rrhh-01"],
    "databases": ["finance", "payroll", "billing", "erp_prod", "contabilidad", "tesoreria"],
    "password_words": ["Backup", "Respaldo", "Finanzas", "Central", "Nomina", "Proceso"],
}

# Claves que todo juego de credenciales tiene que traer para que
# _render_content() produzca un senuelo completo.
_CREDENTIAL_KEYS = ("username", "password", "connection_string")

# T1552.001 (Unsecured Credentials: Credentials In Files) es la
# sub-tecnica de MITRE ATT&CK que corresponde a encontrar credenciales
# en un archivo de texto plano -- exactamente lo que este honeytoken
# ofrece como senuelo. Configurable via config["ttp_id"] si el
# escenario de la operacion amerita otra.
_DEFAULT_TTP_ID = "T1552.001"

# Extensiones que se renderizan como una tabla usuario/password en vez
# de lineas "clave: valor". Solo las que este plugin puede producir de
# verdad: texto separado por comas.
_TABULAR_SUFFIXES = {".csv"}

# Extensiones que este plugin NO puede generar, y que por lo tanto
# rechaza en vez de escribir algo que no es lo que su nombre promete
# -- E4 de docs/improvements.md.
#
# `credenciales.xlsx` era uno de los dos nombres por defecto y el
# archivo desplegado contenia CSV en texto plano: `file(1)` lo reporta
# como "ASCII text", no empieza con la firma `PK\x03\x04` de un ZIP y
# Excel no lo abre. Un comentario anterior daba por buena esa
# aproximacion ("suficiente para que sea plausible a primera vista"); no
# lo es -- un senuelo que se delata solo al abrirlo o al correrle
# `file` es peor que no tenerlo, porque le confirma al adversario que
# hay engano desplegado.
#
# Generar OOXML real es posible con `zipfile` de la biblioteca estandar
# y sin dependencias nuevas, pero no se puede validar en este entorno
# que Excel lo abra, asi que se prefiere fallar claro antes que
# desplegar un binario a ciegas.
_UNSUPPORTED_SUFFIXES = {".xlsx", ".xls", ".ods"}


class HoneytokenPlugin(DeceptionPlugin):
    """Plugin de honeytokens de archivo: deploy() coloca senuelos con
    contenido plausible, check_access() detecta por polling si se
    tocaron (ver limitaciones en el docstring del modulo), rotate()
    regenera su contenido para no volverse predecible, y retire() los
    elimina de forma verificable."""

    plugin_description = PluginDescription(
        kind="honeytoken",
        display_name=lazy_gettext("Honeytokens de archivo"),
        description=lazy_gettext(
            "Coloca senuelos de archivo con credenciales ficticias y detecta acceso por "
            "polling sobre sus timestamps -- el unico plugin no simulado que no depende de "
            "ninguna herramienta externa."
        ),
        surface="Archivos / credenciales",
    )

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._paths: list[Path] = []
        self._baseline: dict[Path, tuple[float, float]] = {}
        # Solo se borra en retire() si este plugin creo el directorio:
        # nunca se borra un directorio preexistente, aunque quede
        # vacio, para no llevarse por delante algo que no le pertenece.
        self._created_directory: Optional[Path] = None

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")

        filenames = self.config.get("filenames") or _DEFAULT_FILENAMES
        _reject_unsupported_filenames(filenames)

        directory = self._directory()
        directory_existed = directory.exists()
        directory.mkdir(parents=True, exist_ok=True)
        self._created_directory = None if directory_existed else directory

        # Se fijan en la config para que sobrevivan a esta instancia: la
        # web construye una nueva por request, y sin esto un rotate()
        # posterior generaria credenciales distintas de las que hay en el
        # archivo. Quien despliega es responsable de persistir la config
        # resultante (la ruta web lo hace); ver la nota de `_credentials()`.
        credentials = self._credentials()
        self.config["fake_credentials"] = dict(credentials)

        paths: list[Path] = []
        for filename in filenames:
            path = directory / filename
            _write(path, _render_content(filename, credentials))
            paths.append(path)
        self._paths = paths
        self._snapshot_baseline()

        self._publish(
            EventType.INTERACTION,
            {
                "kind": "deploy",
                "paths": [str(p) for p in self._paths],
                "detail": f"{len(self._paths)} honeytoken(s) desplegado(s).",
            },
        )
        self.state = PluginLifecycleState.DEPLOYED

    def check_access(self, *, rearm: bool = True) -> list[PluginEvent]:
        """Compara el st_atime/st_mtime actual de cada senuelo contra
        el ultimo snapshot conocido (tomado en deploy()/rotate(), o en
        la deteccion anterior) y publica un evento por cada archivo
        que cambio desde entonces. No forma parte del contrato de
        DeceptionPlugin -- es específico de este plugin.
        ``rearm=False`` observa sin reescrituras, para que una operación
        adoptada no eluda K1/K2 desde una comprobación aparentemente de lectura.
        Pensado para llamarse desde un loop de polling externo, igual que
        RuleEngine.check_closure() en M3 (ver limitaciones de atime en
        el docstring del modulo)."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="check_access")

        events: list[PluginEvent] = []
        for path in self._paths:
            try:
                stat_result = path.stat()
            except FileNotFoundError:
                # El senuelo desaparecio por fuera del ciclo de vida
                # del plugin (por ejemplo, alguien lo borro a mano).
                # No es un "acceso": queda fuera de alcance de este
                # metodo, que solo detecta lecturas/escrituras.
                continue

            baseline_atime, baseline_mtime = self._baseline[path]
            accessed = stat_result.st_atime > baseline_atime
            modified = stat_result.st_mtime > baseline_mtime
            if not (accessed or modified):
                # Igual hay que dejarlo armado: si `atime` quedo por
                # delante de `mtime` (por ejemplo, porque el baseline se
                # fijo recien en este chequeo, despues de una lectura que
                # no se pudo atribuir), sin esto ninguna lectura futura
                # movería `atime` y el senuelo quedaria ciego para
                # siempre. Ver `_arm()`.
                if rearm:
                    self._arm(path)
                self._baseline[path] = self._current_stamps(path, fallback=stat_result)
                continue

            kind = "modified" if modified else "access"
            # Re-armado (E2): solo ante una lectura. Una modificacion ya
            # dejo mtime por delante de atime, y su contenido es
            # evidencia que no se debe sobreescribir.
            rearmed = self._arm(path) if rearm and not modified else None
            detail = f"Honeytoken {'modificado' if modified else 'accedido'}: {path}"
            if rearmed is False:
                detail += (
                    " -- no se pudo reescribir el senuelo, asi que deja de detectar "
                    "lecturas nuevas hasta que se lo rote."
                )
            events.append(
                self._publish(
                    EventType.INTERACTION,
                    {
                        "kind": kind,
                        "path": str(path),
                        "rearmed": rearmed,
                        "detail": detail,
                    },
                    resource_id=f"honeytoken:{path}",
                )
            )
            events.append(
                self._publish(
                    EventType.TTP_OBSERVED,
                    {
                        "ttp_id": self.config.get("ttp_id", _DEFAULT_TTP_ID),
                        "path": str(path),
                        "detail": "TTP observada por acceso a un honeytoken de archivo.",
                    },
                    resource_id=f"honeytoken:{path}",
                )
            )
            # Se resetea el baseline al detectar, para no reportar el
            # mismo acceso en cada poll subsiguiente mientras nadie
            # vuelva a tocar el archivo. Se vuelve a leer el stat porque
            # el re-armado acaba de mover mtime: snapshotear el valor
            # anterior reportaria una "modificacion" fantasma en el
            # proximo chequeo.
            self._baseline[path] = self._current_stamps(path, fallback=stat_result)
        return events

    def rotate(self) -> None:
        """Regenera el contenido de cada senuelo (credenciales
        ficticias con un sufijo nuevo) para que no quede un contenido
        estatico e identificable. No reubica los archivos -- cambiar
        de ruta obligaria a borrar los anteriores y trackear nuevos
        paths sin ganar mucho frente a solo regenerar el contenido, que
        ya alcanza para que un hash/firma estatica del senuelo deje de
        servir -- si hace falta relocalizar, retire() + deploy() con
        otra 'directory'/'filenames' en la config cubre ese caso.

        Rota **todos** los campos que contienen la contrasena, no solo
        `password` (E6 de docs/improvements.md): antes la connection
        string se escribia tal cual, con la contrasena vieja embebida, y
        el archivo quedaba con dos contrasenas distintas para la misma
        cuenta -- incoherente para quien lo lea con atencion, y la mitad
        del contenido no cambiaba nunca."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")

        credentials = _rotate_credentials(self._credentials())
        for path in self._paths:
            _write(path, _render_content(path.name, credentials))
        self._snapshot_baseline()

        self._publish(
            EventType.INTERACTION,
            {
                "kind": "rotate",
                "paths": [str(p) for p in self._paths],
                "detail": "Honeytoken(s) rotados: contenido regenerado.",
            },
        )
        # rotate() no cambia el estado del ciclo de vida: sigue DEPLOYED.

    def retire(self) -> None:
        """Elimina todos los senuelos desplegados y verifica que cada
        borrado se concreto (no asume que unlink() sin excepcion
        implica que el archivo ya no existe). Si este plugin creo el
        directorio en deploy() y queda vacio despues de retirar sus
        propios archivos, tambien lo borra -- para no dejar huerfanos
        -- pero nunca borra un directorio que ya existia de antes."""

        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")

        removed = 0
        for path in self._paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise HoneytokenFileError(
                    _("No se pudo eliminar el honeytoken '%(path)s': %(error)s", path=path, error=exc)
                ) from exc
            else:
                removed += 1
            if path.exists():
                raise HoneytokenFileError(
                    _("No se pudo confirmar que se elimino el honeytoken '%(path)s'.", path=path)
                )

        if self._created_directory is not None:
            try:
                self._created_directory.rmdir()
            except OSError:
                # El directorio no esta vacio (por ejemplo, algo mas
                # se guardo ahi mientras tanto) -- no se fuerza el
                # borrado de contenido que este plugin no coloco.
                pass

        self._paths = []
        self._baseline = {}
        self._publish(
            EventType.INTERACTION,
            {"kind": "retire", "detail": f"{removed} honeytoken(s) retirado(s)."},
        )
        self.state = PluginLifecycleState.RETIRED

    def configured_paths(self) -> list[Path]:
        """Devuelve las rutas objetivo derivadas de la configuración.

        No crea, lee ni modifica archivos. La UI contextual la usa para
        mostrar estado real y para evitar sobrescribir un archivo ya
        existente al desplegar manualmente.
        """

        directory = self._directory()
        filenames = self.config.get("filenames") or _DEFAULT_FILENAMES
        return [directory / filename for filename in filenames]

    def restore_deployed_state(self) -> None:
        """Rehidrata una instancia efímera desde recursos verificables.

        Las rutas web construyen una instancia nueva por request. Rotar o
        retirar exige estado ``DEPLOYED`` y la lista interna de archivos;
        ambas se reconstruyen solo si *todos* los objetivos configurados
        existen. Un estado parcial se rechaza para no actuar a ciegas.
        """

        paths = self.configured_paths()
        missing = [path for path in paths if not path.is_file()]
        if missing:
            raise HoneytokenFileError(
                _(
                    "No se puede restaurar el despliegue: faltan archivos configurados: "
                    "%(archivos)s",
                    archivos=", ".join(str(path) for path in missing),
                )
            )
        self._paths = paths
        self._created_directory = (
            self._directory() if self.config.get("_apate_created_directory") else None
        )
        self._snapshot_baseline()
        self.state = PluginLifecycleState.DEPLOYED

    # -- Helpers internos ---------------------------------------------------

    def _directory(self) -> Path:
        directory = self.config.get("directory")
        if not directory:
            raise HoneytokenFileError(
                _(
                    "HoneytokenPlugin requiere 'directory' en la configuracion "
                    "(PluginBinding.config): la ruta donde colocar los archivos senuelo."
                )
            )
        return Path(directory)

    def _credentials(self) -> dict[str, str]:
        """Credenciales del senuelo: lo que el operador configuro en
        `config["fake_credentials"]` gana clave por clave, y lo que falte se
        **genera**, nunca se completa con un literal publicado (E5).

        `deploy()` fija el resultado en `self.config["fake_credentials"]`
        para que un `rotate()` posterior parta de las mismas credenciales
        en vez de inventar otras.
        """

        configuradas = self.config.get("fake_credentials") or {}
        return {**_generate_fake_credentials(), **configuradas}

    def _arm(self, path: Path) -> bool:
        """Deja el senuelo en condiciones de detectar la proxima lectura
        -- ver la nota de `relatime` en el docstring del modulo.

        `relatime` solo actualiza `atime` mientras `atime <= mtime`. Si el
        archivo ya quedo con `atime` por delante, reescribirlo con los
        bytes que ya tiene mueve `mtime` al presente y vuelve a habilitar
        la deteccion. Si la condicion ya se cumple no se toca el disco,
        asi que llamarlo en cada chequeo cuesta a lo sumo una reescritura
        por lectura detectada.

        Reescribe el contenido actual en vez de regenerarlo desde
        `_credentials()`: una lectura no cambia el archivo, asi que los
        bytes son identicos y armarlo no altera el senuelo. Volver a
        renderizarlo perderia el sufijo que haya dejado un `rotate()`
        previo, que es una decision del operador y no de este metodo.

        Devuelve False si no se pudo reescribir (permisos, disco): el
        acceso detectado se reporta igual -- perder la deteccion por no
        poder armar seria peor -- y el evento lo deja dicho."""

        try:
            stat_result = path.stat()
            if stat_result.st_atime <= stat_result.st_mtime:
                return True  # ya esta armado, no hace falta tocar el disco
            path.write_bytes(path.read_bytes())
        except OSError:
            return False
        return True

    def _current_stamps(self, path: Path, *, fallback: os.stat_result) -> tuple[float, float]:
        """Marcas de tiempo despues del re-armado, con el stat previo como
        respaldo si el archivo desaparecio en el medio."""

        try:
            stat_result = path.stat()
        except OSError:
            stat_result = fallback
        return (stat_result.st_atime, stat_result.st_mtime)

    def _snapshot_baseline(self) -> None:
        self._baseline = {path: (path.stat().st_atime, path.stat().st_mtime) for path in self._paths}

    # -- Baseline persistible ----------------------------------------------
    #
    # `check_access()` compara contra un snapshot tomado en deploy()/rotate().
    # Eso alcanza para un loop de polling que mantiene viva la instancia, pero
    # no para la web: ahi cada request construye una instancia nueva y
    # `restore_deployed_state()` vuelve a snapshotear, con lo cual la
    # comparacion seria "ahora contra ahora" y no detectaria nunca nada.
    #
    # Estos dos metodos permiten guardar el baseline junto al binding y
    # devolverlo antes de comparar, que es el mismo patron de cursor
    # persistido que ya usan `CanarytokenPlugin` (`last_hit_time`) y
    # `ExternalTelemetrySource` (`last_fetch_at`). Las claves se serializan
    # como texto porque `PluginBinding.config` va a JSON.

    def export_baseline(self) -> dict[str, list[float]]:
        """Devuelve el snapshot actual en forma serializable a JSON."""

        return {str(path): [atime, mtime] for path, (atime, mtime) in self._baseline.items()}

    def load_baseline(self, stored: dict[str, list[float]]) -> None:
        """Reemplaza el snapshot por uno guardado, solo para las rutas vivas.

        Una ruta que ya no esta configurada se ignora, y una configurada que
        no figura en lo guardado conserva el snapshot recien tomado: es lo
        conservador, porque tratar "sin baseline previo" como acceso
        generaria una deteccion falsa en el primer chequeo.
        """

        for path in self._paths:
            valores = stored.get(str(path))
            if valores and len(valores) == 2:
                self._baseline[path] = (float(valores[0]), float(valores[1]))


def _generate_fake_credentials() -> dict[str, str]:
    """Un juego de credenciales sinteticas nuevo, plausible y distinto en
    cada despliegue -- ver la nota de `_CREDENTIAL_VOCABULARY`.

    Usa `secrets` y no `random`: no hay razon para elegir el generador
    predecible, y aca el valor tiene que ser inadivinable para quien
    conozca el codigo.
    """

    cuenta = secrets.choice(_CREDENTIAL_VOCABULARY["accounts"])
    host = secrets.choice(_CREDENTIAL_VOCABULARY["hosts"])
    base_de_datos = secrets.choice(_CREDENTIAL_VOCABULARY["databases"])
    palabra = secrets.choice(_CREDENTIAL_VOCABULARY["password_words"])
    # Forma de contrasena corporativa elegida por una persona, que es lo
    # que un adversario espera encontrar en un archivo asi.
    password = f"{palabra}_{secrets.randbelow(9000) + 1000}!"
    return {
        "username": cuenta,
        "password": password,
        "connection_string": (
            f"Server={host};Database={base_de_datos};User Id={cuenta};Password={password};"
        ),
    }


def _rotate_credentials(credentials: dict[str, str]) -> dict[str, str]:
    """Le pone un sufijo nuevo a la contrasena y la actualiza en cualquier
    otro campo que la contenga -- E6 de docs/improvements.md.

    Se reemplaza por substring en vez de reconstruir la connection string
    desde sus partes: el operador puede haber configurado un formato
    propio en `config["fake_credentials"]`, y reemplazar el valor viejo
    respeta cualquier formato sin tener que entenderlo. Tambien cubre
    campos extra que sume el operador.
    """

    anterior = credentials["password"]
    nueva = f"{anterior}-{uuid.uuid4().hex[:6]}"
    rotadas: dict[str, str] = {}
    for clave, valor in credentials.items():
        if clave == "password":
            rotadas[clave] = nueva
        elif isinstance(valor, str) and anterior in valor:
            rotadas[clave] = valor.replace(anterior, nueva)
        else:
            rotadas[clave] = valor
    return rotadas


def _reject_unsupported_filenames(filenames: list[str]) -> None:
    """Falla antes de escribir nada si algun nombre promete un formato que
    este plugin no puede generar -- ver `_UNSUPPORTED_SUFFIXES`.

    Se valida al principio de `deploy()` y no por archivo: desplegar la
    mitad de los senuelos y abortar dejaria el conjunto a medias.
    """

    invalidos = [f for f in filenames if Path(f).suffix.lower() in _UNSUPPORTED_SUFFIXES]
    if not invalidos:
        return
    raise HoneytokenFileError(
        _(
            "Este plugin no puede generar el formato que prometen estos nombres: "
            "%(nombres)s. El archivo quedaria en texto plano con una extension que no le "
            "corresponde, y un adversario que lo abra o le corra 'file' descubre el engano. "
            "Usa '.csv' para una tabla usuario/password o '.txt' para lineas 'clave: valor'.",
            nombres=", ".join(invalidos),
        )
    )


def _render_content(filename: str, credentials: dict[str, str]) -> str:
    if Path(filename).suffix.lower() in _TABULAR_SUFFIXES:
        return "usuario,password\n" + f"{credentials['username']},{credentials['password']}\n"
    return "\n".join(f"{key}: {value}" for key, value in credentials.items()) + "\n"


def _write(path: Path, content: str) -> None:
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise HoneytokenFileError(
            _("No se pudo escribir el honeytoken '%(path)s': %(error)s", path=path, error=exc)
        ) from exc
