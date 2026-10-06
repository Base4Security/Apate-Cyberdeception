"""Wrapper de ciclo de vida del stack Playground (M5) - documento de
diseno, seccion 6.2.

No reimplementa nada del stack: invoca `docker compose up --profile
<nivel> -d` / `docker compose down` por subprocess sobre el checkout
local configurado (PlaygroundConfig), igual que lo haria un operador
a mano. El <nivel> sale directo de DeceptionLevel (los cuatro valores
reales del repo, ver apate.core.models), mapeado 1:1 a los profiles
del docker-compose real.

Tambien expone run_attacker_script(): a diferencia de los demas
servicios del stack (ssh_honeypot, frontend, backend, mysql), que
Filebeat indexa en Elasticsearch (ver events.py), el contenedor
attacker-tools no corre nada automaticamente -- es una shell
interactiva (`command: /bin/bash` en el docker-compose real) sin
logging ni entrada en Filebeat. La unica forma de observar sus
acciones es ejecutar attack_scripts/main_attacker.py via `docker exec`
y capturar su salida estandar (ver docs/analisis-repos-existentes.md,
verificado contra el repo real).

Ese script es ademas interactivo: cada una de sus fases llama a
ask_continue() (components/base_attacker.py), que bloquea esperando
una linea por stdin -- no hay flag ni variable de entorno para
saltarlo -- y no acepta argumentos por linea de comandos (no usa
argparse). Por eso run_attacker_script() invoca `docker exec -i` (sin
esa `-i`, docker no conecta el stdin del proceso, y el script se
queda esperando para siempre) y le escribe por stdin suficientes
confirmaciones para cubrir las fases reales, con margen.

Se usa subprocess.run con una lista de argumentos (nunca
shell=True ni interpolacion de strings en un comando de shell), en
linea con el enfoque de la seccion 8 del documento de diseno.

**Verificacion manual pendiente desde M5 (ver docs/roadmap.md),
cerrada ejecutando de verdad contra Docker/Elasticsearch reales --
tres correcciones encontradas, ninguna aparecia en la suite de tests
porque siempre mockeo subprocess.run/urllib.request.urlopen:**

1. **`--profile` va antes del subcomando, no despues.** La version real
   de Docker Compose de este entorno (v5.3.1) rechaza
   `docker compose up --profile <nivel> -d` con "unknown flag:
   --profile" -- el flag es global de `docker compose`, no propio de
   `up`. Confirmado con el CLI real antes de tocar el codigo.
2. **El nivel de decepcion real (contenido, no solo que contenedores
   arrancan) lo decide la variable de entorno `DECEPTION_LEVEL`, leida
   por el propio `docker-compose.yml` (`${DECEPTION_LEVEL:-none}`) --
   `--profile` unicamente controla que servicios se incluyen, no que
   SQL/contenido cargan.** Confirmado con el stack real: arrancar con
   `--profile basic` sin setear la variable de entorno deja el backend
   y MySQL corriendo igual, pero con "Deception Level: NONE" en los
   logs y `init-none.sql` cargado -- el nivel elegido en la UI de APATE
   nunca llegaba a afectar el contenido real. `start_stack()` ahora
   pasa `DECEPTION_LEVEL=<nivel>` en el entorno del subprocess.
3. **`stop_stack()` tambien necesita `--profile`, y no alcanza con uno
   solo.** Cada servicio del compose real tiene `profiles:` explicito
   (ninguno queda "siempre activo" sin filtro) -- un `docker compose
   down` sin `--profile` no matchea ningun servicio y no hace nada, en
   silencio, sin error. Como `stop_stack()` no recibe (ni deberia
   necesitar) el nivel con el que se arranco -- la sesion web no lo
   guarda -- pasa los cuatro perfiles (`DeceptionLevel` completo) a la
   vez, confirmado que Docker Compose acepta `--profile` repetido para
   habilitar la union.

**Sobre `main_attacker.py` en si, confirmado corriendolo de punta a
punta (10x "c\n" alcanzaron, con margen real, no solo teorico):**
tiene **8** `ask_continue()` reales, no 7 -- la "Fase 6.5: Lateral
Movement via SSH" es una fase propia con su propia confirmacion,
distinta de la Fase 6 (SSH Brute Force) aunque el nombre sugiera que
es una sub-parte; confirmado contando los `ask_continue()` en el
codigo real, no solo leyendo el resumen que el script imprime.
**Duracion real medida: ~18 minutos** (no segundos) para una corrida
completa de las 8 fases sin saltear ninguna -- el grueso del tiempo lo
consume la Fase 4 (Reconnaissance), que instala nmap dentro del
contenedor `frontend` via inyeccion de comandos y corre
`nmap -sn -R <red>/24` (barrido ping con resolucion DNS inversa
forzada para cada host) contra una red completa sin DNS funcional --
nmap agota el timeout de resolucion inversa host por host, no es un
cuelgue ni un bug de `run_attacker_script()`/`ask_continue()`. Para una
demo en vivo, correr este script con margen de tiempo real (no
segundos) o preparar la corrida de antemano -- ver
docs/guia-demo-blackhat.md. Las 8 fases produjeron sus 8 banners MITRE
reales, confirmados palabra por palabra contra el formato documentado
en events.py, y `PlaygroundEventBridge.ingest_attacker_output()` los
tradujo los 8 sin descartar ninguno.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

from ..core.models import DeceptionLevel
from ..i18n import gettext as _
from .config import PlaygroundConfig
from .exceptions import PlaygroundCommandError

# Nombre del servicio/contenedor atacante y del script de entrada
# principal, tal como estan definidos en el docker-compose y el
# repositorio real (ver docs/analisis-repos-existentes.md).
_ATTACKER_CONTAINER = "attacker-tools"
_ATTACKER_SCRIPT = "attack_scripts/main_attacker.py"

# main_attacker.py tiene 8 fases reales (Fase 6.5 "Lateral Movement"
# es una fase propia con su propia confirmacion, no parte de la Fase
# 6 -- confirmado contando los ask_continue() reales en el codigo, ver
# docstring del modulo), cada una con su propio ask_continue(); "c\n"
# x 10 cubre las 8 con margen sin tener que parsear la salida a medida
# que se genera solo para saber cuantas confirmaciones faltan --
# confirmado end-to-end contra Docker real (ver docstring del modulo).
_ATTACKER_CONTINUE_INPUT = "c\n" * 10


@dataclass
class PlaygroundCommandResult:
    """Resultado de un comando de ciclo de vida, para que quien llama
    (la vista web, un test) pueda mostrar/inspeccionar la salida sin
    depender de excepciones para el camino exitoso."""

    args: list[str]
    stdout: str
    stderr: str


def _run(
    full_args: list[str],
    *,
    config: PlaygroundConfig,
    stdin_input: Optional[str] = None,
    extra_env: Optional[dict[str, str]] = None,
) -> PlaygroundCommandResult:
    # env=None (default) hereda el entorno del proceso actual tal cual,
    # igual que antes de esta funcion aceptar extra_env -- solo se
    # construye una copia fusionada cuando alguien pasa algo especifico
    # (DECEPTION_LEVEL en start_stack()).
    env = {**os.environ, **extra_env} if extra_env else None
    try:
        completed = subprocess.run(
            full_args,
            cwd=config.path,
            capture_output=True,
            text=True,
            check=True,
            input=stdin_input,
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        raise PlaygroundCommandError(
            _(
                "El comando '%(command)s' termino con codigo %(code)s: %(stderr)s",
                command=" ".join(full_args),
                code=exc.returncode,
                stderr=exc.stderr.strip() if exc.stderr else _("(sin salida de error)"),
            )
        ) from exc
    except FileNotFoundError as exc:
        raise PlaygroundCommandError(
            _(
                "No se encontro el ejecutable '%(executable)s'. Verificar que Docker (con el "
                "plugin 'compose') este instalado.",
                executable=full_args[0],
            )
        ) from exc
    return PlaygroundCommandResult(args=full_args, stdout=completed.stdout, stderr=completed.stderr)


def _run_compose(
    config: PlaygroundConfig, args: list[str], *, extra_env: Optional[dict[str, str]] = None
) -> PlaygroundCommandResult:
    return _run([*config.compose_command, *args], config=config, extra_env=extra_env)


def start_stack(
    config: PlaygroundConfig, level: DeceptionLevel, *, detach: bool = True
) -> PlaygroundCommandResult:
    """Levanta el stack en el profile correspondiente al nivel de
    engano. `detach=True` (por defecto) agrega `-d`, ya que el uso
    normal desde APATE es levantar el stack y seguir operando, no
    quedarse pegado a la salida de los contenedores.

    `--profile` va **antes** del subcomando `up` (Docker Compose real
    de este entorno, v5.3.1, lo rechaza despues -- ver docstring del
    modulo) y se pasa ademas `DECEPTION_LEVEL=<nivel>` en el entorno
    del subprocess: es la variable que el `docker-compose.yml` real lee
    para decidir que SQL/contenido cargar (`${DECEPTION_LEVEL:-none}`)
    -- `--profile` por si solo unicamente decide que contenedores
    arrancan, no que datos cargan."""

    args = ["--profile", level.value, "up"]
    if detach:
        args.append("-d")
    return _run_compose(config, args, extra_env={"DECEPTION_LEVEL": level.value})


def stop_stack(config: PlaygroundConfig) -> PlaygroundCommandResult:
    """Baja el stack (`docker compose down`), liberando los contenedores
    y la red creados por start_stack(). No borra volumenes (`-v`) a
    proposito: retirar el entorno de simulacion no deberia borrar
    datos de forma implicita.

    Pasa los cuatro `DeceptionLevel` como `--profile` a la vez (en vez
    de recibir el nivel usado en `start_stack()`, que esta funcion no
    tiene forma de conocer -- la sesion web no lo guarda): cada
    servicio del compose real exige un profile explicito, sin ninguno
    "siempre activo", asi que un `down` sin `--profile` no matchea
    ningun servicio y no hace nada, en silencio, sin error (confirmado
    contra Docker real) -- pasar los cuatro cubre cualquier nivel con
    el que se haya arrancado."""

    profile_args = [arg for level in DeceptionLevel for arg in ("--profile", level.value)]
    return _run_compose(config, [*profile_args, "down"])


def run_attacker_script(config: PlaygroundConfig) -> PlaygroundCommandResult:
    """Ejecuta attack_scripts/main_attacker.py dentro del contenedor
    attacker-tools (`docker exec -i`, no `docker compose exec`: el
    contenedor se referencia por nombre, no por el proyecto de compose)
    y captura su salida estandar -- es la unica fuente de eventos del
    atacante, ya que ese contenedor no tiene logging propio ni entrada
    en Filebeat (ver docstring del modulo). No acepta argumentos: el
    script real no tiene argparse, asi que pasarle argumentos no
    tendria ningun efecto. El `-i` conecta el stdin del proceso para
    poder alimentarle las confirmaciones que sus 8 fases interactivas
    esperan (ver _ATTACKER_CONTINUE_INPUT). **Puede tardar minutos
    reales, no segundos** -- la fase de reconocimiento de red instala
    nmap dentro de `frontend` y corre un barrido con resolucion DNS
    inversa contra una red completa, confirmado contra Docker real
    (ver docstring del modulo)."""

    return _run(
        ["docker", "exec", "-i", _ATTACKER_CONTAINER, "python3", _ATTACKER_SCRIPT],
        config=config,
        stdin_input=_ATTACKER_CONTINUE_INPUT,
    )


def run_attacker_script_streaming(
    config: PlaygroundConfig, on_stdout_line: Callable[[str], None]
) -> PlaygroundCommandResult:
    """Ejecuta el atacante y entrega cada línea de stdout al llegar.

    Conserva el mismo ``docker exec -i`` y las confirmaciones del camino
    síncrono, pero evita esperar una corrida completa para que la capa web
    traduzca cada banner MITRE y lo publique sobre el bus de la sesión.
    ``stderr`` se conserva separado para informar un fallo al finalizar.
    """

    args = ["docker", "exec", "-i", _ATTACKER_CONTAINER, "python3", _ATTACKER_SCRIPT]
    try:
        process = subprocess.Popen(
            args,
            cwd=config.path,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise PlaygroundCommandError(
            _(
                "No se encontró el ejecutable 'docker'. Verificar que Docker esté instalado y "
                "levantado."
            )
        ) from exc

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    process.stdin.write(_ATTACKER_CONTINUE_INPUT)
    process.stdin.close()

    stdout_lines: list[str] = []
    for line in process.stdout:
        stdout_lines.append(line)
        on_stdout_line(line)
    stderr = process.stderr.read()
    returncode = process.wait()
    stdout = "".join(stdout_lines)
    if returncode != 0:
        raise PlaygroundCommandError(
            _(
                "El comando '%(command)s' terminó con código %(code)s: %(stderr)s",
                command=" ".join(args),
                code=returncode,
                stderr=stderr.strip() if stderr else _("(sin salida de error)"),
            )
        )
    return PlaygroundCommandResult(args=args, stdout=stdout, stderr=stderr)
