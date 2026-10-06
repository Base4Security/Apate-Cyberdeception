"""Vida de la sesion y freno a la fuerza bruta en el inicio de sesion.

**Tres huecos que esto cierra, y son distintos entre si.**

1. **La sesion no expiraba nunca.** La cookie firmada llevaba `identity_id` y
   `credential_version` y nada mas: una cookie capturada -- de un backup, de
   un log de proxy, de un perfil de navegador compartido, de un puesto sin
   bloquear -- valia indefinidamente mientras no rotara `APATE_SECRET_KEY` ni
   cambiara esa contrasenia. Ahora hay dos relojes, y los dos hacen falta: un
   **maximo absoluto** desde que se inicio sesion, que acota el dano de una
   credencial robada, y uno **por inactividad**, que cierra el puesto que
   alguien dejo abierto. Ninguno reemplaza al otro: una sesion muy usada nunca
   vence por inactividad, y una recien iniciada no vence por antiguedad.

2. **No habia ningun freno a los intentos.** `authenticate()` se podia llamar
   en un bucle sin contador ni espera. El freno es por **(nombre, origen)** y
   no solo por nombre: frenar solo por nombre le da a cualquiera una forma
   trivial de bloquearle la cuenta a otro con solo fallar adrede.

3. **Los inicios de sesion no quedaban en ninguna parte.** Habia auditoria de
   alta, baja y cambio de contrasenia, pero no de quien entro, ni de quien lo
   intento y fallo. La fuerza bruta era libre *e* invisible.

**El estado del freno vive en memoria, y hay que decir que eso significa.** Se
pierde al reiniciar, y con varios procesos cada uno cuenta por su cuenta -- la
instalacion soportada es de un solo worker (`docs/instalacion-produccion.md`),
asi que hoy coincide. Es un freno, no una defensa contra un atacante decidido
y distribuido: para eso hace falta el proxy reverso o un almacen compartido.
Decirlo es mejor que dar a entender otra cosa.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

#: Maximo absoluto de una sesion. Doce horas cubre una jornada larga de
#: operacion sin obligar a reautenticar en el medio de un ejercicio.
VIDA_MAXIMA_SEGUNDOS = 12 * 60 * 60

#: Inactividad tolerada. Una consola de ciberengano abierta en un puesto vacio
#: es exactamente lo que esto cierra.
INACTIVIDAD_MAXIMA_SEGUNDOS = 60 * 60

#: Intentos fallidos antes de frenar, y cuanto dura el freno.
INTENTOS_ANTES_DE_FRENAR = 5
FRENO_SEGUNDOS = 15 * 60

#: Cuanto vive un contador sin intentos nuevos. Sin esto la tabla crece sola.
MEMORIA_DE_INTENTOS_SEGUNDOS = 60 * 60

#: Claves de la sesion. Con guion bajo para no chocar con datos de identidad.
CLAVE_INICIO = "_iniciada_en"
CLAVE_ACTIVIDAD = "_ultima_actividad"


@dataclass
class _Intentos:
    fallos: int = 0
    ultimo: float = 0.0


class ControlDeIntentos:
    """Cuenta fallos por (nombre, origen) y frena cuando se pasan.

    `time.monotonic()` y no la hora del reloj: cambiar la hora del sistema --
    o un ajuste de NTP -- no debe levantar un freno activo.
    """

    def __init__(
        self,
        limite: int = INTENTOS_ANTES_DE_FRENAR,
        freno: float = FRENO_SEGUNDOS,
        memoria: float = MEMORIA_DE_INTENTOS_SEGUNDOS,
        reloj_monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limite = limite
        self._freno = freno
        self._memoria = memoria
        self._reloj_monotonic = reloj_monotonic
        self._por_clave: dict[tuple[str, str], _Intentos] = {}
        self._lock = threading.Lock()

    def segundos_de_espera(self, nombre: str, origen: str) -> float:
        """Cuanto falta para poder volver a intentar. 0 si se puede ahora."""

        with self._lock:
            registro = self._por_clave.get((nombre, origen))
            if registro is None or registro.fallos < self._limite:
                return 0.0
            transcurrido = self._reloj_monotonic() - registro.ultimo
            return max(0.0, self._freno - transcurrido)

    def registrar_fallo(self, nombre: str, origen: str) -> None:
        with self._lock:
            ahora = self._reloj_monotonic()
            self._limpiar(ahora)
            registro = self._por_clave.setdefault((nombre, origen), _Intentos(ultimo=ahora))
            # Un intento durante el freno lo reinicia: insistir no acorta la espera.
            if registro.fallos >= self._limite and ahora - registro.ultimo < self._freno:
                registro.ultimo = ahora
                return
            if registro.fallos >= self._limite:
                registro.fallos = 0
            registro.fallos += 1
            registro.ultimo = ahora

    def registrar_exito(self, nombre: str, origen: str) -> None:
        """Entrar limpia el contador de esa combinacion."""

        with self._lock:
            self._por_clave.pop((nombre, origen), None)

    def _limpiar(self, ahora: float) -> None:
        """Descarta contadores viejos. Se llama con el lock tomado."""

        vencidos = [
            clave
            for clave, registro in self._por_clave.items()
            if ahora - registro.ultimo >= self._memoria
        ]
        for clave in vencidos:
            del self._por_clave[clave]


def marcar_inicio(session) -> None:
    """Sella la sesion recien iniciada con los dos relojes."""

    ahora = time.time()
    session[CLAVE_INICIO] = ahora
    session[CLAVE_ACTIVIDAD] = ahora


def vencida(session, *, ahora: float | None = None) -> bool:
    """`True` si la sesion supero el maximo absoluto o el de inactividad.

    Una sesion **sin sello** se considera vencida: es una cookie anterior a
    esta verificacion, y darle vida indefinida seria dejar abierta justo la
    puerta que esto viene a cerrar.
    """

    inicio = session.get(CLAVE_INICIO)
    actividad = session.get(CLAVE_ACTIVIDAD)
    if not isinstance(inicio, (int, float)) or not isinstance(actividad, (int, float)):
        return True
    ahora = time.time() if ahora is None else ahora
    if ahora - inicio > VIDA_MAXIMA_SEGUNDOS:
        return True
    return ahora - actividad > INACTIVIDAD_MAXIMA_SEGUNDOS


def refrescar_actividad(session) -> None:
    """Corre el reloj de inactividad. No toca el maximo absoluto."""

    session[CLAVE_ACTIVIDAD] = time.time()
