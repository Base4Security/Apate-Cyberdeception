**APATE — Contrato de plugins y eventos (M2)**

**Ejecución de operaciones adoptadas (B, 26 septiembre 2026):** este contrato
describe el adaptador de bajo nivel, no una autorización para invocarlo.
La app usa `ApprovedPlugin`/`OperationExecutor` antes de acciones compatibles;
el soporte efectivo y los adaptadores bloqueados están en
`docs/ejecucion-trazable-operaciones.md`. Un programa externo debe proporcionar
la misma autoridad si declara esa garantía. `HoneytokenPlugin.check_access`
admite `rearm=False`; la fachada adoptada lo usa para observar sin reescrituras.

**Continuidad B1:** OpenCanary, DOLOS-T, BUDA y Playground tienen ejecución
gestionada para descriptores aprobados nuevos. La configuración efectiva,
identidad de recursos y límites están en `docs/adaptadores-trazables-b1.md`.
`PlaygroundPlugin` requiere la fachada: sus métodos de bajo nivel no autorizan
despliegues por sí solos.

*Documento autocontenido. No requiere acceso al resto del repositorio de APATE: si estás implementando un adaptador para DOLOS-T, BUDA, o cualquier otra herramienta de engaño, esto es todo lo que necesitás saber para que APATE la reconozca como plugin.*

*Extraído directamente del código real en `src/apate/plugins/` (paquete `apate.plugins`, expuesto también como `apate.plugins` en el nivel superior del paquete `apate`) y de las validaciones que le aplica `src/apate/rules/engine.py` (paquete `apate.rules`). Referencias de línea omitidas a propósito porque el código puede moverse; las firmas y nombres citados son exactos a la fecha de este documento.*

---

# 1. Resumen (TL;DR)

Para integrarse con APATE, un plugin tiene que:

1. Ser una subclase de `apate.plugins.DeceptionPlugin` que implemente `deploy()`, `rotate()` y `retire()` — los tres sin parámetros (más allá de `self`) y sin retorno (`None`).
2. Publicar eventos (`apate.plugins.PluginEvent`) al `EventBus` que recibió en el constructor, usando el helper heredado `self._publish(event_type, payload)`.
3. Llevar internamente su propio estado de ciclo de vida (`CREATED` → `DEPLOYED` → `RETIRED`) y validarlo antes de cada operación, usando el helper heredado `self._require_state(...)`.
4. Estar registrado bajo el mismo `plugin_id` en dos lugares distintos y consistentes entre sí: la instancia viva que el motor de reglas usa para llamar métodos, y un `PluginBinding` en `operation.plugins` — si no coinciden, el motor de reglas rechaza cualquier acción que intente dirigirse a tu plugin (`UnknownPluginError`, ver sección 5).

No hay nada más que registrar, heredar de una interfaz de red, ni exponer por HTTP. El contrato es deliberadamente mínimo: tres métodos y un formato de evento.

---

# 2. La interfaz `DeceptionPlugin`

Clase base abstracta (`abc.ABC`) en `apate.plugins.base` (re-exportada como `apate.plugins.DeceptionPlugin`).

## 2.1 Constructor

```python
class DeceptionPlugin(ABC):
    def __init__(
        self,
        *,
        plugin_id: str,
        surface: str,
        operation_id: str,
        bus: EventBus,
        config: Optional[dict[str, Any]] = None,
    ) -> None:
        self.plugin_id = plugin_id
        self.surface = surface
        self.operation_id = operation_id
        self.config = dict(config or {})
        self.state = PluginLifecycleState.CREATED
        self._bus = bus
```

Todos los parámetros son **keyword-only** (nota el `*` después de `self`). Un subclase típica no sobreescribe `__init__` — solo agrega estado propio llamando primero a `super().__init__(**kwargs)` si necesita atributos adicionales (así lo hace `HoneytokenPlugin`, ver sección 4).

| Parámetro | Tipo | Significado |
|---|---|---|
| `plugin_id` | `str` | Identificador único de esta instancia dentro de la operación. Tiene que coincidir exactamente con el `plugin_id` del `PluginBinding` correspondiente en `operation.plugins` (ver sección 5.2). |
| `surface` | `str` | Superficie de engaño a la que pertenece: `"network"`, `"identity"`, `"data"`, u otra que el escenario defina. No se valida contra una lista cerrada — es texto libre usado para filtrar telemetría, no una enumeración. |
| `operation_id` | `str` | `id` de la `Operation` (`apate.core.Operation`) a la que pertenece este plugin. Se incluye tal cual en cada evento publicado. |
| `bus` | `EventBus` | El bus de eventos de esa operación. Una misma instancia de `EventBus` se comparte entre todos los plugins de una operación — no crear una instancia propia. |
| `config` | `dict[str, Any]` (opcional) | Configuración específica del plugin (por ejemplo, credenciales de un connection string, rutas de archivos, endpoints a los que llamar). Viene del `config` del `PluginBinding`. Se copia a un `dict` nuevo (`self.config = dict(config or {})`), así que mutar `self.config` no afecta al `PluginBinding` original. |

### Factory alternativo: `from_binding`

```python
@classmethod
def from_binding(
    cls, binding: PluginBinding, *, operation_id: str, bus: EventBus
) -> "DeceptionPlugin":
    return cls(
        plugin_id=binding.plugin_id,
        surface=binding.surface,
        operation_id=operation_id,
        bus=bus,
        config=binding.config,
    )
```

Construye la instancia directamente a partir de un `PluginBinding` ya registrado en la `Operation` — evita tener que copiar `plugin_id`/`surface`/`config` a mano. `PluginBinding` (de `apate.core`) es:

```python
@dataclass
class PluginBinding:
    plugin_id: str
    surface: str
    config: dict[str, Any] = field(default_factory=dict)
```

## 2.2 Métodos abstractos

```python
@abstractmethod
def deploy(self) -> None: ...

@abstractmethod
def rotate(self) -> None: ...

@abstractmethod
def retire(self) -> None: ...
```

Ningún parámetro más allá de `self`. Ningún valor de retorno (`None`) — el resultado de la operación se comunica publicando eventos al bus, no devolviéndolo. Python no impone nada más allá de "el método existe": la semántica de cada uno es una convención documentada, reforzada por los dos plugins reales del repositorio (`MockHoneypotPlugin`, `HoneytokenPlugin`):

| Método | Cuándo se llama | Estado de entrada esperado | Estado de salida |
|---|---|---|---|
| `deploy()` | Al activar el plugin por primera vez para esta operación. | `CREATED` | `DEPLOYED` |
| `rotate()` | Para renovar el señuelo (nueva identidad, nuevo contenido) sin retirarlo. | `DEPLOYED` | `DEPLOYED` (no cambia) |
| `retire()` | Al desactivar el plugin (cierre de la operación, u orden explícita). | `DEPLOYED` | `RETIRED` |

Si tu implementación intenta ejecutar una de estas tres fuera del estado esperado (por ejemplo, `deploy()` dos veces, o `retire()` antes de `deploy()`), la convención de este repositorio es lanzar `PluginStateError` — ver sección 2.4 y 5.1.

`retire()` debería dejar el recurso real (si lo hay) en un estado verificablemente eliminado, no solo marcar una bandera — `HoneytokenPlugin.retire()` (sección 4.2) es el ejemplo de referencia: no asume que un `unlink()` sin excepción implica que el archivo desapareció, lo vuelve a comprobar.

## 2.3 Ciclo de vida (`PluginLifecycleState`)

```python
class PluginLifecycleState(str, Enum):
    CREATED = "created"
    DEPLOYED = "deployed"
    RETIRED = "retired"
```

Es un `str, Enum` — comparable directamente contra el string (`plugin.state == "deployed"` funciona igual que `plugin.state == PluginLifecycleState.DEPLOYED`). Todo plugin arranca en `CREATED` (lo fija el `__init__` de la base) y solo dos transiciones son válidas por convención: `CREATED → DEPLOYED` (via `deploy()`) y `DEPLOYED → RETIRED` (via `retire()`). No hay manera de volver a un estado anterior.

## 2.4 Helpers heredados (protegidos, no abstractos)

Estos dos métodos **ya vienen implementados** en `DeceptionPlugin` — no hace falta reimplementarlos, solo llamarlos desde tu `deploy()`/`rotate()`/`retire()`.

```python
def _require_state(self, expected: PluginLifecycleState, *, action: str) -> None:
    if self.state is not expected:
        raise PluginStateError(
            f"No se puede ejecutar '{action}' en estado "
            f"'{self.state.value}' (se esperaba '{expected.value}')."
        )
```

Llamalo al principio de cada método de ciclo de vida, con el estado que tu método espera encontrar y un nombre corto de la acción (usado solo para el mensaje de error). Ejemplo real, de `MockHoneypotPlugin.deploy()`:

```python
def deploy(self) -> None:
    self._require_state(PluginLifecycleState.CREATED, action="deploy")
    ...
```

```python
def _publish(self, event_type: EventType, payload: dict[str, Any]) -> PluginEvent:
    event = PluginEvent(
        event_type=event_type,
        plugin_id=self.plugin_id,
        surface=self.surface,
        operation_id=self.operation_id,
        payload=payload,
    )
    self._bus.publish(event)
    return event
```

Arma el `PluginEvent` completando automáticamente `plugin_id`/`surface`/`operation_id` con los de la instancia (así no hay que repetirlos en cada llamada), lo publica en el bus, y te devuelve el evento ya construido (útil si necesitás su `id` o `timestamp` para otra cosa). Pasás `event_type`, `payload` y, cuando el proveedor puede demostrar el recurso exacto, `resource_id=` — ver sección 3 para el formato exacto.

---

# 3. El evento: `PluginEvent`

```python
class EventType(str, Enum):
    INTERACTION = "interaction"
    TTP_OBSERVED = "ttp_observed"


@dataclass
class PluginEvent:
    event_type: EventType
    plugin_id: str
    surface: str
    operation_id: str
    resource_id: Optional[str] = None
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
```

## 3.1 Campos

| Campo | Tipo | Obligatorio | Quién lo llena |
|---|---|---|---|
| `event_type` | `EventType` (`"interaction"` \| `"ttp_observed"`) | Sí | Vos, al llamar `self._publish(event_type, payload)`. |
| `plugin_id` | `str` | Sí | Automático — `self._publish()` lo completa con `self.plugin_id`. |
| `surface` | `str` | Sí | Automático — `self._publish()` lo completa con `self.surface`. |
| `operation_id` | `str` | Sí | Automático — `self._publish()` lo completa con `self.operation_id`. |
| `resource_id` | `str` | No | Vos, mediante `self._publish(..., resource_id=...)`, solo si identifica de forma estable el recurso observado dentro de la capacidad. |
| `payload` | `dict[str, Any]` | No (default `{}`) | Vos — contenido libre, ver 3.3. |
| `id` | `str` (UUID4) | No (autogenerado) | Automático. |
| `timestamp` | `datetime` (UTC, timezone-aware) | No (autogenerado, `datetime.now(timezone.utc)`) | Automático. |

Si construís un `PluginEvent` a mano (en vez de usar `self._publish()`) — por ejemplo desde un test, o desde un adaptador que traduce eventos ya emitidos por una herramienta externa — los cuatro primeros campos son obligatorios en el constructor; `resource_id`, `payload`, `id` y `timestamp` tienen default. `resource_id` no se deduce de `detail`, `target` ni nombres parecidos: si la fuente no ofrece identidad estable, queda `None`.

## 3.2 `event_type`: `interaction` vs `ttp_observed`

No hay una regla mecánica que los distinga — es una decisión semántica de quién emite el evento:

- **`interaction`** — cualquier acción observable sobre el plugin: se desplegó, alguien accedió al señuelo, se rotó, se retiró. Es el tipo de evento más frecuente. Payload típico: `{"kind": "scan" | "access" | "rotate" | "retire" | "deploy" | "modified" | ..., "detail": "texto legible", ...}`.
- **`ttp_observed`** — se identificó una técnica o sub-técnica concreta de MITRE ATT&CK asociada a la interacción (por ejemplo, se detectó el patrón de un `T1078` — *Valid Accounts* — o un `T1552.001` — *Unsecured Credentials: Credentials In Files*). Payload esperado: `{"ttp_id": "T1234[.001]", ...}` — la clave `ttp_id` es la que el resto del sistema (telemetría, informes) busca para extraer la TTP; no es obligatoria a nivel de esquema (`payload` es libre), pero sin ella el evento no se correlaciona con TTPs en ningún lado.

En la práctica, un mismo suceso real suele generar **dos eventos separados**: un `interaction` describiendo qué pasó, y un `ttp_observed` inmediatamente después identificando la técnica — así lo hacen tanto `MockHoneypotPlugin.simulate_access()` como `HoneytokenPlugin.check_access()` (ver sección 4). No es obligatorio emitir ambos siempre — `deploy()`/`rotate()`/`retire()` en los dos plugins de referencia solo emiten `interaction`, nunca `ttp_observed`, porque desplegar/rotar/retirar un señuelo no es en sí mismo una técnica del adversario.

## 3.3 `payload`: convención, no esquema cerrado

`payload` es un `dict[str, Any]` intencionalmente libre — cada plugin/superficie observa cosas distintas y no hay una clase de payload separada por tipo de evento. Dicho esto, el resto de APATE (telemetría, motor de reglas) reconoce por convención estas claves si aparecen:

| Clave de `payload` | Se usa para |
|---|---|
| `kind` | Categoría corta del evento (`"scan"`, `"access"`, `"deploy"`, `"rotate"`, `"retire"`, `"modified"`, ...). El motor de reglas (`apate.rules`) suele filtrar condiciones sobre esta clave — ver sección 5.3, ejemplo de regla. |
| `detail` | Texto legible para humanos, sin estructura. |
| `ttp_id` | ID de MITRE ATT&CK (`"T1078"`, `"T1552.001"`, ...) — se espera en eventos `ttp_observed` (ver 3.2). |
| `source_ip` / `ip` | Se extrae como IoC de tipo `"ip"`. |
| `hash` / `file_hash` | Se extrae como IoC de tipo `"hash"`. |
| `credential` | Se extrae como IoC de tipo `"credential"`. **Nunca pongas acá el valor de una credencial real ni de un secreto verdadero** — ver la nota de seguridad en 3.4. |
| `domain` | Se extrae como IoC de tipo `"domain"`. |
| `url` | Se extrae como IoC de tipo `"url"`. |

Cualquier otra clave que uses (`path`, `target`, `command`, lo que necesite tu integración) no se pierde — queda disponible en el payload crudo para quien consuma el evento — pero tampoco se promueve automáticamente a IoC estructurado a menos que coincida con una de las claves de la tabla.

## 3.4 Nota de seguridad: qué no poner en un evento

Los eventos que publicás viajan por el `EventBus` a **todo** suscriptor activo (motor de reglas, telemetría, cualquier otro que se suscriba) y pueden terminar persistidos (telemetría los guarda en disco) o mostrados en la interfaz web. No incluyas en el `payload`:

- El valor real de credenciales o secretos de producción (aunque tu plugin trabaje con honeytokens/credenciales *sintéticas*, el valor de esas credenciales sintéticas tampoco tiene por qué viajar en el evento — `HoneytokenPlugin`, sección 4.2, publica `path`/`kind`/`detail`/`ttp_id`, nunca el valor de la credencial falsa que escribió en el archivo).
- Contenido sin sanitizar proveniente de una fuente no confiable (por ejemplo, texto crudo tecleado por un atacante en una sesión SSH) sin al menos truncarlo/escaparlo — nada en APATE ejecuta el contenido de un payload como código, pero sí puede terminar renderizado en una página HTML o en un log.

## 3.5 `EventBus`: mecánica de publicación

```python
class EventBus:
    def subscribe(self, event_type: EventType, handler: Callable[[PluginEvent], None]) -> None: ...
    def publish(self, event: PluginEvent) -> None: ...
```

- **Sincrónico, sin cola, sin hilos.** `bus.publish(event)` llama a cada handler suscripto a ese `event_type` **en el mismo hilo, antes de retornar**. Si tu `deploy()` llama a `self._publish(...)` y hay un motor de reglas suscripto cuya regla dispara una acción sobre tu propio plugin (por ejemplo, `rotate()`), esa llamada a `rotate()` sucede **dentro** de tu `deploy()`, antes de que `deploy()` termine. Diseñá tus métodos asumiendo que pueden ser reentrantes de esta forma.
- **Publicar sin suscriptores no es un error.** Podés (y probablemente vas a, en tests) instanciar un `EventBus` sin nada suscripto y publicar igual — simplemente no pasa nada del otro lado.
- **Una instancia de `EventBus` por operación**, compartida entre todos los plugins de esa operación (no una por plugin).

---

# 4. Ejemplo mínimo funcional

## 4.1 Adaptado de `MockHoneypotPlugin` (M2) — el más simple posible

```python
from __future__ import annotations

from apate.plugins import DeceptionPlugin, EventType, PluginLifecycleState


class MyExternalPlugin(DeceptionPlugin):
    """Ejemplo mínimo: un adaptador que no hace nada real todavía,
    solo cumple el contrato y emite eventos plausibles."""

    def deploy(self) -> None:
        self._require_state(PluginLifecycleState.CREATED, action="deploy")
        self._publish(
            EventType.INTERACTION,
            {
                "kind": "scan",
                "source_ip": self.config.get("source_ip", "203.0.113.10"),
                "detail": "Escaneo de puertos detectado.",
            },
        )
        self.state = PluginLifecycleState.DEPLOYED

    def rotate(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="rotate")
        self._publish(EventType.INTERACTION, {"kind": "rotate", "detail": "Identidad rotada."})
        # rotate() no cambia self.state: sigue DEPLOYED.

    def retire(self) -> None:
        self._require_state(PluginLifecycleState.DEPLOYED, action="retire")
        self._publish(EventType.INTERACTION, {"kind": "retire", "detail": "Plugin retirado."})
        self.state = PluginLifecycleState.RETIRED
```

Uso end-to-end, sin ningún otro módulo de APATE de por medio más que `EventBus`:

```python
from apate.plugins import EventBus, EventType

bus = EventBus()
bus.subscribe(EventType.INTERACTION, lambda e: print(e.event_type.value, e.payload))

plugin = MyExternalPlugin(
    plugin_id="mi-plugin-1",
    surface="network",
    operation_id="op-123",
    bus=bus,
    config={"source_ip": "198.51.100.7"},  # TEST-NET-2 (RFC 5737)
)
plugin.deploy()
# -> imprime: interaction {'kind': 'scan', 'source_ip': '198.51.100.7', 'detail': 'Escaneo de puertos detectado.'}
```

Un `deploy()` real (contra DOLOS-T, BUDA, o cualquier herramienta con estado externo) reemplazaría el cuerpo de `deploy()` por la llamada real (por ejemplo, un `requests.post()` al endpoint HTTP de esa herramienta) y construiría el `payload` a partir de la respuesta real, en vez de un valor fijo — la forma del evento publicado no cambia.

## 4.2 Un evento `ttp_observed`, adaptado de `HoneytokenPlugin.check_access()` (M7)

Para mostrar el patrón "interaction + ttp_observed" del que habla la sección 3.2, y el patrón de payload con `ttp_id`:

```python
def check_access(self) -> None:
    # ... (deteccion de que un senuelo fue tocado, omitida) ...
    self._publish(
        EventType.INTERACTION,
        {"kind": "access", "path": str(path), "detail": f"Honeytoken accedido: {path}"},
    )
    self._publish(
        EventType.TTP_OBSERVED,
        {
            "ttp_id": self.config.get("ttp_id", "T1552.001"),
            "path": str(path),
            "detail": "TTP observada por acceso a un honeytoken de archivo.",
        },
    )
```

Notá que ninguno de los dos payloads incluye el valor de ninguna credencial — solo la ruta del archivo y una descripción (ver 3.4).

---

# 5. Validaciones de M9 que le pegan a un plugin externo

Ninguna de estas corre dentro de tu plugin — corren en el motor de reglas (`apate.rules.RuleEngine`), que es quien decide **si** llamar a tu `deploy()`/`rotate()`/`retire()` en respuesta a una regla. Te afectan igual porque determinan si tu plugin llega a ejecutarse.

## 5.1 `PluginStateError` — tu propia responsabilidad

No es una validación externa: es la excepción que tu propio `_require_state()` lanza si alguien (el motor de reglas, un test, código a mano) invoca `deploy()`/`rotate()`/`retire()` en el estado equivocado. El motor de reglas **no la atrapa** — si tu método la lanza en medio de una cadena de acciones disparada por una regla, la excepción se propaga sin capturar hasta quien haya llamado a `bus.publish(...)` originalmente (potencialmente otro `deploy()` tuyo, si la reentrancia de la sección 3.5 aplica). Diseñá tu integración asumiendo que esto puede pasar y que nadie más la va a atajar por vos.

## 5.2 `UnknownPluginError` — alcance de plugin (M9)

Ojo con el matiz exacto: **esto no pasa por publicar un evento.** `EventBus.publish()` no valida nada contra `operation.plugins` — tu plugin puede publicar eventos libremente sin que nadie los rechace. Lo que sí se valida, y solo en ese momento, es cuando una `Rule` cargada en el `RuleEngine` matchea uno de tus eventos y su acción (`Action`, con `kind` en `deploy`/`rotate`/`retire`) intenta dirigirse de vuelta a un `plugin_id` específico.

En ese momento (`RuleEngine._resolve_targets`), se validan **dos** cosas, ambas necesarias:

1. Que `plugin_id` esté en el diccionario de plugins vivos con el que se construyó el `RuleEngine` (`RuleEngine(plugins={...})`) — es decir, que exista una instancia real a la que llamarle el método.
2. Que ese mismo `plugin_id` tenga un `PluginBinding` en `operation.plugins` — es decir, que la `Operation` lo haya vinculado explícitamente vía `operation.bind_plugin(PluginBinding(plugin_id=..., surface=...))`.

Si falta cualquiera de las dos, se levanta `UnknownPluginError` (de `apate.rules`) — **salvo** que la acción no tenga `plugin_id` explícito (`Action(kind=..., plugin_id=None)`, que significa "todos los plugins registrados"): en ese caso, en vez de lanzar, el motor simplemente **excluye en silencio** (con un log de advertencia) los plugins que fallen el segundo chequeo, para no bloquear una acción masiva (por ejemplo, "retirar todos los plugins al cerrar la operación") por un solo plugin mal vinculado.

**Implicación práctica para tu integración:** el `plugin_id` con el que instancias tu plugin, el `plugin_id` bajo el que lo registrás en el `dict` que le pasás al `RuleEngine`, y el `plugin_id` del `PluginBinding` que agregaste a la `Operation` vía `operation.bind_plugin(...)` **tienen que ser el mismo string exacto en los tres lugares**. Si alguno no coincide, tu plugin puede desplegarse y emitir eventos sin problema, pero cualquier regla que intente actuar sobre él (rotarlo, retirarlo) va a fallar con `UnknownPluginError` en cuanto se dispare.

## 5.3 `RulesOfEngagement.permits()` — políticas por operación (M9)

Antes de ejecutar **cualquier** `Action` (incluidas las que apuntan a tu plugin), el motor de reglas consulta:

```python
operation.roe.permits(*action.signatures())
```

`RulesOfEngagement` (de `apate.core`) tiene dos listas de texto libre, `allowed_actions` y `forbidden_actions`. `Action.signatures()` (de `apate.rules`) genera hasta tres strings de "firma" por cada acción, y `permits()` los contrasta contra esas dos listas:

- `"<kind>"` — por ejemplo `"deploy"`, `"rotate"`, `"retire"` (siempre presente).
- `"<kind>:<plugin_id>"` — por ejemplo `"retire:mi-plugin-1"` (si la acción tiene `plugin_id`).
- `"transition:<destino>"` — por ejemplo `"transition:closed"` (solo para acciones de transición de estado, no relevante para tu plugin directamente).

Reglas de `permits()`:

- Si **cualquiera** de esas firmas está en `forbidden_actions`, la acción se rechaza.
- Si `allowed_actions` **no está vacía**, la acción también se rechaza a menos que **alguna** de sus firmas esté ahí (allowlist). Una `allowed_actions` vacía no restringe nada (comportamiento por defecto de cualquier operación que nunca configuró una allowlist).

**Qué pasa si tu plugin queda bloqueado por esto:** no se te llama al método en absoluto (ni `deploy()`, ni `rotate()`, ni `retire()`) — no hay excepción, no hay ningún callback de "fuiste rechazado" hacia tu plugin. El rechazo queda registrado del lado del motor, en `RuleEngine.rejected_actions` (una lista de `RejectedAction`, con `rule_name`, la `Action` completa, y el motivo como texto), y se loguea con `logging.getLogger("apate.rules.engine").warning(...)`. Si tu integración necesita saber si fue bloqueada, tiene que consultar esa lista desde el lado de quien construyó el `RuleEngine` — tu plugin no se entera por sí solo.

Un ejemplo concreto: si la operación se creó con

```python
RulesOfEngagement(forbidden_actions=["retire:mi-plugin-1"])
```

entonces ninguna regla va a poder retirar `mi-plugin-1`, sin importar qué regla lo intente ni cuántas veces — `deploy()` y `rotate()` sobre ese mismo plugin siguen permitidos, porque la firma prohibida es específica de `retire`.

---

# 6. Registrarte de verdad: `PluginRegistry` y `entry_points` (Fase 5 post-BlackHat)

Todo lo de las secciones 1-5 alcanza para que tu clase **funcione** como plugin si alguien la instancia
a mano (`MyExternalPlugin(plugin_id=..., ...)`) y la pasa al `RuleEngine`/al resto de `apate` por su
cuenta — así es como se probó el ejemplo de la sección 4. Pero APATE (el catálogo en `/plugins`, M13i,
y cualquier código que resuelva un plugin por `kind` en vez de por clase importada a mano) no sabe que
tu clase existe hasta que la **registrás**. Desde la Fase 5 (ver `docs/roadmap.md`), eso ya no requiere
tocar ningún archivo de APATE — se hace 100% desde tu propio paquete.

## 6.1 Cómo se descubre un plugin

`apate.plugins.registry.PluginRegistry` no importa ninguna clase de plugin a mano — consulta
`importlib.metadata.entry_points(group="apate.plugins")` en cada llamada (sin cachear, a propósito: una
consulta fresca es barata para el volumen de esta app, y evita que quedar cacheado desincronice el
registro si se instala/desinstala un plugin durante el mismo proceso). Los plugins "de fábrica"
(`mock`/`honeytoken`/`dolost`/`buda`/`canarytoken`) se registran exactamente por el mismo mecanismo que
usaría tu paquete de terceros — no tienen ningún trato especial ni atajo. `canarytoken_plugin.py`
(`apate.plugins.canarytoken_plugin.CanarytokenPlugin`) es, de hecho, el primero de los cinco que se
construyó explícitamente evaluando (y descartando, con el argumento documentado en su propio docstring)
vivir como paquete separado en vez de en el repo — un ejemplo real de esa decisión, no solo teórica.

## 6.2 Declarar el entry point

En el `pyproject.toml` de **tu propio paquete** (no el de APATE):

```toml
[project.entry-points."apate.plugins"]
mi-herramienta = "mi_paquete.plugin:MyExternalPlugin"
```

El nombre a la izquierda (`mi-herramienta`) es el `kind` — el string corto por el que se va a resolver
tu plugin (`PluginRegistry.get("mi-herramienta")`, o `plugin_kind="mi-herramienta"` en un
`PluginBinding` desde la interfaz web, ver `docs/roadmap.md` sección M12h para ese lado). El valor a la
derecha es la ruta punteada `módulo:Clase` de tu implementación de `DeceptionPlugin`. Con tu paquete
instalado en el mismo entorno que APATE (`pip install -e .` desde tu propio repo, o publicado en un
índice), APATE lo descubre solo — sin editar `apate/plugins/registry.py` ni ningún otro archivo del
repositorio de APATE.

**Ojo con la reinstalación:** `entry_points()` lee metadata generada al instalar el paquete
(`*.dist-info/entry_points.txt`), no el `pyproject.toml` en sí. Si editás la sección
`[project.entry-points."apate.plugins"]` de un paquete ya instalado en modo editable, hace falta
reinstalarlo (`pip install -e . --no-deps`) para que el cambio se vea reflejado — cambiar el archivo
solo no alcanza.

## 6.3 Metadata de catálogo: `plugin_description`

Opcional, pero recomendado si tu plugin va a aparecer en `/plugins` (el catálogo de M13i) con
información legible en vez de un respaldo genérico:

```python
from apate.plugins import DeceptionPlugin
from apate.plugins.registry import PluginDescription


class MyExternalPlugin(DeceptionPlugin):
    plugin_description = PluginDescription(
        kind="mi-herramienta",
        display_name="Mi Herramienta",
        description="Qué hace, en una oración, para quien lo lea en el catálogo.",
        surface="Superficie que cubre (texto libre, ej. \"Red / host\")",
    )

    def deploy(self) -> None: ...
```

Es un `ClassVar` (`DeceptionPlugin.plugin_description: ClassVar[Optional[PluginDescription]] = None`
en la base) — se declara una sola vez a nivel de clase, no por instancia. Si no lo declarás, tu plugin
igual queda descubierto y usable: `PluginRegistry.describe()` arma una `PluginDescription` de respaldo
(`display_name` = nombre de tu clase, `surface` = `"Sin especificar"`, con una nota de que no declaró
metadata propia) en vez de fallar — sumar un plugin sin metadata curada es un caso degradado, no un
error. El `kind` que declares en `plugin_description` no tiene por qué coincidir con la clave del entry
point (aunque debería): `PluginRegistry.describe()` lo corrige siempre para que coincida con la clave
por la que se buscó, vía `dataclasses.replace()` — una red de seguridad, no una forma de tener dos
kinds con el mismo `plugin_description`.

**Si querés que tu metadata se traduzca**, envolvé `display_name`/`description`/`surface` con
`lazy_gettext()` de `apate.i18n`, como hacen las seis implementaciones nativas:

```python
from apate.i18n import lazy_gettext

    plugin_description = PluginDescription(
        kind="mi-herramienta",
        display_name=lazy_gettext("Mi Herramienta"),
        ...
    )
```

Tiene que ser **`lazy_gettext()` y no `gettext()`**: un `ClassVar` se construye al importar el módulo
del plugin, así que una traducción normal quedaría congelada en el idioma que estuviera activo al
arrancar el proceso. `LazyString` resuelve recién al convertirse a texto, ya dentro de la request. Si
tu plugin vive en su propio paquete vas a necesitar además tu propio catálogo gettext: el de APATE
(`apate/web/translations/`) solo cubre las frases de APATE. Sin nada de esto tu metadata se muestra
tal cual la escribiste, en cualquier idioma — degradado, no un error.

## 6.4 API del registro, si necesitás consultarlo en tu propio código

```python
from apate.plugins.registry import PluginRegistry

PluginRegistry.get("mi-herramienta")           # -> tu clase, ya importada real (EntryPoint.load())
PluginRegistry.list_kinds()                    # -> ["buda", "canarytoken", "dolost", "honeytoken", "mi-herramienta", "mock", "opencanary"]
PluginRegistry.describe("mi-herramienta")      # -> tu PluginDescription (o el respaldo)
PluginRegistry.list_descriptions()             # -> una PluginDescription por kind, mismo orden que list_kinds()
```

`list_kinds()` **no garantiza ningún orden específico** — es el que devuelva
`importlib.metadata.entry_points()`, que en la práctica resultó alfabético por nombre de entry point en
este entorno, pero no es un contrato. No escribas código (ni tests) que dependa de un orden particular.

---

# 7. Checklist final

- [ ] Tu clase hereda de `apate.plugins.DeceptionPlugin` e implementa `deploy()`, `rotate()`, `retire()` — sin parámetros propios, sin retorno.
- [ ] Cada uno de esos tres métodos empieza con `self._require_state(<estado esperado>, action="...")`.
- [ ] `deploy()` termina con `self.state = PluginLifecycleState.DEPLOYED`; `retire()` termina con `self.state = PluginLifecycleState.RETIRED`; `rotate()` no toca `self.state`.
- [ ] Publicás eventos con `self._publish(event_type, payload)`, no construyendo `PluginEvent` a mano (salvo que tengas una razón concreta para hacerlo distinto).
- [ ] Usás `EventType.INTERACTION` para "algo pasó" y `EventType.TTP_OBSERVED` (con `payload["ttp_id"]`) cuando identificás una técnica MITRE ATT&CK concreta.
- [ ] Ningún `payload` que publiques incluye el valor de una credencial o secreto real (sintético o no).
- [ ] El `plugin_id` con el que instanciás tu plugin coincide exactamente con el `plugin_id` del `PluginBinding` en `operation.plugins` y con la clave bajo la que se registra en el `dict` de plugins del `RuleEngine`.
- [ ] Si tu integración necesita saber qué acciones fueron bloqueadas por política, consultá `RuleEngine.rejected_actions` — no vas a recibir ningún callback en tu propio plugin.
- [ ] Declaraste el entry point en el `pyproject.toml` de tu propio paquete
      (`[project.entry-points."apate.plugins"]`, sección 6.2) y lo reinstalaste si ya estaba instalado
      en modo editable — si no, `PluginRegistry`/el catálogo `/plugins` no van a encontrar tu clase.
- [ ] (Opcional) Declaraste `plugin_description` (sección 6.3) si querés que tu plugin se vea con
      información real en el catálogo en vez del respaldo genérico.
- [ ] (Opcional) Si esa metadata tiene que traducirse, la envolviste con `lazy_gettext()` y no con
      `gettext()` — es un `ClassVar`, y una traducción normal quedaría congelada en el idioma del
      arranque (sección 6.3).
