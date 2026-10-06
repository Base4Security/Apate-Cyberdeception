"""Registro formal de plugins (M12h, ver docs/roadmap.md seccion M12h),
mas el catalogo de metadata legible para operadores (M13i) -- Fase 5
post-BlackHat (ver docs/roadmap.md): descubrimiento real via entry
points en vez de un dict estatico `kind -> clase` fijado en este
modulo.

Hasta la Fase 5, `_REGISTRY` importaba directo las cuatro clases
concretas (`MockHoneypotPlugin`/`HoneytokenPlugin`/`DolosTPlugin`/
`BudaPlugin`) -- sumar un plugin nuevo, aunque fuera de terceros,
exigia tocar este archivo. Ahora `PluginRegistry` consulta
`importlib.metadata.entry_points(group="apate.plugins")`: cualquier
paquete instalado (incluido `apate` mismo, para sus cuatro plugins
"de fabrica") que declare un entry point en ese grupo queda
descubierto en runtime, sin que este modulo sepa de antemano que
clases van a existir. Los cuatro kinds canonicos siguen siendo
`mock`/`honeytoken`/`dolost`/`buda` -- ahora declarados en
`pyproject.toml` (`[project.entry-points."apate.plugins"]`) en vez de
en este dict.

**Consecuencia para `list_kinds()`, documentada porque cambia respecto
de antes:** el orden ya no esta garantizado como mock-primero-siempre
(eso era una propiedad de un dict literal, no un contrato) -- es el
orden que devuelve `importlib.metadata.entry_points()`, que en la
practica (verificado en este entorno) ordena alfabeticamente por
nombre de entry point (`buda, dolost, honeytoken, mock`), no por orden
de declaracion en `pyproject.toml` (que se mantuvo mock/honeytoken/
dolost/buda solo por legibilidad del archivo, sin efecto en el orden
real). Ningun test depende de un orden especifico de `list_kinds()`
despues de esta fase -- los que antes lo hacian se ajustaron para
comparar contra `set()`/`sorted()`.

**Metadata de catalogo (M13i), reubicada:** antes vivia en un dict
aparte (`_DESCRIPTIONS`) sincronizado a mano contra `_REGISTRY` -- con
descubrimiento dinamico eso ya no es sostenible (este modulo no tiene
la lista de clases de antemano para poblar un dict paralelo). Pasa a
ser un atributo de clase opcional, `DeceptionPlugin.plugin_description`
(`ClassVar`, `apate.plugins.base`) que cada implementacion declara
sobre si misma; `PluginRegistry.describe()` lo lee de la clase
resuelta. Un plugin de terceros que no lo declare no rompe el
catalogo: `describe()` arma una `PluginDescription` de respaldo en vez
de fallar, para que sumar un plugin sin metadata curada sea un caso
degradado, no un error."""

from __future__ import annotations

from dataclasses import dataclass, replace
from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING

from ..i18n import gettext as _
from .base import DeceptionPlugin
from .exceptions import PluginConfigError

if TYPE_CHECKING:
    from ..core.models import PluginBinding

# Mismo nombre de grupo documentado en pyproject.toml
# ([project.entry-points."apate.plugins"]) -- constante para no
# repetir el literal en cada llamada a entry_points().
_ENTRY_POINT_GROUP = "apate.plugins"


@dataclass(frozen=True)
class PluginDescription:
    """Metadata legible de un kind de plugin -- pensada para una
    tarjeta de catalogo (M13i), no para logica de negocio. `surface`
    es texto libre en espanol, coherente con el vocabulario que ya usan
    los docstrings de `DolosTPlugin`/`BudaPlugin` ("superficie
    red/host"/"superficie identidad/comportamiento") pero no es el
    mismo campo que `PluginBinding.surface` (ese es libre, por
    operacion; este es fijo, por kind, a nivel de catalogo)."""

    kind: str
    display_name: str
    description: str
    surface: str


def _fallback_description(kind: str, cls: type[DeceptionPlugin]) -> PluginDescription:
    """Respaldo para un plugin descubierto via entry point que no
    declara `plugin_description` -- el caso esperable de un plugin de
    terceros que todavia no sumo metadata curada. El catalogo (M13i)
    lo muestra igual, en vez de que `describe()`/`list_descriptions()`
    exploten por un kind valido sin metadata."""

    return PluginDescription(
        kind=kind,
        display_name=cls.__name__,
        description=(
            f"Plugin de terceros descubierto via entry point ('{cls.__module__}.{cls.__qualname__}'), "
            "sin metadata de catalogo declarada (DeceptionPlugin.plugin_description)."
        ),
        surface="Sin especificar",
    )


def _discover() -> dict[str, EntryPoint]:
    """Kind -> EntryPoint tal cual lo reporta `importlib.metadata`, sin
    resolver la clase todavia (`EntryPoint.load()` recien en `get()`).
    Sin cachear a proposito: una consulta fresca por llamada es
    despreciable en costo para el volumen de esta app (no es un hot
    path) y evita que un registro cacheado quede desactualizado si se
    instala/desinstala un plugin de terceros durante el mismo proceso,
    o que un test que instala un entry point falso via monkeypatch
    tenga que lidiar con una cache stale de otra corrida."""

    return {ep.name: ep for ep in entry_points(group=_ENTRY_POINT_GROUP)}


class PluginRegistry:
    """Fachada de solo lectura sobre los plugins descubiertos via entry
    points y su metadata legible (M13i). No es instanciable con estado
    propio a proposito -- get()/list_kinds()/describe()/
    list_descriptions() son staticmethod para dejar eso explicito."""

    @staticmethod
    def get(kind: str) -> type[DeceptionPlugin]:
        entry_point = _discover().get(kind)
        if entry_point is None:
            raise PluginConfigError(
                _(
                    "'%(kind)s' no es un plugin_kind registrado (kinds disponibles: %(kinds)s).",
                    kind=kind,
                    kinds=sorted(_discover()),
                )
            )
        return entry_point.load()

    @staticmethod
    def list_kinds() -> list[str]:
        return list(_discover())

    @staticmethod
    def resolve_binding_kind(binding: "PluginBinding") -> str | None:
        """Resuelve el kind ejecutable de un binding de Operacion.

        El ``plugin_kind`` explícito es la fuente de verdad. Para los
        bindings persistidos antes de que existiera ese campo se conserva
        el prefijo del ``plugin_id`` como compatibilidad legacy, pero solo
        si coincide exactamente con un kind descubierto. Centralizar esta
        regla evita que Playground dependa de ``apate.web`` para construir
        los plugins que usará el motor de reglas.
        """

        registered = set(PluginRegistry.list_kinds())
        if binding.plugin_kind in registered:
            return binding.plugin_kind
        if binding.plugin_kind is not None:
            return None

        prefix = binding.plugin_id.lower().split("-", 1)[0]
        return prefix if prefix in registered else None

    @staticmethod
    def describe(kind: str) -> PluginDescription:
        cls = PluginRegistry.get(kind)
        description = cls.plugin_description
        if description is None:
            return _fallback_description(kind, cls)
        # dataclasses.replace() en vez de devolver el atributo tal
        # cual: garantiza que el `kind` devuelto coincide siempre con
        # la clave por la que se busco, aunque la clase haya declarado
        # un valor desactualizado (ej. copiar/pegar de otro kind).
        return replace(description, kind=kind)

    @staticmethod
    def list_descriptions() -> list[PluginDescription]:
        """Mismo orden que `list_kinds()` (ver docstring del modulo
        sobre que garantiza ese orden ahora)."""

        return [PluginRegistry.describe(kind) for kind in PluginRegistry.list_kinds()]
