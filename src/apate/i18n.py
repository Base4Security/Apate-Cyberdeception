"""Traduccion degradable: el mismo `_()` sirve dentro y fuera de Flask.

APATE nacio en espanol y ese sigue siendo el **idioma fuente**: los
`msgid` del catalogo son las frases en espanol tal como estaban escritas,
y el ingles vive como traduccion en `apate/web/translations/en`. La
alternativa (invertir a ingles como fuente) obligaria a reescribir las 40
plantillas, los 217 `flash()` y los asserts de copy de 88 archivos de test
en una sola tanda; con el espanol como fuente, el texto renderizado en
locale `es` es identico byte a byte al de antes de existir este modulo.

**Por que no se importa `flask_babel` directamente donde se necesita:**
el texto visible no vive solo en `apate.web`. `apate.reporting` arma los
encabezados del informe y del kit de taller, `apate.plugins` declara la
metadata del catalogo de capacidades y `apate.assets` valida el CSV del
inventario -- ninguno de los tres depende de Flask, y no deberian
empezar a depender (el nucleo se mantiene sin dependencias externas, ver
`docs/diseno.md` seccion 1). `gettext()` de este modulo delega en
`flask_babel` **solo si hay contexto de aplicacion con la extension
inicializada**, y en cualquier otro caso devuelve el `msgid` -- que es la
frase en espanol. Asi `generate_report()` sigue funcionando desde
`examples/seed_demo.py`, desde un test sin app y desde una ruta web, sin
que quien la llama tenga que saber en cual de los tres esta.

`lazy_gettext()` existe para el texto que se evalua en tiempo de import,
antes de que exista ninguna request: el caso real es
`DeceptionPlugin.plugin_description`, un `ClassVar` construido al importar
el modulo del plugin. Traducirlo con `gettext()` congelaria el idioma del
arranque; el proxy resuelve recien al convertirse a texto.
"""

from __future__ import annotations

from typing import Any

#: Idioma fuente del proyecto y default de toda la aplicacion.
DEFAULT_LOCALE = "es"

#: Idiomas con catalogo propio. El orden es el del selector visible.
SUPPORTED_LOCALES: tuple[str, ...] = ("es", "en")

#: Nombre de cada idioma en si mismo -- nunca traducido: quien busca
#: "English" en un menu no lo reconoce como "Ingles".
LOCALE_NAMES: dict[str, str] = {"es": "Español", "en": "English"}


#: Funciones que marcan texto traducible, para `pybabel extract`. Vive aca
#: y no en `babel.cfg` (que solo describe que archivos leer) para que el
#: test de sincronizacion del catalogo y el comando de linea usen la misma
#: lista: dos definiciones separadas se desincronizarian, que es justo el
#: problema que ese test existe para evitar.
#:
#: El flujo de trabajo completo, desde la raiz del repo:
#:
#:     pybabel extract -F babel.cfg -k gettext_noop -k lazy_gettext #:         --no-location -o src/apate/web/translations/messages.pot .
#:     pybabel update -i src/apate/web/translations/messages.pot #:         -d src/apate/web/translations
#:     # ... traducir lo nuevo en en/LC_MESSAGES/messages.po ...
#:     pybabel compile -d src/apate/web/translations
#:
#: `_` y `N_` ya son palabras clave por defecto de Babel.
EXTRACTION_KEYWORDS: tuple[str, ...] = ("gettext_noop", "lazy_gettext")


def _translate(message: str) -> str:
    """Resuelve contra el catalogo activo, o devuelve el `msgid`.

    Degradar al `msgid` no es un modo de error: el `msgid` **es** la
    frase en espanol, asi que fuera de una request la salida sigue
    siendo texto correcto para un usuario.
    """

    try:
        from flask import current_app, has_app_context
        from flask_babel import gettext as _flask_gettext
    except ImportError:  # pragma: no cover - Flask siempre esta instalado
        return message

    if not has_app_context():
        return message
    # `Babel(app)` puede no haberse inicializado todavia (o no existir,
    # en una app de prueba minima): pedir la traduccion ahi lanzaria.
    if "babel" not in current_app.extensions:
        return message
    return str(_flask_gettext(message))


def gettext(message: str, **variables: Any) -> str:
    """Traduce `message` e interpola `variables` con formato `%`.

    La interpolacion se hace siempre aca, no en `flask_babel`, para que
    el resultado sea el mismo con y sin contexto de aplicacion.
    """

    translated = _translate(message)
    return translated % variables if variables else translated


def gettext_noop(message: str) -> str:
    """Marca una frase para el catalogo sin traducirla todavia.

    Sirve para el texto que se declara lejos de donde se muestra -- el caso
    real son los diccionarios de `apate.web._enum_labels`, construidos al
    importar el modulo pero leidos durante una request. Envolverlos con
    `lazy_gettext()` cambiaria el tipo de sus valores de `str` a proxy y con
    el las firmas de todas las funciones que los leen; con este marcador el
    diccionario sigue siendo `dict[str, str]` y la traduccion ocurre en la
    funcion de acceso, que ya corre con la request activa.

    Devuelve el mensaje intacto: lo unico que hace es dejarlo visible para
    `pybabel extract` (ver `babel.cfg`).
    """

    return message


class LazyString:
    """Texto que se traduce recien al convertirse en `str`.

    Delega en el texto ya resuelto todo lo que no implementa (`.lower()`,
    `.startswith()`, ...), asi puede ocupar el lugar de un `str` en un
    dataclass de metadata sin que quien lo consume note la diferencia.
    """

    __slots__ = ("_message", "_variables")

    def __init__(self, message: str, **variables: Any) -> None:
        self._message = message
        self._variables = variables

    def __str__(self) -> str:
        return gettext(self._message, **self._variables)

    def __repr__(self) -> str:
        return f"LazyString({self._message!r})"

    @property
    def source_text(self) -> str:
        """El msgid sin traducir, para consumidores que no son la interfaz.

        `str()` resuelve al idioma activo, que es lo correcto en pantalla y
        lo incorrecto en un documento que tiene que ser identico en cada
        generacion: `apate.sbom` escribe el mismo SBOM corra donde corra, y
        para eso necesita el texto fuente, no el del operador que lo pidio.

        Existe como propiedad real y no como acceso a `_message` porque
        `__getattr__` delega en `str(self)`: sin esto, `.source_text` le
        preguntaria al texto ya traducido por un atributo que no tiene.
        """

        return self._message

    # Jinja marca como seguro lo que expone __html__; no se hace, para
    # que el autoescape trate esto como cualquier otro texto.

    def __eq__(self, other: object) -> bool:
        return str(self) == other if isinstance(other, str) else NotImplemented

    def __hash__(self) -> int:
        return hash(str(self))

    def __len__(self) -> int:
        return len(str(self))

    def __contains__(self, item: object) -> bool:
        return str(item) in str(self)

    def __add__(self, other: object) -> str:
        return str(self) + str(other)

    def __radd__(self, other: object) -> str:
        return str(other) + str(self)

    def __getattr__(self, name: str) -> Any:
        return getattr(str(self), name)


def lazy_gettext(message: str, **variables: Any) -> LazyString:
    """Version diferida de `gettext()` para texto de tiempo de import."""

    return LazyString(message, **variables)
