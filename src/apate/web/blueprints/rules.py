"""Vista de Reglas (M4b): ver y editar el YAML de reglas del motor de
decision (M3) sin tocar codigo.

**Constructor visual (referencia declarada: CounterCraft, cuya
interfaz de reglas es drag-and-drop) -- ver `rules/index.html`.**
Drag-and-drop se evaluo y se descarto (caro y fragil para lo que
realmente resuelve el problema real: no es arrastrar cajas, es no
tener que recordar la sintaxis/los nombres de campo del YAML). En
cambio, un formulario con selects poblados desde valores reales
(`EventType`, `ActionKind`, `OperationStatus` para transiciones, y los
`plugin_id` realmente vinculados a operaciones existentes, via
`known_plugin_ids` mas abajo) arma el YAML de UNA regla nueva del lado
del cliente y la inserta en el mismo editor CodeMirror de abajo --
"reusa el mismo `parse_rules()` de siempre" se cumple literal: el
constructor nunca valida ni guarda nada por su cuenta, solo genera
texto que termina pasando por el mismo `_try_parse()`/`save_rules()`
de siempre, exactamente como si el operador lo hubiera tecleado a
mano. Sin endpoint nuevo para "construir" -- toda la generacion de
YAML es JS puro (sin logica de parseo, solo armar un bloque de texto
con formato fijo), este modulo solo agrega los tres iterables de
opciones (`event_types`/`action_kinds`/`transition_targets`) y
`known_plugin_ids` al contexto de `show_rules()`.

**Alcance deliberadamente limitado a "crear", no "editar" -- ver
docstring de `rules/index.html` para el detalle completo de por que.**

"Recargar el motor" en este hito significa: validar el YAML nuevo
(parse_rules), y si es valido, sobreescribir el archivo en
APATE_RULES_PATH. No hay un RuleEngine corriendo en background contra
un bus real dentro del proceso web (eso requiere plugins y una
operacion activos, que en este hito no gestiona la UI todavia - ver
M5/M7): cualquier proceso que si tenga un RuleEngine corriendo
consulta ese mismo archivo via `apate.rules.load_rules(path)`, y ve
las reglas nuevas la proxima vez que lo lea. La vista siempre lee el
archivo en el momento de la request, asi que no hace falta ademas
mantener una cache en memoria para "refrescar".

Desde M13c, ademas, `validate_rules()`: validacion en linea mientras
el operador tipea (editor CodeMirror en rules/index.html, fetch()
debounced), reusando `_try_parse()` tal cual -- nunca escribe en
APATE_RULES_PATH, `save_rules()` sigue siendo la unica via que
sobreescribe el archivo y la unica fuente de verdad real. No se
reimplementa la semantica de `parse_rules()`/`RuleDefinitionError` en
JavaScript: el editor solo le pega a este endpoint y muestra lo que
devuelve."""

from __future__ import annotations

from typing import Optional

from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, request, url_for

from ...core import OperationStatus
from ...plugins import EventType
from ...rules import ActionKind, RuleDefinitionError, parse_rules, replay_rules
from ...atomic_write import write_text_atomically

rules_bp = Blueprint("rules", __name__, url_prefix="/rules")

# Unicos destinos de transicion que una regla puede disparar de verdad
# (Action.__post_init__, apate.rules.models) -- PLANNING queda afuera
# porque ninguna transicion vuelve a ese estado. No se importa la
# constante privada del motor (_VALID_TRANSITION_TARGETS): se deriva
# del mismo enum publico filtrando el unico valor que esa validacion
# ya excluye, sin duplicar la lista de valores validos a mano.
_TRANSITION_TARGETS = [status for status in OperationStatus if status != OperationStatus.PLANNING]


def _known_plugin_ids() -> list[str]:
    """`plugin_id` realmente vinculados a alguna operacion existente --
    sugerencias para el constructor visual (`<datalist>`, texto libre
    igual, no una restriccion: una regla puede referirse a un
    `plugin_id` que todavia no existe)."""

    operations = current_app.config["OPERATION_REPOSITORY"].list()
    return sorted({binding.plugin_id for operation in operations for binding in operation.plugins})


def _render_rules_page(*, rules: list, rules_text: str, error: Optional[str]):
    """Comun a `show_rules()` y al camino de error de `save_rules()` --
    las dos rutas que renderizan `rules/index.html` (a diferencia de
    `validate_rules()`, que solo devuelve JSON). Centraliza el
    contexto que el constructor visual necesita
    (`event_types`/`action_kinds`/`transition_targets`/
    `known_plugin_ids`) para que no queden Undefined en el camino de
    error de `save_rules()` (400, YAML invalido)."""

    return render_template(
        "rules/index.html",
        rules=rules,
        rules_text=rules_text,
        error=error,
        event_types=list(EventType),
        action_kinds=list(ActionKind),
        transition_targets=_TRANSITION_TARGETS,
        known_plugin_ids=_known_plugin_ids(),
    )


@rules_bp.route("/", methods=["GET"])
def show_rules():
    path = current_app.config["APATE_RULES_PATH"]
    text = path.read_text(encoding="utf-8")
    rules, error = _try_parse(text)
    return _render_rules_page(rules=rules, rules_text=text, error=error)


@rules_bp.route("/", methods=["POST"])
def save_rules():
    path = current_app.config["APATE_RULES_PATH"]
    text = request.form["rules_text"]

    rules, error = _try_parse(text)
    if error is not None:
        flash(f"No se guardo: {error}", "error")
        return _render_rules_page(rules=[], rules_text=text, error=error), 400

    # Bug real encontrado verificando el constructor visual con un
    # navegador real (Playwright), no con el test client de Flask (que no
    # reproduce el envio real de un <textarea>): el HTML/HTTP de un form
    # normaliza el contenido de un <textarea> a CRLF al enviarlo, y
    # Path.write_text() en Windows (modo texto, sin `newline=`) ademas
    # traduce cada "\n" a os.linesep -- sobre un texto que YA tenia "\r\n",
    # eso duplica el retorno de carro ("\r\r\n") en cada guardado real
    # desde un navegador, empeorando en cada ciclo editar->guardar.
    # parse_rules()/YAML nunca lo detecta (YAML trata \r\n/\r/\n por
    # igual), asi que quedaba invisible -- se normaliza a LF antes de
    # escribir, consistente con el resto del repo (.gitattributes:
    # `* text=auto eol=lf`), y `newline="\n"` evita que write_text() lo
    # vuelva a traducir.
    normalized_text = text.replace("\r\n", "\n").replace("\r", "\n")
    #
    # Y se escribe de forma atomica porque este es el archivo que el motor de
    # reglas relee: un guardado interrumpido dejaba un YAML cortado, y la
    # siguiente recarga se encontraba sin reglas o con la mitad.
    # `write_text_atomically()` fija `newline="\n"` siempre, asi que la
    # normalizacion de arriba no se vuelve a traducir en Windows.
    revisions = current_app.config["RULE_REVISION_REPOSITORY"]
    revisions.save(path.read_text(encoding="utf-8"))
    revisions.save(normalized_text)
    write_text_atomically(path, normalized_text)
    flash(f"Reglas guardadas y recargadas: {len(rules)} regla(s).", "success")
    return redirect(url_for("rules.show_rules"))


@rules_bp.get("/replay/<operation_id>")
def replay(operation_id: str):
    """Inspecciona decisiones contrafácticas sin tocar conectores."""

    from .operations import _get_operation_or_404

    operation = _get_operation_or_404(operation_id)
    revisions = current_app.config["RULE_REVISION_REPOSITORY"]
    current_text = current_app.config["APATE_RULES_PATH"].read_text(encoding="utf-8")
    revision = request.args.get("revision", "")
    try:
        text = revisions.get(revision) if revision else current_text
    except (KeyError, ValueError):
        abort(404)
    records = current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
    result = replay_rules(operation, records, text)
    return render_template("rules/replay.html", operation=operation, result=result,
                           selected_revision=revision, revisions=revisions.list())


@rules_bp.route("/validate", methods=["POST"])
def validate_rules():
    """Validacion en linea (M13c) sobre el YAML tal cual esta en el
    editor en este momento -- nunca toca `APATE_RULES_PATH`, no llama
    `path.write_text()` en ningun camino. Mismo `_try_parse()` que
    `save_rules()`, sin duplicar la logica de parseo: si algun dia
    `parse_rules()` cambia, este endpoint y el guardado real quedan
    sincronizados automaticamente, no hay una segunda copia de la
    semantica que se pueda desviar."""

    text = request.form.get("rules_text", "")
    rules, error = _try_parse(text)
    if error is not None:
        return jsonify({"valid": False, "error": error})
    return jsonify({"valid": True, "rule_count": len(rules)})


def _try_parse(text: str):
    try:
        return parse_rules(text), None
    except RuleDefinitionError as exc:
        return [], str(exc)
