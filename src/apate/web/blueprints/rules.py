"""Vista para consultar y editar el archivo YAML de reglas.

El proceso web valida y guarda el archivo. No ejecuta RuleEngine en
segundo plano; otro proceso puede cargar las reglas actualizadas.
"""

from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from ...rules import RuleDefinitionError, parse_rules
from ..i18n import translate

rules_bp = Blueprint("rules", __name__, url_prefix="/rules")


@rules_bp.route("/", methods=["GET"])
def show_rules():
    path = current_app.config["APATE_RULES_PATH"]
    text = path.read_text(encoding="utf-8")
    rules, error = _try_parse(text)
    return render_template("rules/index.html", rules=rules, rules_text=text, error=error)


@rules_bp.route("/", methods=["POST"])
def save_rules():
    path = current_app.config["APATE_RULES_PATH"]
    text = request.form["rules_text"]

    rules, error = _try_parse(text)
    if error is not None:
        flash(translate("No se guardó: {}").format(error), "error")
        return render_template("rules/index.html", rules=[], rules_text=text, error=error), 400

    path.write_text(text, encoding="utf-8")
    flash(translate("Reglas guardadas y recargadas: {} regla(s).").format(len(rules)), "success")
    return redirect(url_for("rules.show_rules"))


def _try_parse(text: str):
    try:
        return parse_rules(text), None
    except RuleDefinitionError as exc:
        return [], str(exc)
