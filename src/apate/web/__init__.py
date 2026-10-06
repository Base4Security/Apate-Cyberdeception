"""Interfaz local de Apate Core para operaciones, reglas y telemetría.

La aplicación Flask usa los repositorios y colectores del núcleo abierto.
No ejecuta un motor de reglas en segundo plano ni requiere servicios externos.
"""

from __future__ import annotations

from pathlib import Path
import hmac
import secrets
from typing import Any, Optional

from flask import Flask, abort, redirect, request, session, url_for

from ..core import JSONFileOperationRepository
from ..telemetry import JSONFileTelemetryRepository, TelemetryCollector
from .blueprints.operations import operations_bp
from .blueprints.rules import rules_bp
from .blueprints.telemetry import telemetry_bp
from .i18n import current_language, select_language, translate
from .. import __version__

# Documento YAML vacio: se usa para inicializar APATE_RULES_PATH la
# primera vez que se levanta la app contra un directorio de datos
# nuevo, para que la vista de reglas siempre tenga un archivo valido
# que leer (en vez de tener que distinguir "no existe" de "esta vacio").
_EMPTY_RULES_DOCUMENT = "rules: []\n"
_STATUS_LABELS = {
    "planning": "Planificada",
    "active": "Activa",
    "compromised": "Comprometida",
    "closed": "Cerrada",
}


def create_app(config: Optional[dict[str, Any]] = None) -> Flask:
    """Construye la aplicación Flask de Apate Core. `config` permite
    sobreescribir APATE_DATA_DIR/APATE_RULES_PATH (usado por los
    tests, que apuntan a un directorio temporal en vez de
    `.apate_data`)."""

    app = Flask(__name__)
    app.config.from_mapping(
        # SECRET_KEY solo habilita los mensajes flash de la UI; no hay
        # autenticacion ni sesiones de usuario en este hito.
        SECRET_KEY=secrets.token_hex(32),
        APATE_DATA_DIR=Path(".apate_data"),
        APATE_RULES_PATH=Path(".apate_data/rules.yaml"),
    )
    if config:
        app.config.update(config)

    @app.before_request
    def guard_local_requests() -> None:
        """Restringe la interfaz local y valida formularios con cambios."""

        if not app.testing and request.host.split(":")[0] not in {"127.0.0.1", "localhost"}:
            abort(403)
        select_language()
        if request.method == "POST" and not app.testing:
            expected = session.get("_csrf_token", "")
            submitted = request.form.get("_csrf_token", "")
            if not expected or not hmac.compare_digest(expected, submitted):
                abort(400)

    @app.context_processor
    def inject_csrf_token():
        token = session.get("_csrf_token")
        if token is None:
            token = secrets.token_urlsafe(32)
            session["_csrf_token"] = token
        def language_url(language: str) -> str:
            values = dict(request.view_args or {})
            values.update(request.args.to_dict(flat=True))
            values["lang"] = language
            return url_for(request.endpoint or "operations.list_operations", **values)

        return {
            "csrf_token": lambda: token,
            "status_label": lambda status: translate(_STATUS_LABELS.get(status, status)),
            "tr": translate,
            "ui_language": current_language(),
            "language_url": language_url,
            "app_version": __version__,
        }

    data_dir = Path(app.config["APATE_DATA_DIR"])
    rules_path = Path(app.config["APATE_RULES_PATH"])
    app.config["APATE_DATA_DIR"] = data_dir
    app.config["APATE_RULES_PATH"] = rules_path

    rules_path.parent.mkdir(parents=True, exist_ok=True)
    if not rules_path.exists():
        rules_path.write_text(_EMPTY_RULES_DOCUMENT, encoding="utf-8")

    app.config["OPERATION_REPOSITORY"] = JSONFileOperationRepository(data_dir / "operations")
    app.config["TELEMETRY_COLLECTOR"] = TelemetryCollector(
        repository=JSONFileTelemetryRepository(data_dir / "telemetry")
    )

    app.register_blueprint(operations_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(telemetry_bp)

    @app.route("/")
    def index() -> Any:
        return redirect(url_for("operations.list_operations"))

    return app
