"""Vista de eventos, IoCs y TTPs observadas por operación."""

from __future__ import annotations

from flask import Blueprint, current_app, render_template, request

telemetry_bp = Blueprint("telemetry", __name__, url_prefix="/telemetry")


@telemetry_bp.route("/")
def index():
    repo = current_app.config["OPERATION_REPOSITORY"]
    operations = sorted(repo.list(), key=lambda op: op.created_at, reverse=True)
    return render_template("telemetry/index.html", operations=operations)


@telemetry_bp.route("/<operation_id>")
def detail(operation_id: str):
    collector = current_app.config["TELEMETRY_COLLECTOR"]
    all_events = collector.list_events(operation_id)

    plugin_id = request.args.get("plugin_id") or None
    surface = request.args.get("surface") or None
    events = all_events
    if plugin_id:
        events = [e for e in events if e.plugin_id == plugin_id]
    if surface:
        events = [e for e in events if e.surface == surface]

    return render_template(
        "telemetry/detail.html",
        operation_id=operation_id,
        events=events,
        iocs=collector.list_iocs(operation_id),
        ttps=collector.list_ttps(operation_id),
        plugin_ids=sorted({e.plugin_id for e in all_events}),
        surfaces=sorted({e.surface for e in all_events}),
        selected_plugin_id=plugin_id,
        selected_surface=surface,
    )
