"""Centro de impacto real, con vista previa explícita como respaldo."""

from __future__ import annotations

from flask import Blueprint, current_app, g, render_template, request

from .._dashboard_mock import impact_dashboard_mock
from .._impact_dashboard import impact_dashboard_data
from ..access import visible_operations
from .operations import _bulk_deployment_status


impact_bp = Blueprint("impact", __name__, url_prefix="/impact")


@impact_bp.get("/")
def dashboard():
    """Renderiza datos reales; ``?preview=1`` conserva el fixture portátil."""

    if request.args.get("preview") == "1":
        return render_template("impact.html", dashboard=impact_dashboard_mock())

    identity = getattr(g, "current_identity", None)
    operations = visible_operations(identity, current_app.config["OPERATION_REPOSITORY"].list())
    deployment_status = _bulk_deployment_status(
        operations,
        external_tools_mounted=current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"],
    ) if operations else {}
    dashboard_data = impact_dashboard_data(
        operations,
        current_app.config["TELEMETRY_COLLECTOR"],
        current_app.config["RULE_DECISION_REPOSITORY"],
        deployment_status,
    )

    return render_template("impact.html", dashboard=dashboard_data)
