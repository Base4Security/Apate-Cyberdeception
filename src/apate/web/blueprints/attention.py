"""Bandeja de atención por operación; ninguna ruta ejecuta despliegues."""

from __future__ import annotations

import json

from flask import Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request, session, url_for

from ...i18n import gettext as _
from ..access import visible_operations
from .operations import _get_operation_or_404, _log_operator_action

attention_bp = Blueprint("attention", __name__)

_SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_labels():
    return {"informational": _("Informativa"), "low": _("Baja"), "medium": _("Media"),
            "high": _("Alta"), "critical": _("Crítica")}


@attention_bp.get("/attention")
def inbox():
    """Bandeja SOC global limitada a las operaciones visibles del equipo."""
    operations = visible_operations(getattr(g, "current_identity", None),
                                    current_app.config["OPERATION_REPOSITORY"].list())
    repository = current_app.config["ATTENTION_REPOSITORY"]
    rows = []
    for operation in operations:
        signals_by_id = {signal.id: signal for signal in repository.list_signals(operation.id)}
        for case in repository.list_cases(operation.id):
            signals = [signals_by_id[signal_id] for signal_id in case.signal_ids if signal_id in signals_by_id]
            severity = max((signal.severity for signal in signals),
                           key=lambda value: _SEVERITY_ORDER[value], default="")
            rows.append({"operation": operation, "case": case, "signals": signals,
                         "severity": severity, "missing_signals": len(case.signal_ids) - len(signals)})

    selected_status = "all" if request.args.get("status") == "all" else "open"
    selected_operation = request.args.get("operation_id", "")
    selected_responsible = request.args.get("responsible", "")
    selected_severity = request.args.get("severity", "")
    selected_sort = "updated" if request.args.get("sort") == "updated" else "severity"
    responsible_options = sorted({row["case"].responsible for row in rows if row["case"].responsible}, key=str.casefold)
    rows = [row for row in rows
            if (selected_status == "all" or row["case"].status == "open")
            and (not selected_operation or row["operation"].id == selected_operation)
            and (not selected_responsible or row["case"].responsible == selected_responsible)
            and (not selected_severity or row["severity"] == selected_severity)]
    rows.sort(key=lambda row: row["case"].updated_at, reverse=True)
    if selected_sort == "severity":
        rows.sort(key=lambda row: _SEVERITY_ORDER.get(row["severity"], -1), reverse=True)
    total = len(rows)
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    page_size = 25
    page_count = max(1, (total + page_size - 1) // page_size)
    page = min(page, page_count)
    rows = rows[(page - 1) * page_size:page * page_size]
    filters = {"status": selected_status, "operation_id": selected_operation,
               "responsible": selected_responsible, "severity": selected_severity,
               "sort": selected_sort}
    return render_template("attention/inbox.html", rows=rows, total=total, page=page,
                           page_count=page_count, filters=filters, operations=operations,
                           responsible_options=responsible_options, severity_labels=_severity_labels())


def _back(operation_id: str):
    return redirect(url_for("attention.index", operation_id=operation_id))


def _audit(operation_id: str, action: str, target: str, detail: str) -> None:
    _log_operator_action(operation_id, action=action, outcome="success", detail=detail, target=target)


@attention_bp.get("/operations/<operation_id>/attention")
def index(operation_id: str):
    operation = _get_operation_or_404(operation_id)
    repo = current_app.config["ATTENTION_REPOSITORY"]
    events = current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
    events_by_id = {event.id: event for event in events}
    selected_ids = [event_id for event_id in request.args.getlist("event_ids") if event_id in events_by_id]
    severity_labels = _severity_labels()
    status_labels = {"open": _("Abierta"), "acknowledged": _("Reconocida"), "resolved": _("Resuelta")}
    origin_labels = {"rule": _("Regla"), "manual": _("Manual")}
    actions = [action for action in current_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation_id)
               if action.action.startswith(("signal_", "case_"))]
    return render_template("attention/index.html", operation=operation,
                           signals=repo.list_signals(operation_id), cases=repo.list_cases(operation_id),
                           events_by_id=events_by_id, selected_ids=selected_ids,
                           recent_events=list(reversed(events))[:30], attention_actions=list(reversed(actions)),
                           severity_labels=severity_labels, status_labels=status_labels, origin_labels=origin_labels)


@attention_bp.get("/operations/<operation_id>/attention/cases/<case_id>")
def case_detail(operation_id: str, case_id: str):
    """Concentra un caso y sus referencias sin atribuir causalidad."""
    operation = _get_operation_or_404(operation_id)
    repo = current_app.config["ATTENTION_REPOSITORY"]
    try:
        case = repo.get_case(operation_id, case_id)
    except KeyError:
        abort(404)
    signals = []
    for signal_id in case.signal_ids:
        try:
            signals.append(repo.get_signal(operation_id, signal_id))
        except KeyError:
            pass
    event_ids = {item.value for signal in signals for item in signal.evidence if item.kind == "telemetry_event"}
    events_by_id = {event.id: event for event in current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
                    if event.id in event_ids}
    actions = [action for action in current_app.config["OPERATOR_ACTION_REPOSITORY"].list_for_operation(operation_id)
               if action.action.startswith(("signal_", "case_")) and action.target in {case.id, *case.signal_ids}]
    available_signals = [signal for signal in repo.list_signals(operation_id) if signal.id not in case.signal_ids]
    return render_template("attention/case_detail.html", operation=operation, case=case,
                           signals=signals, missing_signals=len(case.signal_ids) - len(signals),
                           events_by_id=events_by_id, actions=list(reversed(actions)),
                           available_signals=available_signals, severity_labels=_severity_labels(),
                           status_labels={"open": _("Abierta"), "acknowledged": _("Reconocida"),
                                          "resolved": _("Resuelta")},
                           origin_labels={"rule": _("Regla"), "manual": _("Manual")})


@attention_bp.get("/operations/<operation_id>/attention/cases/<case_id>/handoff.json")
def case_handoff(operation_id: str, case_id: str):
    """Entrega al SOC un expediente con referencias de evidencia verificables."""
    operation = _get_operation_or_404(operation_id)
    repo = current_app.config["ATTENTION_REPOSITORY"]
    try:
        case = repo.get_case(operation_id, case_id)
    except KeyError:
        abort(404)
    signals = [repo.get_signal(operation_id, signal_id) for signal_id in case.signal_ids]
    event_ids = {item.value for signal in signals for item in signal.evidence if item.kind == "telemetry_event"}
    events = [event for event in current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
              if event.id in event_ids]
    package = {
        "schema": "apate.soc.handoff.v1",
        "operation": {"id": operation.id, "name": operation.name},
        "case": case.to_dict(),
        "signals": [signal.to_dict() for signal in signals],
        "event_summaries": [
            {"id": event.id, "source_event_id": event.source_event_id,
             "timestamp": event.timestamp.isoformat(), "plugin_id": event.plugin_id,
             "event_type": event.event_type.value, "ttp_id": event.ttp_id}
            for event in events
        ],
        "missing_event_ids": sorted(event_ids - {event.id for event in events}),
    }
    response = Response(json.dumps(package, ensure_ascii=False, indent=2), mimetype="application/json")
    response.headers["Content-Disposition"] = f'attachment; filename="case-{case.id}.json"'
    return response


@attention_bp.post("/operations/<operation_id>/attention/signals")
def create_signal(operation_id: str):
    _get_operation_or_404(operation_id)
    service = current_app.config["ATTENTION_SERVICE"]
    try:
        signal = service.create_manual(
            operation_id, title=request.form.get("title", ""), description=request.form.get("description", ""),
            severity=request.form.get("severity", "medium"), event_ids=request.form.getlist("event_ids"),
            note=request.form.get("note", ""), operator=session.get("operator", "sin especificar"),
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return _back(operation_id)
    _audit(operation_id, "signal_create", signal.id, _("Señal manual creada."))
    flash(_("Señal creada."), "success")
    return _back(operation_id)


@attention_bp.post("/operations/<operation_id>/attention/signals/<signal_id>/<action>")
def signal_action(operation_id: str, signal_id: str, action: str):
    _get_operation_or_404(operation_id)
    if action not in {"acknowledge", "resolve", "reopen", "assign"}:
        abort(404)
    try:
        service = current_app.config["ATTENTION_SERVICE"]
        if action == "assign":
            service.assign_signal(operation_id, signal_id, request.form.get("responsible", ""))
        else:
            service.transition_signal(operation_id, signal_id, action, note=request.form.get("note", ""))
    except KeyError:
        abort(404)
    except ValueError as exc:
        flash(str(exc), "error")
        return _back(operation_id)
    _audit(operation_id, f"signal_{action}", signal_id, _("Acción de atención registrada: %(action)s.", action=action))
    flash(_("Señal actualizada."), "success")
    return _back(operation_id)


@attention_bp.post("/operations/<operation_id>/attention/cases")
def create_case(operation_id: str):
    _get_operation_or_404(operation_id)
    try:
        case = current_app.config["ATTENTION_SERVICE"].create_case(
            operation_id, title=request.form.get("title", ""), description=request.form.get("description", ""),
            signal_ids=request.form.getlist("signal_ids"),
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return _back(operation_id)
    _audit(operation_id, "case_create", case.id, _("Caso creado por agrupación manual."))
    flash(_("Caso creado."), "success")
    return _back(operation_id)


@attention_bp.post("/operations/<operation_id>/attention/cases/<case_id>/<action>")
def case_action(operation_id: str, case_id: str, action: str):
    _get_operation_or_404(operation_id)
    if action not in {"resolve", "reopen", "add_signal", "remove_signal", "assign"}:
        abort(404)
    try:
        service = current_app.config["ATTENTION_SERVICE"]
        if action in {"add_signal", "remove_signal"}:
            selected = request.form.getlist("signal_ids")
            service.update_case_signals(operation_id, case_id,
                                        add=selected if action == "add_signal" else (),
                                        remove=selected if action == "remove_signal" else ())
        elif action == "assign":
            service.assign_case(operation_id, case_id, request.form.get("responsible", ""))
        else:
            service.transition_case(operation_id, case_id, action, note=request.form.get("note", ""))
    except KeyError:
        abort(404)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("attention.case_detail", operation_id=operation_id, case_id=case_id))
    _audit(operation_id, f"case_{action}", case_id, _("Caso actualizado por el operador."))
    flash(_("Caso actualizado."), "success")
    return redirect(url_for("attention.case_detail", operation_id=operation_id, case_id=case_id))
