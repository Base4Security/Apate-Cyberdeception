"""Vista de Telemetria (M4b): eventos, IoCs y TTPs observadas por
operacion, usando list_events/list_iocs/list_ttps del
TelemetryCollector (M4). Acepta filtros opcionales por plugin_id y
surface via query string (?plugin_id=...&surface=...), pensados para
que el modo Playground (M5) pueda reutilizar esta misma vista mas
adelante en vez de reconstruir el filtrado. No incluye las vistas
separadas de atacante/defensor de la seccion 6.4 del diseno: esas
dependen del entorno real del Playground, que todavia no existe.

Desde la primera tarea de la tanda de UI/UX con referencia CounterCraft
(ver docs/roadmap.md), suma tambien la vista "Incidentes": agrupacion
manual de eventos ya persistidos (`apate.telemetry.incidents.Incident`),
para correlacionarlos y estudiarlos en conjunto -- puramente de
analisis, el motor de reglas no los usa para nada.

Desde la segunda tarea de esa misma tanda, suma ademas clasificacion
TLP (Traffic Light Protocol, `apate.telemetry.classifications`) sobre
eventos e IoCs -- mismo criterio de "asiste, nunca decide": el motor
de reglas no la usa para nada, solo se refleja en el export STIX 2.1
del informe post-operacion (`apate.reporting.stix`)."""

from __future__ import annotations

import csv
import io
import json
import os
import requests
import zipfile
from pathlib import Path
from collections import Counter
from datetime import date, datetime, timedelta, timezone

from flask import Blueprint, Response, current_app, flash, g, jsonify, redirect, render_template, request, session, url_for

from ...i18n import gettext as _
from ...plugins import EventType
from ...telemetry import (
    Incident,
    PrivateIoCError,
    SUPPORTED_IOC_TYPES,
    TlpClassification,
    TlpLevel,
    ioc_subject_key,
    query_virustotal,
)
from .._enum_labels import event_type_label, provider_label
from ..access import visible_operations

telemetry_bp = Blueprint("telemetry", __name__, url_prefix="/telemetry")


@telemetry_bp.get("/<operation_id>/evidence.zip")
def download_evidence(operation_id: str):
    """Descarga evidencia y manifiesto verificable sin purgar telemetría."""
    from .operations import _get_operation_or_404
    from ...telemetry.archive import export_operation_evidence

    _get_operation_or_404(operation_id)
    repository = current_app.config["TELEMETRY_COLLECTOR"].repository
    archive_dir = Path(current_app.config["APATE_DATA_DIR"]) / "evidence_archives"
    manifest = export_operation_evidence(repository, operation_id, archive_dir)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as package:
        package.write(archive_dir / manifest["file"], arcname=manifest["file"])
        package.write(archive_dir / (manifest["file"] + ".manifest.json"),
                      arcname=manifest["file"] + ".manifest.json")
    response = Response(buffer.getvalue(), mimetype="application/zip")
    response.headers["Content-Disposition"] = f'attachment; filename="evidence-{operation_id}.zip"'
    return response


@telemetry_bp.post("/<operation_id>/export/<destination>")
def export_external(operation_id: str, destination: str):
    """El operador confirma el egreso de evidencia a un destino preconfigurado."""
    from .operations import _get_operation_or_404, _log_operator_action
    from ...telemetry.exporters import export_to_otlp_http, export_to_splunk_hec

    _get_operation_or_404(operation_id)
    if destination not in {"splunk", "otlp"}:
        return jsonify({"error": "Destino desconocido."}), 404
    records = current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
    try:
        if destination == "splunk":
            count = export_to_splunk_hec(
                records, os.getenv("APATE_SPLUNK_HEC_URL", ""), os.getenv("APATE_SPLUNK_HEC_TOKEN", ""),
            )
        else:
            count = export_to_otlp_http(
                records, os.getenv("APATE_OTLP_LOGS_URL", ""),
                bearer_token=os.getenv("APATE_OTLP_BEARER_TOKEN", ""),
            )
    except (ValueError, requests.RequestException) as exc:
        current_app.logger.warning("Falló exportación %s: %s", destination, type(exc).__name__)
        flash(_("No se pudo exportar la telemetría."), "error")
    else:
        _log_operator_action(operation_id, action="telemetry_export", outcome="success",
                             target=destination, detail=f"{count} eventos")
        flash(_("Se exportaron %(count)s eventos.", count=count), "success")
    return redirect(url_for("telemetry.detail", operation_id=operation_id))

_VIEWS = {"summary", "live", "events", "iocs", "ttps", "incidents"}
_PERIODS = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
_PROVIDER_LABELS = {"buda": "APATE", "dolost": "APATE", "honeytoken": "APATE", "mock": "APATE"}


@telemetry_bp.route("/")
def index():
    repo = current_app.config["OPERATION_REPOSITORY"]
    operations = sorted(visible_operations(getattr(g, "current_identity", None), repo.list()), key=lambda op: op.created_at, reverse=True)
    return render_template("telemetry/index.html", operations=operations, live_mode=False)


@telemetry_bp.get("/live")
def live_index():
    """Selector canónico para actividad en vivo, siempre por operación."""

    repo = current_app.config["OPERATION_REPOSITORY"]
    operations = sorted(visible_operations(getattr(g, "current_identity", None), repo.list()), key=lambda op: op.updated_at, reverse=True)
    return render_template("telemetry/index.html", operations=operations, live_mode=True)


@telemetry_bp.route("/<operation_id>")
def detail(operation_id: str):
    collector = current_app.config["TELEMETRY_COLLECTOR"]
    all_events = collector.list_events(operation_id)
    operation = next(
        (item for item in current_app.config["OPERATION_REPOSITORY"].list() if item.id == operation_id),
        None,
    )

    filters = _request_filters()
    events = _filter_events(all_events, operation, filters)
    selected_view = request.args.get("view", "summary")
    if selected_view not in _VIEWS:
        selected_view = "summary"

    export_format = request.args.get("format")
    if export_format == "json":
        return jsonify([event.to_dict() for event in events])
    if export_format == "csv":
        return _csv_response(operation_id, events)

    filtered_iocs = _deduplicate_iocs(events)
    filtered_ttps = sorted({event.ttp_id for event in events if event.ttp_id})
    event_context = {event.id: _event_context(operation, event) for event in events}
    event_inspector_payloads = {
        event.id: {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event_type_label(event.event_type.value),
            "kind": event.payload.get("kind", "-"),
            "detail": event.payload.get("detail", "-"),
            "provider": event_context[event.id]["provider"],
            "scenario": event_context[event.id]["scenario"],
            "scenario_id": event_context[event.id]["scenario_id"],
            "plugin_id": event.plugin_id,
            "resource_id": event.resource_id or _("No disponible"),
            "surface": event.surface,
            "ttp_id": event.ttp_id or "-",
            "payload": event.payload,
            "iocs": [ioc.to_dict() for ioc in getattr(event, "iocs", [])],
        }
        for event in events
    }
    all_event_context = {event.id: _event_context(operation, event) for event in all_events}
    service = current_app.config["ACTIVITY_INGESTION_SERVICE"]
    live_events = _filter_events(service.live_events(operation_id), operation, filters)
    persisted_source_ids = {event.source_event_id for event in all_events}
    live_rows = [
        _live_event_dict(event, persisted=event.id in persisted_source_ids, context=_event_context(operation, event))
        for event in reversed(live_events[-100:])
    ]
    scenario_options = [
        {"id": scenario.id, "name": scenario.description}
        for scenario in (operation.scenarios if operation else [])
    ]
    provider_values = sorted(
        {
            context["provider"]
            for context in all_event_context.values()
        }
        | {
            _provider_for_binding(binding)
            for binding in (operation.plugins if operation else [])
        }
    )
    dolost_decoys = _dolost_decoys(operation, filters)
    breakdowns = {
        "providers": Counter(context["provider"] for context in event_context.values()),
        "surfaces": Counter(event.surface for event in events),
        "kinds": Counter(str(event.payload.get("kind", _("sin tipo"))) for event in events),
    }
    incident_rows = _incident_rows(operation, operation_id, all_events)
    tlp_repo = current_app.config["TLP_CLASSIFICATION_REPOSITORY"]
    tlp_classifications = tlp_repo.list_for_operation(operation_id)
    event_tlp = {c.subject_key: c for c in tlp_classifications if c.subject_type == "event"}
    ioc_tlp = {c.subject_key: c for c in tlp_classifications if c.subject_type == "ioc"}
    vt_repo = current_app.config["VIRUSTOTAL_ENRICHMENT_REPOSITORY"]
    vt_enrichments = {
        item.subject_key: item for item in vt_repo.list_for_operation(operation_id)
    }
    vt_configured = bool(
        current_app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].load().get("api_key")
    )
    ioc_rows = [
        {
            "ioc": ioc,
            "subject_key": (key := ioc_subject_key(ioc.type, ioc.value)),
            "classification": ioc_tlp.get(key),
            "virustotal": vt_enrichments.get(key),
            "virustotal_supported": ioc.type in SUPPORTED_IOC_TYPES,
        }
        for ioc in filtered_iocs
    ]

    return render_template(
        "telemetry/detail.html",
        operation=operation,
        operation_id=operation_id,
        splunk_export_configured=bool(os.getenv("APATE_SPLUNK_HEC_URL") and os.getenv("APATE_SPLUNK_HEC_TOKEN")),
        otlp_export_configured=bool(os.getenv("APATE_OTLP_LOGS_URL")),
        selected_view=selected_view,
        events=events,
        iocs=filtered_iocs,
        ioc_rows=ioc_rows,
        ttps=filtered_ttps,
        incidents=incident_rows,
        tlp_levels=list(TlpLevel),
        virustotal_configured=vt_configured,
        event_tlp=event_tlp,
        event_context=event_context,
        live_rows=live_rows,
        ingestion_status=service.status(),
        dolost_decoys=dolost_decoys,
        dolost_live_enabled=bool(
            current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"]
            and dolost_decoys
            and filters["provider"] in (None, "APATE")
        ),
        breakdowns=breakdowns,
        plugin_ids=sorted({e.plugin_id for e in all_events}),
        surfaces=sorted({e.surface for e in all_events}),
        providers=provider_values,
        scenarios=scenario_options,
        event_kinds=sorted({str(e.payload.get("kind")) for e in all_events if e.payload.get("kind")}),
        selected_plugin_id=filters["plugin_id"],
        selected_surface=filters["surface"],
        selected_provider=filters["provider"],
        selected_scenario_id=filters["scenario_id"],
        selected_event_kind=filters["event_kind"],
        selected_event_id=filters["event_id"],
        selected_period=filters["period"],
        event_types=[item.value for item in EventType],
        selected_event_type=filters["event_type"],
        selected_ttp_id=filters["ttp_id"],
        event_inspector_payloads=event_inspector_payloads,
        search_query=request.args.get("q", "").strip(),
        selected_date_from=request.args.get("date_from", ""),
        selected_date_to=request.args.get("date_to", ""),
        filters_active=any(value for key, value in filters.items() if key != "query" or value),
        export_csv_args={**request.args.to_dict(), "format": "csv"},
        export_json_args={**request.args.to_dict(), "format": "json"},
        drilldown_url=lambda parameter, value: _filter_link(
            operation_id, parameter, value
        ),
        remove_filter_url=lambda parameter: _filter_link(operation_id, parameter),
    )


@telemetry_bp.post("/<operation_id>/iocs/virustotal")
def enrich_ioc_with_virustotal(operation_id: str):
    """Consulta bajo demanda un IoC real de la operacion y guarda el resumen."""

    ioc_type = request.form.get("ioc_type", "")
    ioc_value = request.form.get("ioc_value", "")
    known_iocs = {
        ioc_subject_key(ioc.type, ioc.value)
        for ioc in current_app.config["TELEMETRY_COLLECTOR"].list_iocs(operation_id)
    }
    subject_key = ioc_subject_key(ioc_type, ioc_value)
    destination = redirect(url_for("telemetry.detail", operation_id=operation_id, view="iocs"))
    if ioc_type not in SUPPORTED_IOC_TYPES or subject_key not in known_iocs:
        flash(_("El IoC no existe en la telemetría de esta operación o su tipo no es compatible."), "error")
        return destination

    api_key = current_app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].load().get("api_key", "")
    if not api_key:
        flash(_("Configurá la API key en Salud y configuración → Inteligencia de amenazas."), "error")
        return destination

    try:
        enrichment = query_virustotal(operation_id, ioc_type, ioc_value, api_key)
    except PrivateIoCError as exc:
        flash(str(exc), "error")
        return destination
    except Exception as exc:
        current_app.logger.warning("Falló la consulta a VirusTotal: %s", type(exc).__name__)
        flash(_("VirusTotal no pudo devolver un reporte para este IoC."), "error")
        return destination
    current_app.config["VIRUSTOTAL_ENRICHMENT_REPOSITORY"].save(enrichment)
    flash(_("Resultado de VirusTotal guardado como anotación del IoC."), "success")
    return destination


@telemetry_bp.get("/<operation_id>/live.json")
def live_feed(operation_id: str):
    """Buffer del proceso; ``persisted`` explicita su relación con SQLite."""

    operation = next(
        (item for item in current_app.config["OPERATION_REPOSITORY"].list() if item.id == operation_id),
        None,
    )
    service = current_app.config["ACTIVITY_INGESTION_SERVICE"]
    live_events = _filter_events(service.live_events(operation_id), operation, _request_filters())
    persisted = {
        event.source_event_id
        for event in current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
    }
    return jsonify(
        {
            "status": service.status(),
            "events": [
                _live_event_dict(
                    event,
                    persisted=event.id in persisted,
                    context=_event_context(operation, event),
                )
                for event in reversed(live_events[-100:])
            ],
        }
    )


@telemetry_bp.post("/<operation_id>/incidents")
def create_incident(operation_id: str):
    """Agrupa los eventos seleccionados en la pestana "Eventos" en un
    incidente nuevo o en uno ya existente. `event_ids` se filtra contra
    la telemetria real de la operacion -- un id que no corresponde a
    ningun evento persistido (formulario manipulado, evento borrado
    entre medio) se ignora en silencio en vez de crear una referencia
    rota."""

    repo = current_app.config["INCIDENT_REPOSITORY"]
    collector = current_app.config["TELEMETRY_COLLECTOR"]
    known_event_ids = {event.id for event in collector.list_events(operation_id)}
    event_ids = [eid for eid in request.form.getlist("event_ids") if eid in known_event_ids]
    if not event_ids:
        flash(_("Elegí al menos un evento observado para agrupar en un incidente."), "error")
        return redirect(url_for("telemetry.detail", operation_id=operation_id, view="events"))

    mode = request.form.get("mode", "new")
    if mode == "existing":
        incident_id = request.form.get("incident_id", "")
        existing = next(
            (item for item in repo.list_for_operation(operation_id) if item.id == incident_id), None
        )
        if existing is None:
            flash(_("El incidente elegido ya no existe."), "error")
            return redirect(url_for("telemetry.detail", operation_id=operation_id, view="events"))
        merged = list(existing.event_ids)
        added = 0
        for eid in event_ids:
            if eid not in merged:
                merged.append(eid)
                added += 1
        existing.event_ids = merged
        existing.updated_at = datetime.now(timezone.utc)
        repo.save(existing)
        flash(_("Se agregaron %(count)s evento(s) a '%(name)s'.", count=added, name=existing.name), "success")
    else:
        name = request.form.get("name", "").strip()
        if not name:
            flash(_("El incidente necesita un nombre."), "error")
            return redirect(url_for("telemetry.detail", operation_id=operation_id, view="events"))
        notes = request.form.get("notes", "").strip()
        incident = Incident(operation_id=operation_id, name=name, notes=notes, event_ids=event_ids)
        repo.save(incident)
        flash(_("Incidente '%(name)s' creado con %(count)s evento(s).", name=name, count=len(event_ids)), "success")

    return redirect(url_for("telemetry.detail", operation_id=operation_id, view="incidents"))


@telemetry_bp.post("/<operation_id>/incidents/<incident_id>/update")
def update_incident(operation_id: str, incident_id: str):
    """Edita nombre/notas de un incidente ya creado. No es una accion
    de sistema (nada de infraestructura real se toca), asi que no
    genera entrada en OPERATOR_ACTION_REPOSITORY -- mismo criterio que
    ya dejo afuera de ese log a la medicion de `success_metric` (Fase 2
    post-BlackHat) y la incorporacion de TTPs al perfil de adversario
    (Fase 3)."""

    repo = current_app.config["INCIDENT_REPOSITORY"]
    incident = next(
        (item for item in repo.list_for_operation(operation_id) if item.id == incident_id), None
    )
    if incident is None:
        flash(_("El incidente ya no existe."), "error")
        return redirect(url_for("telemetry.detail", operation_id=operation_id, view="incidents"))
    name = request.form.get("name", "").strip()
    if not name:
        flash(_("El incidente necesita un nombre."), "error")
        return redirect(url_for("telemetry.detail", operation_id=operation_id, view="incidents"))
    incident.name = name
    incident.notes = request.form.get("notes", "").strip()
    incident.updated_at = datetime.now(timezone.utc)
    repo.save(incident)
    flash(_("Incidente '%(name)s' actualizado.", name=name), "success")
    return redirect(url_for("telemetry.detail", operation_id=operation_id, view="incidents"))


@telemetry_bp.post("/<operation_id>/incidents/<incident_id>/remove-event")
def remove_incident_event(operation_id: str, incident_id: str):
    """Saca un evento puntual de un incidente, sin borrar el incidente
    ni el evento en si (que sigue viviendo en la telemetria real)."""

    repo = current_app.config["INCIDENT_REPOSITORY"]
    incident = next(
        (item for item in repo.list_for_operation(operation_id) if item.id == incident_id), None
    )
    if incident is None:
        flash(_("El incidente ya no existe."), "error")
        return redirect(url_for("telemetry.detail", operation_id=operation_id, view="incidents"))
    event_id = request.form.get("event_id", "")
    incident.event_ids = [eid for eid in incident.event_ids if eid != event_id]
    incident.updated_at = datetime.now(timezone.utc)
    repo.save(incident)
    return redirect(url_for("telemetry.detail", operation_id=operation_id, view="incidents"))


@telemetry_bp.post("/<operation_id>/incidents/<incident_id>/delete")
def delete_incident(operation_id: str, incident_id: str):
    """Borra la agrupacion entera. Los eventos agrupados no se tocan
    -- solo desaparece el incidente como tal, idempotente si ya no
    existia (mismo criterio que el resto de las rutas de borrado del
    proyecto)."""

    current_app.config["INCIDENT_REPOSITORY"].delete(operation_id, incident_id)
    flash(_("Incidente eliminado."), "success")
    return redirect(url_for("telemetry.detail", operation_id=operation_id, view="incidents"))


@telemetry_bp.post("/<operation_id>/tlp")
def set_tlp_classification(operation_id: str):
    """Setea, cambia o quita (`level` vacio) la clasificacion TLP de un
    evento o un IoC. Mismo criterio de "asiste, nunca decide" que
    Incidentes: no genera entrada en OPERATOR_ACTION_REPOSITORY -- es
    edicion de un dato de analisis, no una accion de sistema sobre
    infraestructura real. Sin clasificacion explicita no hay ningun
    default (ni siquiera TLP:WHITE): "sin clasificar" es un estado
    real, `clear()` lo vuelve a ese estado en vez de guardar un valor
    inventado."""

    repo = current_app.config["TLP_CLASSIFICATION_REPOSITORY"]
    subject_type = request.form.get("subject_type", "")
    subject_key = request.form.get("subject_key", "")
    view = request.form.get("view", "summary")
    destination = redirect(url_for("telemetry.detail", operation_id=operation_id, view=view))

    if subject_type not in ("event", "ioc") or not subject_key:
        flash(_("Clasificación TLP inválida."), "error")
        return destination

    level_raw = request.form.get("level", "")
    if not level_raw:
        repo.clear(operation_id, subject_type, subject_key)
        flash(_("Clasificación TLP quitada — vuelve a \"sin clasificar\"."), "success")
        return destination

    try:
        level = TlpLevel(level_raw)
    except ValueError:
        flash(_("Nivel TLP inválido."), "error")
        return destination

    repo.save(
        TlpClassification(
            operation_id=operation_id,
            subject_type=subject_type,
            subject_key=subject_key,
            level=level,
            set_by=session.get("operator", ""),
        )
    )
    flash(_("Clasificación TLP:%(level)s guardada.", level=level.value.upper()), "success")
    return destination


def _incident_rows(operation, operation_id: str, all_events: list) -> list[dict]:
    """Resuelve cada Incident guardado a sus TelemetryRecord reales
    (mas contexto de proveedor/escenario), para que la plantilla no
    tenga que conocer el repositorio. `missing_count` cuenta ids
    guardados que ya no resuelven a ningun evento persistido (no
    debería pasar en uso normal, pero un id suelto no debe romper la
    vista ni desaparecer en silencio del todo)."""

    repo = current_app.config["INCIDENT_REPOSITORY"]
    events_by_id = {event.id: event for event in all_events}
    incidents = sorted(
        repo.list_for_operation(operation_id), key=lambda item: item.created_at, reverse=True
    )
    rows = []
    for incident in incidents:
        resolved = [events_by_id[eid] for eid in incident.event_ids if eid in events_by_id]
        rows.append(
            {
                "incident": incident,
                "events": [
                    {"event": event, "context": _event_context(operation, event)} for event in resolved
                ],
                "missing_count": len(incident.event_ids) - len(resolved),
            }
        )
    return rows


def _request_filters() -> dict[str, object]:
    event_type_value = request.args.get("event_type") or None
    return {
        "plugin_id": request.args.get("plugin_id") or None,
        "surface": request.args.get("surface") or None,
        "provider": request.args.get("provider") or None,
        "scenario_id": request.args.get("scenario_id") or None,
        "event_type": event_type_value.replace("-", "_") if event_type_value else None,
        "event_kind": request.args.get("event_kind") or None,
        "event_id": request.args.get("event_id") or None,
        "ttp_id": request.args.get("ttp_id", "").strip() or None,
        "query": request.args.get("q", "").strip().casefold() or None,
        "date_from": _parse_date(request.args.get("date_from")),
        "date_to": _parse_date(request.args.get("date_to")),
        "period": request.args.get("period") if request.args.get("period") in _PERIODS else None,
    }


def _filter_link(operation_id: str, parameter: str, value: str | None = None) -> str:
    """Arma un enlace compartible preservando el resto de los filtros.

    ``value`` agrega o reemplaza un filtro puntual; ``None`` lo quita. Los
    filtros de Telemetria son singulares, por lo que ``to_dict()`` conserva
    exactamente su contrato actual sin perder valores multiples relevantes.
    """

    arguments = request.args.to_dict()
    arguments.pop("format", None)
    if value is None:
        arguments.pop(parameter, None)
    else:
        arguments[parameter] = value
    return url_for("telemetry.detail", operation_id=operation_id, **arguments)


def _filter_events(events: list, operation, filters: dict[str, object]) -> list:
    threshold = None
    if filters["period"]:
        threshold = datetime.now(timezone.utc) - _PERIODS[str(filters["period"])]
    result = []
    for event in events:
        context = _event_context(operation, event)
        timestamp = event.timestamp
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if filters["plugin_id"] and event.plugin_id != filters["plugin_id"]:
            continue
        if filters["surface"] and event.surface != filters["surface"]:
            continue
        if filters["provider"] and context["provider"] != filters["provider"]:
            continue
        if filters["scenario_id"] and context["scenario_id"] != filters["scenario_id"]:
            continue
        if filters["event_type"] and event.event_type.value != filters["event_type"]:
            continue
        if filters["event_kind"] and event.payload.get("kind") != filters["event_kind"]:
            continue
        if filters["event_id"] and event.id != filters["event_id"]:
            continue
        if filters["ttp_id"] and (event.ttp_id or "").casefold() != str(filters["ttp_id"]).casefold():
            continue
        if filters["date_from"] and timestamp.date() < filters["date_from"]:
            continue
        if filters["date_to"] and timestamp.date() > filters["date_to"]:
            continue
        if threshold and timestamp < threshold:
            continue
        if filters["query"] and str(filters["query"]) not in _event_search_text(event):
            continue
        result.append(event)
    return result


def _binding_kind(binding) -> str:
    if binding.plugin_kind:
        return binding.plugin_kind
    return binding.plugin_id.casefold().split("-", 1)[0]


def _provider_for_binding(binding) -> str:
    return _PROVIDER_LABELS.get(_binding_kind(binding), "APATE")


def _event_context(operation, event) -> dict[str, str]:
    binding = next(
        (item for item in operation.plugins if item.plugin_id == event.plugin_id),
        None,
    ) if operation else None
    if binding is None:
        prefix = event.plugin_id.casefold().split("-", 1)[0]
        return {"provider": _PROVIDER_LABELS.get(prefix, "APATE"), "scenario_id": "", "scenario": _("Sin escenario")}
    scenario = operation.find_scenario(binding.scenario_id)
    return {
        "provider": _provider_for_binding(binding),
        "scenario_id": binding.scenario_id or "",
        "scenario": scenario.description if scenario else _("Sin escenario"),
    }


def _dolost_decoys(operation, filters: dict[str, object]) -> list[str]:
    if operation is None:
        return []
    names = []
    for binding in operation.plugins:
        if _binding_kind(binding) != "dolost":
            continue
        if filters["scenario_id"] and binding.scenario_id != filters["scenario_id"]:
            continue
        if filters["surface"] and binding.surface != filters["surface"]:
            continue
        names.extend(
            str(decoy["Hostname"])
            for decoy in binding.config.get("decoys", [])
            if decoy.get("Hostname")
        )
    return sorted(set(names))


def _deduplicate_iocs(events: list) -> list:
    seen = set()
    result = []
    for event in events:
        for ioc in getattr(event, "iocs", []):
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                result.append(ioc)
    return result


def _live_event_dict(event, *, persisted: bool, context: dict[str, str]) -> dict[str, object]:
    return {
        "id": event.id,
        "timestamp": event.timestamp.isoformat(),
        "event_type": event.event_type.value,
        "plugin_id": event.plugin_id,
        "resource_id": event.resource_id,
        "surface": event.surface,
        "provider": context["provider"],
        # Etiqueta aparte del valor: las filas que agrega el JS en vivo
        # tienen que decir lo mismo que las que renderiza Jinja, y el
        # valor crudo sigue siendo el que viaja en los filtros.
        "provider_label": provider_label(context["provider"]),
        "scenario": context["scenario"],
        "ttp_id": event.payload.get("ttp_id"),
        "kind": event.payload.get("kind", ""),
        "detail": event.payload.get("detail", ""),
        "persisted": persisted,
    }


def _parse_date(raw: str | None) -> date | None:
    try:
        return date.fromisoformat(raw) if raw else None
    except ValueError:
        return None


def _event_search_text(event) -> str:
    """Texto determinista usado por el buscador de telemetria."""

    values = [
        event.plugin_id,
        event.resource_id or "",
        event.surface,
        event.ttp_id or "",
        event.event_type.value,
        json.dumps(event.payload),
    ]
    values.extend(ioc.value for ioc in getattr(event, "iocs", []))
    return " ".join(values).casefold()


def _csv_response(operation_id: str, events: list) -> Response:
    """Exporta exactamente los eventos ya filtrados por la vista."""

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(("timestamp", "event_type", "plugin_id", "resource_id", "surface", "ttp_id", "iocs", "payload"))
    for event in events:
        writer.writerow(
            (
                event.timestamp.isoformat(),
                event.event_type.value,
                event.plugin_id,
                event.resource_id or "",
                event.surface,
                event.ttp_id or "",
                json.dumps([ioc.to_dict() for ioc in event.iocs], ensure_ascii=False),
                json.dumps(event.payload, ensure_ascii=False),
            )
        )
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="telemetry-{operation_id}.csv"'},
    )
