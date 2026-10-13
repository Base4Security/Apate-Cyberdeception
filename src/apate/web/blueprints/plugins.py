"""Catálogo unificado de capacidades reutilizables.

Los motores registrados, perfiles de identidad y tipos de actividad se
presentan por función, superficie, proveedor y disponibilidad. Todas las rutas
canónicas viven bajo ``/capabilities``; ``/plugins/`` solo conserva una
redirección de entrada al catálogo. Elegir "Usar en una operación"
solo abre el contexto correspondiente: nunca vincula ni despliega por sí solo.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlencode

from flask import Blueprint, Response, abort, current_app, flash, g, jsonify, redirect, render_template, request, stream_with_context, url_for

from BUDA.app import db as _buda_db
from BUDA.models import Activity as BudaActivity
from BUDA.models import UserProfile as BudaUserProfile
from BUDA.routes.ai_integration import generate_activity as _buda_generate_activity
from BUDA.routes.ai_integration import generate_activity_commands as _buda_generate_commands

from ...plugins import PluginRegistry
from ...core import BehaviorContextStatus
from ...i18n import gettext, gettext_noop
from .._behavior_context import count_evtx_records, extract_candidate, save_evtx_upload
from .._enum_labels import provider_label as _provider_label
from ..access import visible_operations

plugins_bp = Blueprint("plugins", __name__, url_prefix="/plugins")
capabilities_bp = Blueprint("capabilities", __name__, url_prefix="/capabilities")

_EXTERNAL_KINDS = {"buda", "dolost"}
_PROVIDERS = {"buda": "APATE", "dolost": "APATE", "honeytoken": "APATE", "mock": "APATE"}
_RESOURCE_TYPE_LABELS = {
    "motor": "Motor",
    "perfil": "Perfil",
    "actividad": "Actividad",
    "contexto": "Contexto",
}
_SURFACE_LABELS = {
    "Identidad / comportamiento": gettext_noop("Identidad / comportamiento"),
    "Multi-superficie (cloud/documentos/DNS/identidad)": gettext_noop(
        "Multi-superficie (cloud/documentos/DNS/identidad)"
    ),
    "Red / host": gettext_noop("Red / host"),
    "Archivos / credenciales": gettext_noop("Archivos / credenciales"),
    "Red (simulada)": gettext_noop("Red (simulada)"),
    "Red / host (multi-servicio)": gettext_noop("Red / host (multi-servicio)"),
}
_CATALOG_PROVIDER_LABELS = {"Tercero": gettext_noop("Tercero")}


def _tools_mounted() -> bool:
    return bool(current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"])


def _unavailable():
    return render_template("plugins/unavailable.html")


def _operations():
    return sorted(
        visible_operations(getattr(g, "current_identity", None), current_app.config["OPERATION_REPOSITORY"].list()),
        key=lambda item: item.name.lower(),
    )


def _resource_type_label(value: object) -> str:
    """Etiqueta localizada; el valor interno sigue siendo el filtro técnico."""

    return gettext(_RESOURCE_TYPE_LABELS.get(str(value), str(value)))


def _surface_label(value: object) -> str:
    """Traduce solo etiquetas propias, nunca contenido aportado por operadores."""

    text = str(value)
    return gettext(_SURFACE_LABELS.get(text, text))


def _catalog_provider_label(value: object) -> str:
    """Muestra el proveedor localizado sin alterar el valor que viaja en filtros."""

    text = _provider_label(str(value))
    return gettext(_CATALOG_PROVIDER_LABELS.get(text, text))


def _capability_rows() -> list[dict[str, object]]:
    """Normaliza las fuentes del catálogo sin leer credenciales."""

    mounted = _tools_mounted()
    rows: list[dict[str, object]] = []
    for item in PluginRegistry.list_descriptions():
        rows.append(
            {
                "resource_type": "motor",
                "resource_id": item.kind,
                "name": item.display_name,
                "description": item.description,
                "surface": item.surface,
                "provider": _PROVIDERS.get(item.kind, "Tercero"),
                "available": mounted or item.kind not in _EXTERNAL_KINDS,
                "edit_endpoint": None,
                "edit_label": "",
            }
        )

    if mounted:
        for profile in BudaUserProfile.query.order_by(BudaUserProfile.name).all():
            rows.append(
                {
                    "resource_type": "perfil",
                    "resource_id": profile.id,
                    "name": profile.name,
                    "description": profile.role,
                    "surface": "Identidad / comportamiento",
                    "provider": "APATE",
                    "available": True,
                    "edit_endpoint": url_for(
                        "capabilities.identity_profile_edit", user_profile_id=profile.id
                    ),
                    "edit_label": gettext("Editar"),
                }
            )
        for activity in BudaActivity.query.order_by(BudaActivity.activity_type).all():
            rows.append(
                {
                    "resource_type": "actividad",
                    "resource_id": activity.id,
                    "name": activity.activity_type,
                    "description": activity.details or gettext("Sin detalle"),
                    "surface": "Identidad / comportamiento",
                    "provider": "APATE",
                    "available": True,
                    "edit_endpoint": url_for(
                        "capabilities.behavior_activity_edit", activity_id=activity.id
                    ),
                    "edit_label": gettext("Editar"),
                }
            )
    for source in current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"].list():
        rows.append(
            {
                "resource_type": "contexto",
                "resource_id": source.id,
                "name": source.name,
                "description": source.provenance,
                "surface": "Identidad / comportamiento",
                "provider": "APATE",
                "available": source.status == BehaviorContextStatus.ACTIVE and source.integrity_ok,
                "edit_endpoint": url_for("capabilities.behavior_context"),
                "edit_label": gettext("Administrar"),
            }
        )
    return rows


@capabilities_bp.route("/")
def catalog():
    rows = _capability_rows()
    filters = {
        "type": request.args.get("type", ""),
        "surface": request.args.get("surface", ""),
        "provider": request.args.get("provider", ""),
        "availability": request.args.get("availability", ""),
    }

    def matches(row: dict[str, object]) -> bool:
        if filters["type"] and row["resource_type"] != filters["type"]:
            return False
        if filters["surface"] and row["surface"] != filters["surface"]:
            return False
        if filters["provider"] and row["provider"] != filters["provider"]:
            return False
        if filters["availability"]:
            expected = filters["availability"] == "available"
            if bool(row["available"]) is not expected:
                return False
        return True

    return render_template(
        "plugins/catalog.html",
        capabilities=[row for row in rows if matches(row)],
        descriptions=PluginRegistry.list_descriptions(),
        filters=filters,
        surfaces=sorted({str(row["surface"]) for row in rows}),
        providers=sorted({str(row["provider"]) for row in rows}),
        provider_label=_catalog_provider_label,
        resource_type_label=_resource_type_label,
        surface_label=_surface_label,
        operations=_operations(),
        tools_mounted=_tools_mounted(),
    )


@plugins_bp.route("/")
def legacy_catalog():
    """Entrada histórica del catálogo; el destino canónico es /capabilities/."""

    target = url_for("capabilities.catalog")
    if request.query_string:
        target = f"{target}?{request.query_string.decode('latin-1')}"
    return redirect(target)


def _behavior_context_reference_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for operation in current_app.config["OPERATION_REPOSITORY"].list():
        for source_id in operation.behavior_context_source_ids:
            counts[source_id] = counts.get(source_id, 0) + 1
    return counts


def _behavior_context_upload_response(*, pending_operation_id: str | None = None):
    """Extrae por SSE y guarda un candidato pendiente, nunca activo."""

    if "file" not in request.files or not request.files["file"].filename:
        flash(gettext("Seleccioná un archivo EVTX."), "error")
        endpoint = "operations.detail" if pending_operation_id else "capabilities.behavior_context"
        values = (
            {"operation_id": pending_operation_id, "_anchor": "tab-preparation"}
            if pending_operation_id
            else {}
        )
        return redirect(url_for(endpoint, **values))
    try:
        path, original_name = save_evtx_upload(
            request.files["file"], Path(current_app.config["BEHAVIOR_CONTEXT_UPLOAD_DIR"])
        )
    except ValueError as exc:
        flash(str(exc), "error")
        endpoint = "operations.detail" if pending_operation_id else "capabilities.behavior_context"
        values = (
            {"operation_id": pending_operation_id, "_anchor": "tab-preparation"}
            if pending_operation_id
            else {}
        )
        return redirect(url_for(endpoint, **values))

    repository = current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"]
    name = request.form.get("name", "").strip()

    def process():
        try:
            total = count_evtx_records(path)
            yield f"data: records:{total}\n\n"
            source = extract_candidate(
                path,
                original_name=original_name,
                name=name,
                repository=repository,
                pending_operation_id=pending_operation_id,
            )
            yield f"data: candidate:{source.id}\n\n"
        except Exception:
            current_app.logger.exception("No se pudo extraer el contexto EVTX")
            # La llamada sale de la f-string a proposito: `pybabel extract` solo
            # ve dentro de una f-string desde Python 3.12 (PEP 701). Anidada ahi,
            # en 3.11 el mensaje no se extrae y
            # `test_el_catalogo_ingles_cubre_todo_el_texto_marcado_en_el_codigo`
            # lo reporta como huerfano segun con que interprete se corra la suite.
            error = gettext("No se pudo procesar el archivo EVTX.")
            yield f"data: error:{error}\n\n"
        finally:
            path.unlink(missing_ok=True)

    return Response(stream_with_context(process()), mimetype="text/event-stream")


@capabilities_bp.get("/behavior-context")
def behavior_context():
    sources = sorted(
        current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"].list(),
        key=lambda item: item.created_at,
        reverse=True,
    )
    return render_template(
        "plugins/behavior_context.html",
        sources=sources,
        reference_counts=_behavior_context_reference_counts(),
        context_status=BehaviorContextStatus,
    )


@capabilities_bp.post("/behavior-context/upload")
def behavior_context_upload():
    return _behavior_context_upload_response()


@capabilities_bp.post("/behavior-context/<source_id>/confirm")
def behavior_context_confirm(source_id: str):
    repository = current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"]
    try:
        source = repository.get(source_id)
    except KeyError:
        abort(404)
    if source.pending_operation_id is not None:
        flash(gettext("Confirmá este candidato desde la operación que inició la extracción."), "error")
        return redirect(url_for("capabilities.behavior_context"))
    if request.form.get("confirm") != "CONFIRMAR":
        flash(gettext("Marcá la revisión explícita antes de activar la fuente."), "error")
        return redirect(url_for("capabilities.behavior_context"))
    try:
        source.confirm()
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        repository.save(source)
        flash(gettext("Fuente '%(name)s' confirmada y disponible.", name=source.name), "success")
    return redirect(url_for("capabilities.behavior_context"))


@capabilities_bp.post("/behavior-context/<source_id>/archive")
def behavior_context_archive(source_id: str):
    repository = current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"]
    try:
        source = repository.get(source_id)
        source.archive()
    except KeyError:
        abort(404)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        repository.save(source)
        references = _behavior_context_reference_counts().get(source.id, 0)
        detail = gettext("Fuente '%(name)s' archivada.", name=source.name)
        if references:
            detail += gettext(" Se conservan %(count)s referencia(s) operativas.", count=references)
        flash(detail, "success")
    return redirect(url_for("capabilities.behavior_context"))


@capabilities_bp.post("/behavior-context/<source_id>/discard")
def behavior_context_discard(source_id: str):
    try:
        current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"].delete_pending(source_id)
    except KeyError:
        abort(404)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        flash(gettext("Candidato pendiente descartado."), "success")
    return redirect(url_for("capabilities.behavior_context"))


@capabilities_bp.route("/behavior-activities", methods=["GET", "POST"])
def behavior_activities():
    if not _tools_mounted():
        return _unavailable()
    if request.method == "POST":
        activity_type = request.form.get("activity_type", "").strip()
        details = request.form.get("details", "").strip()
        profile_ids = request.form.getlist("user_profiles")
        activity = BudaActivity(activity_type=activity_type, details=details)
        activity.set_approved_commands(_comandos_del_formulario())
        activity.user_profiles = BudaUserProfile.query.filter(BudaUserProfile.id.in_(profile_ids)).all()
        _buda_db.session.add(activity)
        _buda_db.session.commit()
        flash(gettext("Tipo de actividad '%(name)s' creado.", name=activity_type), "success")
        return redirect(url_for("capabilities.behavior_activities"))
    return render_template(
        "plugins/activities.html",
        activities=BudaActivity.query.all(),
        user_profiles=BudaUserProfile.query.all(),
        operations=_operations(),
    )


def _comandos_del_formulario() -> list[str]:
    """El repertorio que escribio el operador: un comando por linea."""

    crudo = request.form.get("commands", "")
    return [linea.strip() for linea in crudo.splitlines() if linea.strip()]


def _prompt_context() -> str:
    """El contexto que se le manda al modelo: curado, activo y sin identificadores.

    Dos filtros, y cada uno cierra un agujero distinto:

    * **Solo fuentes ACTIVAS.** Es el repositorio que el operador revisa y
      confirma. Antes el prompt leia `context.json` del directorio de trabajo,
      asi que un candidato descartado en la interfaz seguia viajando igual.
    * **Solo la proyeccion sin identificadores** (`prompt_summary()`): el
      modelo necesita la forma del comportamiento normal, no los nombres de
      usuario, las IPs internas ni los nombres de equipos del cliente.

    Sin fuentes activas se genera sin contexto y se lo dice. Inventar uno, o
    caer al archivo crudo, seria justamente lo que esto viene a evitar.
    """

    repositorio = current_app.config.get("BEHAVIOR_CONTEXT_REPOSITORY")
    if repositorio is None:
        return ""
    resumenes = [
        {"fuente": fuente.name, "resumen": fuente.prompt_summary()}
        for fuente in repositorio.list()
        if fuente.status == BehaviorContextStatus.ACTIVE
    ]
    if not resumenes:
        return ""
    return json.dumps(resumenes, ensure_ascii=False, sort_keys=True)


@capabilities_bp.route("/behavior-activities/generate", methods=["POST"])
def behavior_activity_generate():
    """Genera una sugerencia; no modifica el formulario ni persiste datos."""

    if not _tools_mounted():
        return jsonify({"error": gettext("Herramientas externas no montadas.")}), 503
    data = request.get_json(silent=True) or {}
    try:
        result = _buda_generate_activity(
            data.get("user_profile_id"),
            activity_type=data.get("activity_type"),
            details=data.get("details"),
            context=_prompt_context() or None,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except LookupError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify({"message": result}), 200


@capabilities_bp.route("/behavior-activities/<int:activity_id>/generate-commands", methods=["POST"])
def behavior_activity_generate_commands(activity_id: int):
    """Propone un repertorio. **No lo guarda ni lo ejecuta.**

    Es la mitad "generacion" del principio que la aplicacion declara: el
    modelo propone, la pantalla lo muestra, el operador corrige y recien al
    guardar el formulario ese repertorio pasa a ser lo unico que el worker de
    narrativas ejecuta. Deliberadamente no persiste: si esta ruta escribiera,
    seria otra vez el modelo decidiendo que corre en la red del cliente.
    """

    if not _tools_mounted():
        return jsonify({"error": gettext("Herramientas externas no montadas.")}), 503
    activity = _buda_db.get_or_404(BudaActivity, activity_id)
    rol = next((perfil.role for perfil in activity.user_profiles), None)
    try:
        comandos = _buda_generate_commands(
            activity.activity_type,
            details=activity.details,
            profile_role=rol,
            context=_prompt_context() or None,
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not comandos:
        return jsonify({"error": gettext("El modelo no devolvió comandos utilizables.")}), 502
    return jsonify({"commands": comandos}), 200


@capabilities_bp.route("/behavior-activities/<int:activity_id>/edit", methods=["GET", "POST"])
def behavior_activity_edit(activity_id: int):
    if not _tools_mounted():
        return _unavailable()
    activity = _buda_db.get_or_404(BudaActivity, activity_id)
    if request.method == "POST":
        activity.activity_type = request.form.get("activity_type", "").strip()
        activity.details = request.form.get("details", "").strip()
        activity.set_approved_commands(_comandos_del_formulario())
        profile_ids = request.form.getlist("user_profiles")
        activity.user_profiles = BudaUserProfile.query.filter(BudaUserProfile.id.in_(profile_ids)).all()
        _buda_db.session.commit()
        flash(gettext("Tipo de actividad actualizado."), "success")
        return redirect(url_for("capabilities.behavior_activities"))
    return render_template(
        "plugins/activity_edit.html",
        activity=activity,
        user_profiles=BudaUserProfile.query.all(),
    )


@capabilities_bp.route("/behavior-activities/<int:activity_id>/delete", methods=["POST"])
def behavior_activity_delete(activity_id: int):
    if not _tools_mounted():
        return _unavailable()
    activity = _buda_db.get_or_404(BudaActivity, activity_id)
    _buda_db.session.delete(activity)
    _buda_db.session.commit()
    flash(gettext("Tipo de actividad eliminado."), "success")
    return redirect(url_for("capabilities.behavior_activities"))


@capabilities_bp.route("/identity-profiles", methods=["GET", "POST"])
def identity_profiles():
    if not _tools_mounted():
        return _unavailable()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        role = request.form.get("role", "").strip()
        server = request.form.get("winrm_server", "").strip()
        username = request.form.get("winrm_username", "").strip()
        password = request.form.get("winrm_password", "")
        if not (name and role and server and username and password):
            flash(gettext("Nombre, rol, servidor, usuario y contraseña WinRM son obligatorios."), "error")
            return redirect(url_for("capabilities.identity_profiles"))
        profile = BudaUserProfile(
            name=name,
            role=role,
            behavior_pattern=request.form.get("behavior_pattern", "").strip(),
            winrm_server=server,
            winrm_username=username,
            winrm_password=password,
        )
        _buda_db.session.add(profile)
        _buda_db.session.commit()
        flash(gettext("Perfil de usuario '%(name)s' creado.", name=name), "success")
        return redirect(url_for("capabilities.identity_profiles"))
    return render_template(
        "plugins/profiles.html",
        user_profiles=BudaUserProfile.query.all(),
        operations=_operations(),
    )


@capabilities_bp.route("/identity-profiles/<int:user_profile_id>/edit", methods=["GET", "POST"])
def identity_profile_edit(user_profile_id: int):
    if not _tools_mounted():
        return _unavailable()
    profile = _buda_db.get_or_404(BudaUserProfile, user_profile_id)
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        role = request.form.get("role", "").strip()
        server = request.form.get("winrm_server", "").strip()
        if not (name and role and server):
            flash(gettext("Nombre, rol y servidor WinRM son obligatorios."), "error")
            return redirect(
                url_for("capabilities.identity_profile_edit", user_profile_id=user_profile_id)
            )
        profile.name = name
        profile.role = role
        profile.behavior_pattern = request.form.get("behavior_pattern", "").strip()
        profile.winrm_server = server
        # Ambos secretos son write-only: vacío conserva el valor cifrado existente.
        username = request.form.get("winrm_username", "").strip()
        password = request.form.get("winrm_password", "")
        if username:
            profile.winrm_username = username
        if password:
            profile.winrm_password = password
        _buda_db.session.commit()
        flash(gettext("Perfil de usuario '%(name)s' actualizado.", name=name), "success")
        return redirect(url_for("capabilities.identity_profiles"))
    return render_template("plugins/profile_edit.html", profile=profile)


@capabilities_bp.route("/identity-profiles/<int:user_profile_id>/delete", methods=["POST"])
def identity_profile_delete(user_profile_id: int):
    if not _tools_mounted():
        return _unavailable()
    profile = _buda_db.get_or_404(BudaUserProfile, user_profile_id)
    name = profile.name
    _buda_db.session.delete(profile)
    _buda_db.session.commit()
    flash(gettext("Perfil de usuario '%(name)s' eliminado.", name=name), "success")
    return redirect(url_for("capabilities.identity_profiles"))


@capabilities_bp.route("/use")
def use_in_operation():
    """Abre una operación con contexto, sin aplicar ni vincular recursos."""

    operation_id = request.args.get("operation_id", "")
    resource_type = request.args.get("resource_type", "")
    resource_id = request.args.get("resource_id", "")
    operations = {operation.id: operation for operation in _operations()}
    if operation_id not in operations:
        flash(gettext("Seleccioná una operación válida."), "error")
        return redirect(url_for("capabilities.catalog"))

    if resource_type == "motor" and resource_id in PluginRegistry.list_kinds():
        query = urlencode({"catalog_kind": resource_id})
        fragment = "tab-plugins"
    elif (
        resource_type == "perfil"
        and _tools_mounted()
        and resource_id.isdigit()
        and _buda_db.session.get(BudaUserProfile, int(resource_id))
    ):
        query = urlencode({"catalog_profile_id": resource_id})
        fragment = "tab-mechanics"
    elif resource_type == "contexto":
        try:
            source = current_app.config["BEHAVIOR_CONTEXT_REPOSITORY"].get(resource_id)
        except KeyError:
            source = None
        if source is None or source.status != BehaviorContextStatus.ACTIVE or not source.integrity_ok:
            flash(gettext("La fuente de contexto ya no está disponible."), "error")
            return redirect(url_for("capabilities.catalog"))
        query = urlencode({"catalog_context_id": resource_id})
        fragment = "tab-preparation"
    elif (
        resource_type == "actividad"
        and _tools_mounted()
        and resource_id.isdigit()
        and _buda_db.session.get(BudaActivity, int(resource_id))
    ):
        query = urlencode({"catalog_activity_id": resource_id})
        fragment = "tab-mechanics"
    else:
        flash(gettext("La capacidad seleccionada ya no está disponible."), "error")
        return redirect(url_for("capabilities.catalog"))

    return redirect(f"{url_for('operations.detail', operation_id=operation_id)}?{query}#{fragment}")
