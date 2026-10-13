"""Control plane web para destinos y honeyusers de Active Directory."""

from __future__ import annotations

from pathlib import Path

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from ...deployment import DeploymentError, DeploymentStatus, DeploymentTarget
from ...i18n import gettext as _
from .._operation_health import build_operation_health
from .operations import _log_operator_action

deployments_bp = Blueprint("deployments", __name__)


@deployments_bp.get("/operations/<operation_id>/health")
def operation_health(operation_id: str):
    """Lee frescura de fuentes y recursos sin disparar pruebas de conexión."""

    operation = _operation_or_404(operation_id)
    records = current_app.config["DEPLOYMENT_REPOSITORY"].list_records_for_operation(operation_id)
    monitoring = current_app.config["HONEYUSER_MONITORING_SERVICE"].status()
    health = build_operation_health(records, monitoring,
                                    current_app.config["TELEMETRY_COLLECTOR"].list_events(operation_id))
    return render_template("deployments/health.html", operation=operation, health=health,
                           monitoring=monitoring)


@deployments_bp.post("/deployments/targets/filesystem")
def create_filesystem_target():
    """Registra una raíz local o SMB montada y su lista de carpetas autorizadas."""

    try:
        root = Path(request.form.get("address", "").strip())
        directories = [line.strip() for line in request.form.get("allowed_subdirs", "").splitlines() if line.strip()]
        if not root.is_absolute() or not root.is_dir() or root.is_symlink() or not directories:
            raise DeploymentError(_("La raíz debe ser un directorio absoluto montado y debe haber al menos una carpeta autorizada."))
        if any(Path(directory).is_absolute() or ".." in Path(directory).parts for directory in directories):
            raise DeploymentError(_("Las carpetas autorizadas deben ser relativas a la raíz y no contener '..'."))
        target = DeploymentTarget(name=request.form.get("name", "").strip(),
                                  connector_kind="filesystem-honeyfile", address=str(root.resolve()),
                                  asset_id=request.form.get("asset_id", "").strip() or None,
                                  config={"allowed_subdirs": directories})
        current_app.config["DEPLOYMENT_TARGET_REPOSITORY"].save(target)
    except (DeploymentError, ValueError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("deployments.targets"))
    _log_operator_action("deployment-administration", action="create_filesystem_target", outcome="success",
                         detail=_("Destino de archivos '%(name)s' configurado.", name=target.name), target=target.id)
    flash(_("Destino de archivos guardado. Solo APATE podrá administrar señuelos con recibo de propiedad."), "success")
    return redirect(url_for("deployments.targets"))


@deployments_bp.post("/operations/<operation_id>/deployments/honeyfile/prepare")
def prepare_honeyfile(operation_id: str):
    """Prepara un archivo señuelo sin escribirlo hasta que se confirme el plan."""

    operation = _operation_or_404(operation_id)
    _require_maker_if_enabled()
    target = _target_or_404(request.form.get("target_id", ""))
    if target.connector_kind != "filesystem-honeyfile":
        abort(404)
    plugin_id = request.form.get("plugin_id", "").strip()
    if not plugin_id:
        abort(400, _("La capacidad que será dueña del honeyfile es obligatoria."))
    configuration = {"relative_path": request.form.get("relative_path", "").strip(),
                     "content": request.form.get("content", ""),
                     "rotation_content": request.form.get("rotation_content", "")}
    try:
        plan = current_app.config["DEPLOYMENT_SERVICE"].prepare(
            operation_id=operation.id, plugin_id=plugin_id, target=target, configuration=configuration)
    except DeploymentError as exc:
        _log_operator_action(operation.id, action="prepare_honeyfile", outcome="error", detail=str(exc),
                             plugin_id=plugin_id, target=target.id)
        flash(str(exc), "error")
        return redirect(url_for("deployments.operation_deployments", operation_id=operation.id))
    _log_operator_action(operation.id, action="prepare_honeyfile", outcome="success",
                         detail=_("Plan de honeyfile preparado; todavía no se escribió el archivo."),
                         plugin_id=plugin_id, target=target.id)
    _register_approval_if_enabled(plan)
    flash(_("Plan de archivo preparado. Revisá la ruta y confirmá la creación."), "success")
    return redirect(url_for("deployments.operation_deployments", operation_id=operation.id, plan=plan.id))


def _operation_or_404(operation_id: str):
    try:
        return current_app.config["OPERATION_REPOSITORY"].get(operation_id)
    except Exception as exc:
        from ...core import OperationNotFoundError

        if isinstance(exc, OperationNotFoundError):
            abort(404)
        raise


def _target_or_404(target_id: str):
    try:
        return current_app.config["DEPLOYMENT_TARGET_REPOSITORY"].get(target_id)
    except DeploymentError:
        abort(404)


def _plan_for_operation_or_404(operation_id: str, plan_id: str):
    try:
        plan = current_app.config["DEPLOYMENT_REPOSITORY"].get_plan(plan_id)
    except DeploymentError:
        abort(404)
    if plan.operation_id != operation_id:
        abort(404)
    return plan


def _require_maker_if_enabled() -> None:
    if current_app.config["TWO_PERSON_APPROVAL_ENABLED"] and not getattr(g, "current_identity", None):
        abort(403, _("La aprobación de dos personas exige autenticación activa."))


def _register_approval_if_enabled(plan) -> None:
    if current_app.config["TWO_PERSON_APPROVAL_ENABLED"]:
        current_app.config["PLAN_APPROVAL_REPOSITORY"].register(plan, g.current_identity.id)


def _record_for_operation_or_404(operation_id: str, record_id: str):
    try:
        record = current_app.config["DEPLOYMENT_REPOSITORY"].get_record(record_id)
    except DeploymentError:
        abort(404)
    if record.operation_id != operation_id:
        abort(404)
    return record


@deployments_bp.route("/deployments/targets", methods=["GET", "POST"])
def targets():
    """Configura destinos AD y guarda la cuenta de servicio cifrada."""

    repository = current_app.config["DEPLOYMENT_TARGET_REPOSITORY"]
    if request.method == "POST":
        username = request.form.get("administrative_username", "").strip()
        password = request.form.get("administrative_password", "")
        ous = [line.strip() for line in request.form.get("ou_allowlist", "").splitlines() if line.strip()]
        suffixes = [line.strip().lower() for line in request.form.get("allowed_upn_suffixes", "").splitlines() if line.strip()]
        if not username or not password or not ous or not suffixes:
            flash(_("La cuenta de servicio, su contraseña, al menos una OU y un sufijo UPN son obligatorios."), "error")
            return redirect(url_for("deployments.targets"))
        try:
            target = DeploymentTarget(
                name=request.form.get("name", "").strip(),
                connector_kind="active-directory-honeyuser",
                address=request.form.get("address", "").strip(),
                asset_id=request.form.get("asset_id", "").strip() or None,
                config={
                    "ou_allowlist": ous,
                    "allowed_upn_suffixes": suffixes,
                    "domain": request.form.get("domain", "").strip().lower(),
                    "source_role": request.form.get("source_role", "dc").strip().lower(),
                    "transport": request.form.get("transport", "ntlm").strip().lower(),
                    "server_cert_validation": request.form.get("server_cert_validation", "validate").strip().lower(),
                },
            )
            target.credential_ref = f"secret://deployment-target/{target.id}/administrative"
            current_app.config["DEPLOYMENT_CREDENTIAL_STORE"].save(
                target.credential_ref, {"username": username, "password": password}
            )
            repository.save(target)
        except (DeploymentError, ValueError) as exc:
            flash(str(exc), "error")
            return redirect(url_for("deployments.targets"))
        _log_operator_action(
            "deployment-administration",
            action="create_deployment_target",
            outcome="success",
            detail=_("Destino de Active Directory '%(name)s' configurado.", name=target.name),
            target=target.id,
        )
        flash(_("Destino guardado. La contraseña quedó cifrada y no volverá a mostrarse."), "success")
        return redirect(url_for("deployments.targets"))
    configured = repository.list()
    groups = {}
    monitor_records = current_app.config["HONEYUSER_MONITORING_SERVICE"].status()["records"]
    deployment_repo = current_app.config["DEPLOYMENT_REPOSITORY"]
    by_target = {}
    for operation in current_app.config["OPERATION_REPOSITORY"].list():
        for record in deployment_repo.list_records_for_operation(operation.id):
            by_target.setdefault(record.target_id, []).append(record)
    for target in configured:
        if target.connector_kind != "active-directory-honeyuser":
            continue
        group_name = target.config.get("domain") or target.address
        group = groups.setdefault(group_name, {"sources": 0, "active": 0, "errors": 0})
        group["sources"] += 1
        for record in by_target.get(target.id, []):
            if record.status in {DeploymentStatus.ACTIVE, DeploymentStatus.DEGRADED}:
                group["active"] += 1
                state = monitor_records.get(record.id, {})
                if state.get("last_error") or state.get("last_refresh_error"):
                    group["errors"] += 1
    return render_template("deployments/targets.html", targets=[target for target in configured if target.connector_kind == "active-directory-honeyuser"],
                           filesystem_targets=[target for target in configured if target.connector_kind == "filesystem-honeyfile"],
                           target_histories={target.id: repository.history(target.id) for target in configured},
                           source_groups=groups)


@deployments_bp.post("/deployments/targets/<target_id>/scope")
def update_target_scope(target_id: str):
    """Versiona alcance/dirección; los planes anteriores conservan su snapshot."""

    previous = _target_or_404(target_id)
    if previous.connector_kind != "active-directory-honeyuser":
        abort(404)
    try:
        expected = int(request.form.get("revision", "0"))
        if expected != previous.revision:
            raise DeploymentError(_("La revisión del destino cambió; volvé a cargarlo antes de guardar."))
        ous = [line.strip() for line in request.form.get("ou_allowlist", "").splitlines() if line.strip()]
        suffixes = [line.strip().lower() for line in request.form.get("allowed_upn_suffixes", "").splitlines() if line.strip()]
        if not ous or not suffixes:
            raise DeploymentError(_("El destino exige al menos una OU y un sufijo UPN."))
        updated = DeploymentTarget(
            id=previous.id, revision=previous.revision + 1, name=previous.name,
            connector_kind=previous.connector_kind, credential_ref=previous.credential_ref,
            asset_id=previous.asset_id, address=request.form.get("address", "").strip(),
            config={**previous.config, "ou_allowlist": ous, "allowed_upn_suffixes": suffixes,
                    "domain": request.form.get("domain", "").strip().lower(),
                    "source_role": request.form.get("source_role", "dc").strip().lower()},
        )
        current_app.config["DEPLOYMENT_TARGET_REPOSITORY"].save(updated)
    except (DeploymentError, ValueError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("deployments.targets"))
    _log_operator_action("deployment-administration", action="update_deployment_target_scope", outcome="success",
                         detail=_("Alcance del destino '%(name)s' actualizado a revisión %(revision)s.",
                                  name=updated.name, revision=updated.revision), target=updated.id)
    flash(_("Alcance versionado. Los planes anteriores conservaron su destino original."), "success")
    return redirect(url_for("deployments.targets"))


@deployments_bp.post("/deployments/targets/<target_id>/credential")
def update_target_credential(target_id: str):
    """Rota la cuenta de servicio sin reescribir planes históricos."""

    target = _target_or_404(target_id)
    if target.connector_kind != "active-directory-honeyuser":
        abort(404)
    username = request.form.get("administrative_username", "").strip()
    password = request.form.get("administrative_password", "")
    if not username or not password or not target.credential_ref:
        flash(_("El usuario y la nueva contraseña de servicio son obligatorios."), "error")
        return redirect(url_for("deployments.targets"))
    try:
        current_app.config["DEPLOYMENT_CREDENTIAL_STORE"].save(
            target.credential_ref,
            {"username": username, "password": password},
        )
    except DeploymentError as exc:
        flash(str(exc), "error")
        return redirect(url_for("deployments.targets"))
    _log_operator_action(
        "deployment-administration",
        action="rotate_deployment_target_credential",
        outcome="success",
        detail=_("Credencial de servicio del destino '%(name)s' actualizada.", name=target.name),
        target=target.id,
    )
    flash(_("Credencial de servicio actualizada y cifrada."), "success")
    return redirect(url_for("deployments.targets"))


@deployments_bp.get("/operations/<operation_id>/deployments")
def operation_deployments(operation_id: str):
    operation = _operation_or_404(operation_id)
    repository = current_app.config["DEPLOYMENT_REPOSITORY"]
    plans = repository.list_plans_for_operation(operation_id)
    records = repository.list_records_for_operation(operation_id)
    records_by_plan = {record.plan_id: record for record in records}
    approvals_enabled = current_app.config["TWO_PERSON_APPROVAL_ENABLED"]
    approval_statuses = {plan.id: current_app.config["PLAN_APPROVAL_REPOSITORY"].status(plan)
                         for plan in plans} if approvals_enabled else {}
    return render_template(
        "deployments/operation.html",
        operation=operation,
        targets=[target for target in current_app.config["DEPLOYMENT_TARGET_REPOSITORY"].list() if target.connector_kind == "active-directory-honeyuser"],
        filesystem_targets=[target for target in current_app.config["DEPLOYMENT_TARGET_REPOSITORY"].list() if target.connector_kind == "filesystem-honeyfile"],
        plans=plans,
        records=records,
        records_by_plan=records_by_plan,
        approvals_enabled=approvals_enabled,
        approval_statuses=approval_statuses,
        monitoring_status=current_app.config["HONEYUSER_MONITORING_SERVICE"].status(),
    )


@deployments_bp.post("/operations/<operation_id>/deployments/honeyuser/prepare")
def prepare_honeyuser(operation_id: str):
    operation = _operation_or_404(operation_id)
    _require_maker_if_enabled()
    target = _target_or_404(request.form.get("target_id", ""))
    if target.connector_kind != "active-directory-honeyuser":
        abort(404)
    plugin_id = request.form.get("plugin_id", "").strip()
    if not plugin_id:
        abort(400, _("La capacidad que será dueña del honeyuser es obligatoria."))
    configuration = {
        key: request.form.get(key, "").strip()
        for key in ("sam_account_name", "display_name", "given_name", "surname", "ou_dn", "upn_suffix")
    }
    try:
        plan = current_app.config["DEPLOYMENT_SERVICE"].prepare(
            operation_id=operation.id,
            plugin_id=plugin_id,
            target=target,
            configuration=configuration,
        )
    except DeploymentError as exc:
        _log_operator_action(operation.id, action="prepare_honeyuser", outcome="error", detail=str(exc), plugin_id=plugin_id, target=target.id)
        flash(str(exc), "error")
        return redirect(url_for("deployments.operation_deployments", operation_id=operation.id))
    _log_operator_action(operation.id, action="prepare_honeyuser", outcome="success", detail=_("Plan de honeyuser preparado; todavía no se modificó Active Directory."), plugin_id=plugin_id, target=target.id)
    _register_approval_if_enabled(plan)
    flash(_("Plan preparado. Revisá el cambio y confirmalo para crear el usuario en AD."), "success")
    return redirect(url_for("deployments.operation_deployments", operation_id=operation.id, plan=plan.id))


@deployments_bp.post("/operations/<operation_id>/deployments/plans/<plan_id>/execute")
def execute_plan(operation_id: str, plan_id: str):
    plan = _plan_for_operation_or_404(operation_id, plan_id)
    kind = "honeyfile" if plan.connector_kind == "filesystem-honeyfile" else "honeyuser"
    try:
        if current_app.config["TWO_PERSON_APPROVAL_ENABLED"]:
            current_app.config["PLAN_APPROVAL_REPOSITORY"].require_approved(plan)
        record = current_app.config["DEPLOYMENT_SERVICE"].execute(plan.id)
    except (DeploymentError, ValueError) as exc:
        _log_operator_action(operation_id, action=f"execute_{kind}", outcome="error", detail=str(exc), plugin_id=plan.plugin_id, target=plan.target_id)
        flash(str(exc), "error")
    else:
        _log_operator_action(operation_id, action=f"execute_{kind}", outcome="success", detail=record.detail, plugin_id=plan.plugin_id, target=plan.target_id)
        flash(record.detail, "success")
    return redirect(url_for("deployments.operation_deployments", operation_id=operation_id))


@deployments_bp.post("/operations/<operation_id>/deployments/plans/<plan_id>/approve")
def approve_plan(operation_id: str, plan_id: str):
    """Una identidad distinta aprueba la instantánea exacta del plan."""
    plan = _plan_for_operation_or_404(operation_id, plan_id)
    if not current_app.config["TWO_PERSON_APPROVAL_ENABLED"]:
        abort(404)
    _require_maker_if_enabled()
    try:
        current_app.config["PLAN_APPROVAL_REPOSITORY"].approve(plan, g.current_identity.id)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        _log_operator_action(operation_id, action="approve_deployment_plan", outcome="success",
                             target=plan.id, detail=_('Plan aprobado por segunda identidad.'))
        flash(_("Plan aprobado."), "success")
    return redirect(url_for("deployments.operation_deployments", operation_id=operation_id, plan=plan_id))


def _record_action(operation_id: str, record_id: str, action: str):
    record = _record_for_operation_or_404(operation_id, record_id)
    kind = "honeyfile" if record.connector_kind == "filesystem-honeyfile" else "honeyuser"
    service = current_app.config["DEPLOYMENT_SERVICE"]
    method = getattr(service, action)
    try:
        updated = method(record.id)
    except DeploymentError as exc:
        _log_operator_action(operation_id, action=f"{action}_{kind}", outcome="error", detail=str(exc), plugin_id=record.plugin_id, target=record.target_id)
        flash(str(exc), "error")
    else:
        _log_operator_action(operation_id, action=f"{action}_{kind}", outcome="success", detail=updated.detail, plugin_id=record.plugin_id, target=record.target_id)
        flash(updated.detail, "success")
    return redirect(url_for("deployments.operation_deployments", operation_id=operation_id))


@deployments_bp.post("/operations/<operation_id>/deployments/<record_id>/refresh")
def refresh(operation_id: str, record_id: str):
    return _record_action(operation_id, record_id, "refresh")


@deployments_bp.post("/operations/<operation_id>/deployments/<record_id>/rotate")
def rotate(operation_id: str, record_id: str):
    return _record_action(operation_id, record_id, "rotate")


@deployments_bp.post("/operations/<operation_id>/deployments/<record_id>/retire")
def retire(operation_id: str, record_id: str):
    return _record_action(operation_id, record_id, "retire")


@deployments_bp.post("/operations/<operation_id>/deployments/<record_id>/retry")
def retry(operation_id: str, record_id: str):
    return _record_action(operation_id, record_id, "retry")


@deployments_bp.post("/operations/<operation_id>/deployments/<record_id>/poll")
def poll(operation_id: str, record_id: str):
    operation = _operation_or_404(operation_id)
    record = _record_for_operation_or_404(operation_id, record_id)
    if record.connector_kind != "active-directory-honeyuser":
        abort(404)
    if record.status not in {DeploymentStatus.ACTIVE, DeploymentStatus.DEGRADED}:
        abort(409, _("Solo se monitorean honeyusers activos o degradados."))
    _plan_for_operation_or_404(operation_id, record.plan_id)
    try:
        events = current_app.config["HONEYUSER_MONITORING_SERVICE"].poll_record(operation, record)
    except DeploymentError as exc:
        _log_operator_action(operation_id, action="poll_honeyuser", outcome="error", detail=str(exc), plugin_id=record.plugin_id, target=record.target_id)
        flash(str(exc), "error")
    else:
        detail = _("Se incorporaron %(count)s eventos nuevos del honeyuser.", count=len(events))
        _log_operator_action(operation_id, action="poll_honeyuser", outcome="success", detail=detail, plugin_id=record.plugin_id, target=record.target_id)
        flash(detail, "success")
    return redirect(url_for("deployments.operation_deployments", operation_id=operation_id))
