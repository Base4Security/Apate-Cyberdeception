"""Salud y configuración de integraciones externas.

El resumen conserva comprobaciones locales de solo lectura. Las pruebas de
conexión son acciones explícitas del operador: nunca se ejecutan al abrir una
pantalla y no despliegan recursos ni generan contenido.
"""

from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from openai import OpenAI

from ...audit import OperatorAction
from ...i18n import gettext as _
from ...identity import IdentityRole, LocalIdentityProvider
from BUDA.utils.config_utils import load_llm_config as _buda_load_llm_config
from BUDA.utils.config_utils import save_llm_config as _buda_save_llm_config
from BUDA.utils.init_db_util import recreate_database as _buda_recreate_database
from DOLOST.context import Context as _DolostContext
from DOLOST.services.docker_manager import DockerManager as _DolostDockerManager

health_bp = Blueprint("health", __name__, url_prefix="/health")

_docker_manager = _DolostDockerManager.get_instance()
_RESET_CONFIRMATION = "REINICIAR DATOS"
_IDENTITY_OPERATION_ID = "identity-management"


def _local_identity_provider() -> LocalIdentityProvider | None:
    provider = current_app.config["IDENTITY_PROVIDER"]
    if not isinstance(provider, LocalIdentityProvider):
        flash(_("La administración de usuarios desde la pantalla requiere el proveedor local."), "error")
        return None
    return provider


def _actor_name() -> str:
    """Resuelve el operador autenticado o su alias de sesión abierta."""

    identity_id = session.get("identity_id")
    if isinstance(identity_id, str):
        identity = current_app.config["IDENTITY_PROVIDER"].get(identity_id)
        if identity is not None:
            return identity.display_name
    return session.get("operator") or "sin especificar"


def _log_identity_action(*, action: str, outcome: str, detail: str, target: str | None = None) -> None:
    """Audita cambios de identidad local de forma trazable en operaciones."""

    repo = current_app.config["OPERATOR_ACTION_REPOSITORY"]
    repo.append(
        OperatorAction(
            operation_id=_IDENTITY_OPERATION_ID,
            action=action,
            operator=_actor_name(),
            outcome=outcome,
            detail=detail,
            target=target,
        )
    )


def _identity_admin_context(provider: LocalIdentityProvider) -> dict[str, Any]:
    identities = provider.list()
    active_administrator_count = len(
        [identity for identity in identities if identity.active and identity.role is IdentityRole.ADMINISTRATION]
    )
    available_teams = sorted({identity.team_id for identity in identities if identity.team_id})
    return {
        "identities": identities,
        "active_administrator_count": active_administrator_count,
        "available_teams": available_teams,
    }



def _integrations_enabled() -> bool:
    return bool(current_app.config["APATE_MOUNT_EXTERNAL_TOOLS"])


def _unavailable():
    """Explica por qué la configuración externa está deshabilitada."""

    return render_template("health/unavailable.html")


def _load_llm_settings() -> dict[str, Any]:
    """Normaliza la respuesta heredada de BUDA cuando no existe el archivo."""

    settings = _buda_load_llm_config()
    return settings if isinstance(settings, dict) else {}


def _docker_candidate_from_form() -> dict[str, Any] | None:
    """Construye el contrato que consume ``DockerManager`` desde el formulario."""

    config_type = request.form.get("type")
    if config_type == "env":
        return {"from_env": True}
    if config_type == "tcp":
        return {"tcp": f"tcp://{request.form.get('host', '')}:{request.form.get('port', '')}"}
    if config_type == "socket":
        return {"socket": request.form.get("socketPath", "")}
    if config_type != "tcp_ssl":
        flash(_("Tipo de configuración desconocido: '%(config_type)s'.", config_type=config_type), "error")
        return None

    cert_file = request.files.get("sslCert")
    key_file = request.files.get("sslKey")
    ca_file = request.files.get("sslCa")
    if not (cert_file and key_file and ca_file):
        flash(_("Faltan uno o más archivos TLS (certificado, clave y CA)."), "error")
        return None

    # `config_folder()` y no el atributo de clase: la ruta se resuelve bajo
    # `APATE_DATA_DIR`, que es donde el gestor vendorizado va a buscar despues
    # la configuracion que referencia estos tres archivos. Escribirlos en el
    # directorio de trabajo los dejaba en otro lado que el JSON que los nombra.
    carpeta = _DolostContext.config_folder()
    os.makedirs(carpeta, exist_ok=True)
    cert_path = os.path.join(carpeta, "ssl_cert.pem")
    key_path = os.path.join(carpeta, "ssl_key.pem")
    ca_path = os.path.join(carpeta, "ssl_ca.pem")
    cert_file.save(cert_path)
    key_file.save(key_path)
    ca_file.save(ca_path)
    return {
        # El gestor vendorizado selecciona la rama TLS por esta marca y
        # luego lee los detalles desde ``tcp_ssl``. Sus interfaces
        # originales omitían la marca, por lo que el modo nunca funcionaba.
        "ssl": True,
        "tcp_ssl": {
            "host": request.form.get("host", ""),
            "port": request.form.get("port", ""),
            "cert_path": cert_path,
            "key_path": key_path,
            "ca_path": ca_path,
        },
    }


def _docker_test_payload(config: dict[str, Any]) -> dict[str, Any]:
    """Adapta configuraciones TLS históricas sin modificar el archivo guardado."""

    if "tcp_ssl" in config and "ssl" not in config:
        return {"ssl": True, **config}
    return config


def _lmstudio_models_url(configured_url: str) -> str | None:
    """Deriva el endpoint de modelos desde la URL de chat configurada."""

    parts = urlsplit(configured_url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    path = parts.path.rstrip("/")
    if path.endswith("/chat/completions"):
        path = path[: -len("/chat/completions")] + "/models"
    elif not path.endswith("/models"):
        path = "/v1/models"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _test_content_generation(settings: dict[str, Any]) -> tuple[bool, str]:
    """Comprueba acceso al modelo sin solicitar generación de contenido."""

    provider = settings.get("provider", "")
    model = settings.get("model_name", "")
    if not provider or not model:
        return False, _("Falta configurar proveedor o modelo.")

    try:
        if provider == "openai":
            api_key = settings.get("api_key", "")
            if not api_key:
                return False, _("Falta configurar la API key de OpenAI.")
            OpenAI(api_key=api_key, timeout=8.0).models.retrieve(model)
        elif provider == "lmstudio":
            models_url = _lmstudio_models_url(settings.get("lmstudio_url", ""))
            if not models_url:
                return False, _("La URL de LM Studio no es válida.")
            response = requests.get(models_url, timeout=8.0)
            response.raise_for_status()
        else:
            return False, _("El proveedor configurado no es compatible.")
    except Exception as exc:  # la UI no expone detalles que puedan contener secretos
        current_app.logger.warning("Falló la prueba del proveedor de contenido: %s", type(exc).__name__)
        return False, _("No se pudo conectar con el proveedor y modelo configurados.")
    return True, _("Conexión verificada sin generar contenido.")


@health_bp.route("/administration/users")
def identity_users():
    """Gestiona alta/cambio simple de usuarios locales sin exponer hashes."""

    provider = _local_identity_provider()
    if provider is None:
        return redirect(url_for("health.index"))

    identities = provider.list()

    return render_template(
        "health/users.html",
        **_identity_admin_context(provider),
        has_no_identities=not bool(identities),
    )


@health_bp.post("/administration/users/create")
def create_identity_user():
    """Crea un usuario local desde la UI sin exponer su contraseña."""

    provider = _local_identity_provider()
    if provider is None:
        return redirect(url_for("health.index"))

    role_raw = request.form.get("role", IdentityRole.ADMINISTRATION.value).strip()
    team_id = request.form.get("team_id", "").strip() or None
    display_name = request.form.get("display_name", "").strip()
    password = request.form.get("password", "").strip()
    password_confirmation = request.form.get("password_confirmation", "").strip()
    try:
        role = IdentityRole(role_raw)
    except ValueError:
        flash(_("Rol de usuario inválido."), "error")
        _log_identity_action(
            action="identity_create",
            outcome="error",
            detail=_("Rol de usuario inválido al crear una identidad."),
        )
        return redirect(url_for("health.identity_users"))

    if not password or not password_confirmation:
        flash(_("La contraseña y su confirmación son obligatorias."), "error")
        _log_identity_action(
            action="identity_create",
            outcome="error",
            detail=_("Intento de alta de usuario sin contraseña."),
            target=display_name,
        )
        return redirect(url_for("health.identity_users"))
    if password != password_confirmation:
        flash(_("Las contraseñas no coinciden."), "error")
        _log_identity_action(
            action="identity_create",
            outcome="error",
            detail=_("Las contraseñas no coincidían en la carga."),
            target=display_name,
        )
        return redirect(url_for("health.identity_users"))

    try:
        identity = provider.create(display_name, password, role=role, team_id=team_id)
    except ValueError as exc:
        flash(str(exc), "error")
        _log_identity_action(
            action="identity_create",
            outcome="error",
            detail=_("No se pudo crear el usuario '%(name)s'.", name=display_name),
            target=display_name,
        )
        return redirect(url_for("health.identity_users"))

    flash(_("Usuario creado: %(name)s.", name=identity.display_name), "success")
    _log_identity_action(
        action="identity_create",
        outcome="success",
        detail=_("Alta de usuario '%(name)s' con rol %(role)s.", name=identity.display_name, role=identity.role.value),
        target=identity.id,
    )
    return redirect(url_for("health.identity_users"))


@health_bp.post("/administration/users/<identity_id>/change-password")
def change_identity_password(identity_id: str):
    """Cambia password de usuario local sin mostrarla en pantalla."""

    provider = _local_identity_provider()
    if provider is None:
        return redirect(url_for("health.index"))

    new_password = request.form.get("new_password", "").strip()
    new_password_confirmation = request.form.get("new_password_confirmation", "").strip()
    if not new_password or not new_password_confirmation:
        flash(_("La contraseña y su confirmación son obligatorias."), "error")
        return redirect(url_for("health.identity_users"))
    if new_password != new_password_confirmation:
        flash(_("Las contraseñas no coinciden."), "error")
        _log_identity_action(
            action="identity_change_password",
            outcome="error",
            detail=_("No se pudo cambiar la contraseña de '%(identity_id)s'.", identity_id=identity_id),
            target=identity_id,
        )
        return redirect(url_for("health.identity_users"))

    try:
        identity = provider.change_password(identity_id, new_password)
    except KeyError:
        flash(_("No existe una identidad con ese identificador."), "error")
        _log_identity_action(
            action="identity_change_password",
            outcome="error",
            detail=_("No existe una identidad con ese identificador (%(identity_id)s).", identity_id=identity_id),
            target=identity_id,
        )
        return redirect(url_for("health.identity_users"))

    # Quien acaba de cambiar su propia clave ya demostro que controla la cuenta:
    # se le renueva la marca de sesion para no expulsarlo. Las sesiones de
    # *otras* personas si caen, que es el punto de versionar la credencial.
    if session.get("identity_id") == identity.id:
        session["credential_version"] = identity.credential_version

    flash(_("Contraseña actualizada para %(name)s.", name=identity.display_name), "success")
    _log_identity_action(
        action="identity_change_password",
        outcome="success",
        detail=_("Contraseña actualizada para '%(name)s'.", name=identity.display_name),
        target=identity.id,
    )
    return redirect(url_for("health.identity_users"))


@health_bp.post("/administration/users/<identity_id>/deactivate")
def deactivate_identity_user(identity_id: str):
    """Desactiva una identidad local y obliga al guardado del log de cambios."""

    provider = _local_identity_provider()
    if provider is None:
        return redirect(url_for("health.index"))

    try:
        identity = provider.deactivate(identity_id)
    except ValueError as exc:
        flash(str(exc), "error")
        _log_identity_action(
            action="identity_deactivate",
            outcome="error",
            detail=_("No se pudo desactivar la identidad '%(identity_id)s'.", identity_id=identity_id),
            target=identity_id,
        )
        return redirect(url_for("health.identity_users"))
    except KeyError:
        flash(_("No existe una identidad con ese identificador."), "error")
        _log_identity_action(
            action="identity_deactivate",
            outcome="error",
            detail=_("No existe una identidad con ese identificador (%(identity_id)s).", identity_id=identity_id),
            target=identity_id,
        )
        return redirect(url_for("health.identity_users"))

    if str(session.get("identity_id")) == str(identity.id):
        session.clear()
    flash(_("Usuario desactivado: %(name)s.", name=identity.display_name), "success")
    _log_identity_action(
        action="identity_deactivate",
        outcome="success",
        detail=_("Usuario '%(name)s' desactivado.", name=identity.display_name),
        target=identity.id,
    )
    return redirect(url_for("health.identity_users"))


@health_bp.route("/")
def index():
    playground_path = Path(current_app.config["APATE_PLAYGROUND_PATH"])
    mounted = _integrations_enabled()
    docker_cli = bool(shutil.which("docker"))
    checks = [
        {
            "name": _("Docker CLI"),
            "status": "available" if docker_cli else "unavailable",
            "detail": _("Ejecutable encontrado en PATH.") if docker_cli else _("No se encontró el ejecutable docker en PATH."),
            "action": _("Instalá Docker Desktop y verificá que el comando docker esté en PATH."),
            "href": url_for("health.network_host_runtime"),
            "link_label": _("Configurar y diagnosticar"),
        },
        {
            "name": _("Playground"),
            "status": "configured" if playground_path.is_dir() else "unavailable",
            "detail": _("Ruta configurada: %(path)s", path=playground_path),
            "action": _("Corregí APATE_PLAYGROUND_PATH o restaurá playground-stack/."),
        },
        {
            "name": _("Red y host"),
            "status": "configured" if mounted else "disabled",
            "detail": _("Capacidad de decoys de red preparada.") if mounted else _("Capacidad de decoys de red deshabilitada por APATE_MOUNT_EXTERNAL_TOOLS."),
            "action": _("Iniciá Apate con APATE_MOUNT_EXTERNAL_TOOLS habilitado."),
            "href": url_for("health.network_host_runtime"),
            "link_label": _("Abrir runtime"),
        },
        {
            "name": _("Identidad y comportamiento"),
            "status": "configured" if mounted else "disabled",
            "detail": _("Capacidad de comportamiento simulado preparada.") if mounted else _("Capacidad de comportamiento simulado deshabilitada por APATE_MOUNT_EXTERNAL_TOOLS."),
            "action": _("Iniciá Apate con APATE_MOUNT_EXTERNAL_TOOLS habilitado."),
            "href": url_for("health.content_generation"),
            "link_label": _("Configurar generación"),
        },
        {
            "name": _("Inteligencia de amenazas"),
            "status": "configured"
            if current_app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].load().get("api_key")
            else "disabled",
            "detail": _("API key de VirusTotal configurada.")
            if current_app.config["VIRUSTOTAL_CONFIG_REPOSITORY"].load().get("api_key")
            else _("VirusTotal disponible bajo demanda, sin credencial configurada."),
            "action": _("Configurá una API key para consultar IoCs desde Telemetría."),
            "href": url_for("health.threat_intelligence"),
            "link_label": _("Configurar VirusTotal"),
        },
        {
            "name": _("SIEM/SOAR"),
            "status": "configured"
            if current_app.config["SIEM_SOAR_CONFIG_REPOSITORY"].load().get("webhook_url")
            else "disabled",
            "detail": _("Webhook de salida configurado.")
            if current_app.config["SIEM_SOAR_CONFIG_REPOSITORY"].load().get("webhook_url")
            else _("Envío manual de bundles STIX, sin webhook configurado."),
            "action": _("Configurá un webhook para enviar el informe STIX al cerrar una operación."),
            "href": url_for("health.siem_soar"),
            "link_label": _("Configurar SIEM/SOAR"),
        },
        {
            "name": _("Elasticsearch"),
            "status": "configured",
            "detail": _("Endpoint configurado: %(url)s", url=current_app.config["APATE_ELASTIC_URL"]),
            "action": _("Verificá APATE_ELASTIC_URL y el stack antes de iniciar una sesión."),
        },
    ]
    return render_template("health/index.html", checks=checks, checked_at=datetime.now(timezone.utc))


@health_bp.route("/configuration/threat-intelligence", methods=["GET", "POST"])
def threat_intelligence():
    """Configura VirusTotal sin devolver nunca la API key al HTML."""

    repo = current_app.config["VIRUSTOTAL_CONFIG_REPOSITORY"]
    existing = repo.load()
    if request.method == "POST":
        submitted_api_key = request.form.get("api_key", "").strip()
        repo.save_api_key(submitted_api_key or existing.get("api_key", ""))
        flash(_("Configuración de VirusTotal guardada."), "success")
        return redirect(url_for("health.threat_intelligence"))
    return render_template(
        "health/threat_intelligence.html",
        api_key_configured=bool(existing.get("api_key")),
    )


@health_bp.route("/configuration/siem-soar", methods=["GET", "POST"])
def siem_soar():
    """Configura el webhook manual de salida sin devolver su token al HTML."""

    repo = current_app.config["SIEM_SOAR_CONFIG_REPOSITORY"]
    existing = repo.load()
    if request.method == "POST":
        webhook_url = request.form.get("webhook_url", "").strip()
        parsed_url = urlsplit(webhook_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            flash(_("Indicá una URL HTTP(S) válida para el webhook."), "error")
            return redirect(url_for("health.siem_soar"))
        submitted_auth_token = request.form.get("auth_token", "").strip()
        repo.save(webhook_url, submitted_auth_token or existing.get("auth_token", ""))
        flash(_("Configuración de SIEM/SOAR guardada."), "success")
        return redirect(url_for("health.siem_soar"))
    return render_template(
        "health/siem_soar.html",
        webhook_url=existing.get("webhook_url", ""),
        auth_token_configured=bool(existing.get("auth_token")),
    )


@health_bp.route("/configuration/network-host-runtime", methods=["GET", "POST"])
def network_host_runtime():
    """Configura el cliente Docker global usado por la superficie red/host."""

    if not _integrations_enabled():
        return _unavailable()
    if request.method == "POST":
        candidate = _docker_candidate_from_form()
        if candidate is None:
            return redirect(url_for("health.network_host_runtime"))
        try:
            connected = _docker_manager.check_client_configuration(docker_client=candidate)
        except Exception as exc:
            flash(_("No se pudo validar la configuración de Docker: %(error)s", error=exc), "error")
            return redirect(url_for("health.network_host_runtime"))
        if connected:
            _docker_manager.configure_client(docker_client=candidate)
            _docker_manager.check_connection()
            flash(_("Cliente Docker configurado y conectado correctamente."), "success")
        else:
            flash(_("No se pudo conectar a Docker; la configuración no fue aplicada."), "error")
        return redirect(url_for("health.network_host_runtime"))
    docker_config = _docker_manager.get_current_client_config() or {}
    return render_template("health/network_host_runtime.html", docker_config=docker_config, configured=bool(docker_config))


@health_bp.post("/configuration/network-host-runtime/test")
def network_host_runtime_test():
    """Prueba la configuración Docker guardada sin reemplazarla."""

    if not _integrations_enabled():
        return _unavailable()
    config = _docker_manager.get_current_client_config() or {}
    if not config:
        flash(_("No hay una configuración Docker guardada para probar."), "error")
    elif _docker_manager.check_client_configuration(docker_client=_docker_test_payload(config)):
        flash(_("Conexión Docker verificada con la configuración guardada."), "success")
    else:
        flash(_("La configuración está guardada, pero Docker no respondió."), "error")
    return redirect(url_for("health.network_host_runtime"))


@health_bp.route("/configuration/content-generation", methods=["GET", "POST"])
def content_generation():
    """Configura el proveedor de generación sin devolver su API key al HTML."""

    if not _integrations_enabled():
        return _unavailable()
    existing = _load_llm_settings()
    if request.method == "POST":
        submitted_api_key = request.form.get("api_key", "")
        new_config = {
            "provider": request.form.get("provider", ""),
            "model_name": request.form.get("model_name", ""),
            "api_key": submitted_api_key if submitted_api_key else existing.get("api_key", ""),
            "lmstudio_url": request.form.get("lmstudio_url", "http://localhost:1234/v1/chat/completions"),
        }
        result = _buda_save_llm_config(new_config)
        if "error" in result:
            flash(_("No se pudo guardar la configuración: %(error)s", error=result["error"]), "error")
        else:
            flash(_("Configuración de generación guardada."), "success")
        return redirect(url_for("health.content_generation"))
    return render_template(
        "health/content_generation.html",
        settings=existing,
        api_key_configured=bool(existing.get("api_key")),
        reset_confirmation=_RESET_CONFIRMATION,
    )


@health_bp.post("/configuration/content-generation/test")
def content_generation_test():
    """Prueba proveedor/modelo guardados sin generar ni persistir contenido."""

    if not _integrations_enabled():
        return _unavailable()
    success, message = _test_content_generation(_load_llm_settings())
    flash(message, "success" if success else "error")
    return redirect(url_for("health.content_generation"))


@health_bp.post("/configuration/behavior-data/reset")
def behavior_data_reset():
    """Recrea los datos globales solo tras una confirmación exacta."""

    if not _integrations_enabled():
        return _unavailable()
    if request.form.get("confirmation", "").strip() != _RESET_CONFIRMATION:
        flash(_("Escribí %(confirmation)s exactamente; no se modificó ningún dato.", confirmation=_RESET_CONFIRMATION), "error")
        return redirect(url_for("health.content_generation"))
    result = _buda_recreate_database()
    if isinstance(result, dict) and "message" in result:
        flash(result["message"], "success")
    else:
        flash(_("No se pudo reiniciar la base: %(result)s", result=result), "error")
    return redirect(url_for("health.content_generation"))
