"""Conector de honeyusers para Active Directory mediante WinRM.

La cuenta administrativa y la contraseña señuelo nunca forman parte de un
``DeploymentPlan``. El plan conserva referencias opacas y el transporte recibe
los valores recién al ejecutar. Todos los valores variables llegan a
PowerShell dentro de JSON codificado en base64 para evitar construir comandos
con interpolación de entrada del operador.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping, Protocol

from ..i18n import gettext as _
from ..plugins import EventBus, EventType, PluginEvent
from .connector import ConnectorManifest, DeploymentConnector
from .credentials import CredentialStore
from .exceptions import DeploymentExecutionError, DeploymentValidationError
from .models import (
    ConnectorResult,
    DeploymentAction,
    DeploymentPlan,
    DeploymentRecord,
    DeploymentStatus,
    DeploymentTarget,
    PlannedChange,
)

_SAM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$")
_SID_RE = re.compile(r"^S-1-(?:\d+-){1,14}\d+$", re.IGNORECASE)
_KIND = "active-directory-honeyuser"
_SUCCESSFUL_AUTHENTICATION_EVENTS = frozenset({4624, 4768, 4769, 4776})


@dataclass(frozen=True)
class ActiveDirectoryUser:
    """Vista mínima de una identidad obtenida desde AD."""

    sid: str
    distinguished_name: str
    sam_account_name: str
    user_principal_name: str
    description: str
    enabled: bool

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ActiveDirectoryUser":
        return cls(
            sid=str(data["sid"]),
            distinguished_name=str(data["distinguished_name"]),
            sam_account_name=str(data["sam_account_name"]),
            user_principal_name=str(data.get("user_principal_name", "")),
            description=str(data.get("description", "")),
            enabled=bool(data.get("enabled", False)),
        )


@dataclass(frozen=True)
class ActiveDirectoryLogonEvent:
    """Evento de autenticación relevante extraído del Security log."""

    record_id: int
    event_id: int
    timestamp: datetime
    target_user: str
    target_sid: str
    source_ip: str = ""
    workstation: str = ""
    logon_type: str = ""
    status: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ActiveDirectoryLogonEvent":
        timestamp = datetime.fromisoformat(str(data["timestamp"]).replace("Z", "+00:00"))
        return cls(
            record_id=int(data["record_id"]),
            event_id=int(data["event_id"]),
            timestamp=timestamp,
            target_user=str(data.get("target_user", "")),
            target_sid=str(data.get("target_sid", "")),
            source_ip=str(data.get("source_ip", "")),
            workstation=str(data.get("workstation", "")),
            logon_type=str(data.get("logon_type", "")),
            status=str(data.get("status", "")),
        )


class ActiveDirectoryTransport(Protocol):
    """Operaciones remotas necesarias; permite probar sin un dominio real."""

    def validate(self, target: DeploymentTarget, credential: Mapping[str, str], ou_dn: str) -> None: ...

    def find_user(
        self, target: DeploymentTarget, credential: Mapping[str, str], sam_account_name: str
    ) -> ActiveDirectoryUser | None: ...

    def create_or_update_user(
        self, target: DeploymentTarget, credential: Mapping[str, str], parameters: Mapping[str, Any], password: str
    ) -> ActiveDirectoryUser: ...

    def get_user(
        self, target: DeploymentTarget, credential: Mapping[str, str], identity: str
    ) -> ActiveDirectoryUser | None: ...

    def set_password_and_enable(
        self, target: DeploymentTarget, credential: Mapping[str, str], identity: str, password: str
    ) -> ActiveDirectoryUser: ...

    def disable_user(
        self, target: DeploymentTarget, credential: Mapping[str, str], identity: str
    ) -> ActiveDirectoryUser: ...

    def logon_events(
        self,
        target: DeploymentTarget,
        credential: Mapping[str, str],
        *,
        sam_account_name: str,
        sid: str,
        after_record_id: int,
    ) -> list[ActiveDirectoryLogonEvent]: ...


class ActiveDirectoryHoneyuserConnector(DeploymentConnector):
    """Crea, reconcilia, rota y deshabilita una identidad señuelo."""

    kind = _KIND
    manifest = ConnectorManifest(kind=_KIND, contract_version=2,
        actions=frozenset({"deploy", "rotate", "retire"}),
        observations=frozenset({"status", "events"}))

    def __init__(
        self,
        *,
        credential_store: CredentialStore,
        transport: ActiveDirectoryTransport,
        password_factory: Callable[[], str] | None = None,
    ) -> None:
        self._credentials = credential_store
        self._transport = transport
        self._password_factory = password_factory or _strong_password

    def validate(self, target: DeploymentTarget, configuration: dict[str, Any]) -> None:
        parameters = self._validated_parameters(target, configuration)
        credential = self._administrative_credential(target)
        self._transport.validate(target, credential, parameters["ou_dn"])

    def plan(
        self,
        *,
        operation_id: str,
        plugin_id: str,
        target: DeploymentTarget,
        configuration: dict[str, Any],
    ) -> DeploymentPlan:
        parameters = self._validated_parameters(target, configuration)
        parameters["management_marker"] = _management_marker(operation_id, plugin_id)
        existing = self._transport.find_user(
            target, self._administrative_credential(target), parameters["sam_account_name"]
        )
        if existing is not None and existing.description != parameters["management_marker"]:
            raise DeploymentValidationError(
                _(
                    "La cuenta '%(account)s' ya existe y no pertenece a esta operación de APATE.",
                    account=parameters["sam_account_name"],
                )
            )
        action = DeploymentAction.NOOP if existing is not None else DeploymentAction.CREATE
        summary = (
            _("La identidad señuelo ya existe y será reconciliada sin duplicarla.")
            if existing is not None
            else _("Crear y habilitar una identidad señuelo dentro de la OU autorizada.")
        )
        plan = DeploymentPlan(
            operation_id=operation_id,
            plugin_id=plugin_id,
            target=target,
            changes=[
                PlannedChange(
                    action=action,
                    resource_type="active_directory_user",
                    resource_name=parameters["sam_account_name"],
                    summary=summary,
                )
            ],
            parameters=parameters,
        )
        plan.valid_until = plan.created_at + timedelta(seconds=_plan_ttl_seconds(target))
        plan.parameters["honeyuser_credential_ref"] = f"secret://deployment/{plan.id}/honeyuser"
        return plan

    def deploy(self, plan: DeploymentPlan) -> ConnectorResult:
        self._validate_plan(plan)
        secret_ref = str(plan.parameters["honeyuser_credential_ref"])
        password = self._password_for_deploy(secret_ref, str(plan.parameters["sam_account_name"]))
        user = self._transport.create_or_update_user(
            plan.target,
            self._administrative_credential(plan.target),
            plan.parameters,
            password,
        )
        self._assert_managed(user, plan)
        return _result(user, DeploymentStatus.ACTIVE, _("Honeyuser creado y habilitado."))

    def status(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        self._validate_record(record, plan)
        user = self._transport.get_user(
            plan.target, self._administrative_credential(plan.target), _identity(record, plan)
        )
        if user is None:
            return ConnectorResult(
                DeploymentStatus.DEGRADED,
                _("El honeyuser ya no existe en Active Directory."),
                list(record.external_resource_ids),
            )
        if user.description != plan.parameters["management_marker"]:
            return _result(user, DeploymentStatus.DEGRADED, _("El marcador de propiedad del honeyuser cambió."))
        if not _is_in_ou(user.distinguished_name, str(plan.parameters["ou_dn"])):
            return _result(user, DeploymentStatus.DEGRADED, _("El honeyuser fue movido fuera de la OU autorizada."))
        if not user.enabled:
            if record.status is DeploymentStatus.RETIRED:
                return _result(user, DeploymentStatus.RETIRED, _("Honeyuser deshabilitado y retirado."))
            return _result(user, DeploymentStatus.DEGRADED, _("El honeyuser está deshabilitado fuera de APATE."))
        return _result(user, DeploymentStatus.ACTIVE, _("Honeyuser presente y habilitado."))

    def rotate(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        self._validate_record(record, plan)
        secret_ref = str(plan.parameters["honeyuser_credential_ref"])
        password = self._password_factory()
        # Se persiste antes de tocar AD: si el proceso cae luego del cambio,
        # APATE conserva la única contraseña que puede haber quedado activa.
        self._credentials.save(
            secret_ref,
            {"username": str(plan.parameters["user_principal_name"]), "password": password},
        )
        user = self._transport.set_password_and_enable(
            plan.target,
            self._administrative_credential(plan.target),
            _identity(record, plan),
            password,
        )
        self._assert_managed(user, plan)
        return _result(user, DeploymentStatus.ACTIVE, _("Credencial del honeyuser rotada."))

    def retire(self, record: DeploymentRecord, plan: DeploymentPlan) -> ConnectorResult:
        self._validate_record(record, plan)
        user = self._transport.get_user(
            plan.target, self._administrative_credential(plan.target), _identity(record, plan)
        )
        if user is None:
            return ConnectorResult(DeploymentStatus.RETIRED, _("El honeyuser ya no existe."))
        self._assert_managed(user, plan)
        disabled = self._transport.disable_user(
            plan.target, self._administrative_credential(plan.target), user.sid
        )
        return _result(disabled, DeploymentStatus.RETIRED, _("Honeyuser deshabilitado y conservado para auditoría."))

    def _validated_parameters(self, target: DeploymentTarget, configuration: Mapping[str, Any]) -> dict[str, Any]:
        if target.connector_kind != self.kind:
            raise DeploymentValidationError(_("El destino no corresponde al conector de honeyusers de AD."))
        _plan_ttl_seconds(target)
        sam = str(configuration.get("sam_account_name", "")).strip()
        if not _SAM_RE.fullmatch(sam):
            raise DeploymentValidationError(
                _("sAMAccountName debe tener entre 1 y 20 caracteres alfanuméricos, punto, guion o guion bajo.")
            )
        display_name = str(configuration.get("display_name", "")).strip()
        ou_dn = str(configuration.get("ou_dn", "")).strip()
        upn_suffix = str(configuration.get("upn_suffix", "")).strip().lower()
        if not display_name or len(display_name) > 256:
            raise DeploymentValidationError(_("display_name es obligatorio y no puede superar 256 caracteres."))
        allowed_ous = [str(value).strip() for value in target.config.get("ou_allowlist", [])]
        if not ou_dn or ou_dn.casefold() not in {value.casefold() for value in allowed_ous}:
            raise DeploymentValidationError(_("La OU solicitada no está en la allowlist exacta del destino."))
        allowed_suffixes = [str(value).strip().lower() for value in target.config.get("allowed_upn_suffixes", [])]
        if not upn_suffix or upn_suffix not in allowed_suffixes:
            raise DeploymentValidationError(_("El sufijo UPN solicitado no está autorizado para el destino."))
        return {
            "sam_account_name": sam,
            "user_principal_name": f"{sam}@{upn_suffix}",
            "display_name": display_name,
            "given_name": str(configuration.get("given_name", "")).strip(),
            "surname": str(configuration.get("surname", "")).strip(),
            "ou_dn": ou_dn,
        }

    def _administrative_credential(self, target: DeploymentTarget) -> dict[str, str]:
        if not target.credential_ref:
            raise DeploymentValidationError(_("El destino de Active Directory requiere credential_ref."))
        credential = self._credentials.get(target.credential_ref)
        if not credential.get("username") or not credential.get("password"):
            raise DeploymentValidationError(_("La credencial administrativa requiere username y password."))
        return credential

    def _password_for_deploy(self, reference: str, username: str) -> str:
        if not self._credentials.exists(reference):
            self._credentials.save(reference, {"username": username, "password": self._password_factory()})
        return self._credentials.get(reference)["password"]

    @staticmethod
    def _validate_plan(plan: DeploymentPlan) -> None:
        required = {"sam_account_name", "user_principal_name", "ou_dn", "management_marker", "honeyuser_credential_ref"}
        if plan.connector_kind != _KIND or not required.issubset(plan.parameters):
            raise DeploymentValidationError(_("El plan de honeyuser está incompleto o pertenece a otro conector."))
        if len(plan.changes) != 1 or plan.changes[0].resource_name != plan.parameters["sam_account_name"]:
            raise DeploymentValidationError(_("El cambio declarado no coincide con el honeyuser planificado."))

    @classmethod
    def _validate_record(cls, record: DeploymentRecord, plan: DeploymentPlan) -> None:
        cls._validate_plan(plan)
        if record.plan_id != plan.id or record.target_id != plan.target_id or record.connector_kind != cls.kind:
            raise DeploymentValidationError(_("El registro no coincide con su plan de honeyuser."))

    @staticmethod
    def _assert_managed(user: ActiveDirectoryUser, plan: DeploymentPlan) -> None:
        if user.description != plan.parameters["management_marker"]:
            raise DeploymentExecutionError(_("Active Directory devolvió una cuenta sin el marcador de propiedad esperado."))
        if not _SID_RE.fullmatch(user.sid):
            raise DeploymentExecutionError(_("Active Directory devolvió un SID inválido para el honeyuser."))
        if user.sam_account_name.casefold() != str(plan.parameters["sam_account_name"]).casefold():
            raise DeploymentExecutionError(_("Active Directory devolvió una cuenta distinta de la planificada."))
        if not _is_in_ou(user.distinguished_name, str(plan.parameters["ou_dn"])):
            raise DeploymentExecutionError(_("Active Directory creó el honeyuser fuera de la OU autorizada."))


class HoneyuserEventMonitor:
    """Publica accesos del honeyuser al bus y deduplica por EventRecordID."""

    def __init__(
        self,
        *,
        connector: ActiveDirectoryHoneyuserConnector,
        checkpoint_repository: "HoneyuserCheckpointRepository",
    ) -> None:
        self._connector = connector
        self._checkpoints = checkpoint_repository

    def poll(self, record: DeploymentRecord, plan: DeploymentPlan, bus: EventBus) -> list[PluginEvent]:
        self._connector._validate_record(record, plan)
        after, generation = (
            self._checkpoints.get_state(record.id)
            if hasattr(self._checkpoints, "get_state")
            else (self._checkpoints.get(record.id), 0)
        )
        credential = self._connector._administrative_credential(plan.target)
        sid = _sid(record)
        events = self._connector._transport.logon_events(
            plan.target,
            credential,
            sam_account_name=str(plan.parameters["sam_account_name"]),
            sid=sid,
            after_record_id=after,
        )
        # El Security log puede limpiarse y reiniciar EventRecordID. El
        # transporte real vuelve a consultar desde cero cuando detecta ese
        # reinicio; aceptar IDs menores acá permite mover también el
        # checkpoint y evita que el monitor quede ciego para siempre.
        if events and max(item.record_id for item in events) < after:
            after = 0
            generation += 1
        published: list[PluginEvent] = []
        for observed in sorted(events, key=lambda item: item.record_id):
            if observed.record_id <= after:
                continue
            payload: dict[str, Any] = {
                "kind": (
                    "honeyuser_authentication_success"
                    if _authentication_succeeded(observed)
                    else "honeyuser_authentication_failure"
                ),
                "event_id": observed.event_id,
                "event_record_id": observed.record_id,
                "target_user": observed.target_user,
                "target_sid": observed.target_sid,
                "logon_type": observed.logon_type,
                "workstation": observed.workstation,
                "status": observed.status,
            }
            if observed.source_ip and observed.source_ip != "-":
                payload["source_ip"] = observed.source_ip
            if _authentication_succeeded(observed):
                payload["ttp_id"] = "T1078"
            event = PluginEvent(
                event_type=EventType.INTERACTION,
                plugin_id=record.plugin_id,
                surface="identity",
                operation_id=record.operation_id,
                resource_id=sid or None,
                payload=payload,
                timestamp=observed.timestamp,
                id=f"ad-security-{record.id}-{observed.record_id}"
                   + (f"-generation-{generation}" if generation else ""),
                provenance={"raw": payload, "external_id": str(observed.record_id),
                    "generation": f"{record.id}:{generation}", "origin_time": observed.timestamp.isoformat(),
                    "transformation": "ad-security-checkpoint-v1"},
            )
            bus.publish(event)
            published.append(event)
            if hasattr(self._checkpoints, "save_state"):
                self._checkpoints.save_state(record.id, observed.record_id, generation)
            else:
                self._checkpoints.save(record.id, observed.record_id)
        return published


class HoneyuserCheckpointRepository(Protocol):
    def get(self, record_id: str) -> int: ...

    def save(self, record_id: str, event_record_id: int) -> None: ...


def _management_marker(operation_id: str, plugin_id: str) -> str:
    return f"APATE:honeyuser;operation={operation_id};plugin={plugin_id}"


def _strong_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#%_-"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(char in group for char in value) for group in (string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#%_-")):
            return value


def _external_ids(user: ActiveDirectoryUser) -> list[str]:
    return [f"sid:{user.sid}", f"dn:{user.distinguished_name}"]


def _result(user: ActiveDirectoryUser, status: DeploymentStatus, detail: str) -> ConnectorResult:
    return ConnectorResult(status, detail, _external_ids(user))


def _sid(record: DeploymentRecord) -> str:
    for value in record.external_resource_ids:
        if value.startswith("sid:") and _SID_RE.fullmatch(value[4:]):
            return value[4:]
    return ""


def _identity(record: DeploymentRecord, plan: DeploymentPlan) -> str:
    return _sid(record) or str(plan.parameters["sam_account_name"])


def _is_in_ou(distinguished_name: str, ou_dn: str) -> bool:
    return distinguished_name.casefold().endswith("," + ou_dn.casefold())


def _authentication_succeeded(event: ActiveDirectoryLogonEvent) -> bool:
    if event.event_id not in _SUCCESSFUL_AUTHENTICATION_EVENTS:
        return False
    return not event.status or event.status.casefold() in {"0", "0x0", "success"}


def _plan_ttl_seconds(target: DeploymentTarget) -> int:
    try:
        value = int(target.config.get("plan_ttl_seconds", 900))
    except (TypeError, ValueError) as exc:
        raise DeploymentValidationError(_("plan_ttl_seconds debe ser un número entero.")) from exc
    if not 60 <= value <= 86400:
        raise DeploymentValidationError(_("plan_ttl_seconds debe estar entre 60 y 86400."))
    return value


class WinRMActiveDirectoryTransport:
    """Transporte real basado en ``pywinrm`` y el módulo ActiveDirectory."""

    def validate(self, target: DeploymentTarget, credential: Mapping[str, str], ou_dn: str) -> None:
        self._run(target, credential, """
Import-Module ActiveDirectory -ErrorAction Stop
$null = Get-ADDomain -ErrorAction Stop
$null = Get-ADOrganizationalUnit -Identity $p.ou_dn -ErrorAction Stop
$null = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4768,4769,4771,4776} -MaxEvents 1 -ErrorAction Stop
@{ok=$true} | ConvertTo-Json -Compress
""", {"ou_dn": ou_dn})

    def find_user(self, target, credential, sam_account_name):
        data = self._run(target, credential, _GET_USER_SCRIPT, {"identity": sam_account_name})
        return ActiveDirectoryUser.from_dict(data) if data else None

    def create_or_update_user(self, target, credential, parameters, password):
        payload = dict(parameters)
        payload["password"] = password
        return ActiveDirectoryUser.from_dict(self._run(target, credential, _CREATE_USER_SCRIPT, payload))

    def get_user(self, target, credential, identity):
        data = self._run(target, credential, _GET_USER_SCRIPT, {"identity": identity})
        return ActiveDirectoryUser.from_dict(data) if data else None

    def set_password_and_enable(self, target, credential, identity, password):
        return ActiveDirectoryUser.from_dict(
            self._run(target, credential, _ROTATE_USER_SCRIPT, {"identity": identity, "password": password})
        )

    def disable_user(self, target, credential, identity):
        return ActiveDirectoryUser.from_dict(
            self._run(target, credential, _DISABLE_USER_SCRIPT, {"identity": identity})
        )

    def logon_events(self, target, credential, *, sam_account_name, sid, after_record_id):
        data = self._run(
            target,
            credential,
            _LOGON_EVENTS_SCRIPT,
            {"sam_account_name": sam_account_name, "sid": sid, "after_record_id": after_record_id},
        )
        return [ActiveDirectoryLogonEvent.from_dict(item) for item in (data or [])]

    def _run(
        self,
        target: DeploymentTarget,
        credential: Mapping[str, str],
        body: str,
        payload: Mapping[str, Any],
    ) -> Any:
        endpoint = _winrm_endpoint(target)
        transport_name = str(target.config.get("transport", "ntlm")).lower()
        if transport_name not in {"ntlm", "kerberos", "credssp"}:
            raise DeploymentValidationError(_("El transporte WinRM solicitado no está autorizado."))
        certificate_validation = str(target.config.get("server_cert_validation", "validate")).lower()
        if certificate_validation not in {"validate", "ignore"}:
            raise DeploymentValidationError(_("server_cert_validation debe ser 'validate' o 'ignore'."))
        encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        script = (
            "$ErrorActionPreference='Stop'\n"
            f"$payloadJson=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'))\n"
            "$p=$payloadJson | ConvertFrom-Json\n"
            + body
        )
        try:
            import winrm

            session = winrm.Session(
                endpoint,
                auth=(credential["username"], credential["password"]),
                transport=transport_name,
                server_cert_validation=certificate_validation,
                message_encryption="always" if endpoint.lower().startswith("http://") else "auto",
            )
            response = session.run_ps(script)
        except Exception as exc:
            raise DeploymentExecutionError(
                _("No se pudo conectar con Active Directory mediante WinRM: %(detail)s", detail=exc)
            ) from exc
        stdout = bytes(response.std_out or b"").decode("utf-8", errors="replace").strip()
        stderr = bytes(response.std_err or b"").decode("utf-8", errors="replace").replace(encoded, "[REDACTED]").strip()
        if int(response.status_code) != 0:
            raise DeploymentExecutionError(
                _("PowerShell remoto falló (código %(code)s): %(detail)s", code=response.status_code, detail=stderr[:1000])
            )
        if not stdout:
            return None
        try:
            return json.loads(stdout.splitlines()[-1])
        except json.JSONDecodeError as exc:
            raise DeploymentExecutionError(_("PowerShell remoto devolvió una respuesta no válida.")) from exc


def _winrm_endpoint(target: DeploymentTarget) -> str:
    address = target.address.strip().rstrip("/")
    if "://" not in address:
        address = f"https://{address}:5986/wsman"
    elif not address.endswith("/wsman"):
        address += "/wsman"
    if address.lower().startswith("http://") and not bool(target.config.get("allow_unencrypted", False)):
        raise DeploymentValidationError(
            _("WinRM por HTTP está bloqueado; usá HTTPS o autorizá explícitamente allow_unencrypted.")
        )
    return address


_USER_TO_JSON = r"""
@{
  sid=$u.SID.Value
  distinguished_name=$u.DistinguishedName
  sam_account_name=$u.SamAccountName
  user_principal_name=$u.UserPrincipalName
  description=$u.Description
  enabled=[bool]$u.Enabled
} | ConvertTo-Json -Compress
"""

_GET_USER_SCRIPT = r"""
Import-Module ActiveDirectory -ErrorAction Stop
$u = Get-ADUser -Identity $p.identity -Properties Description,Enabled,UserPrincipalName -ErrorAction SilentlyContinue
if ($null -eq $u) { 'null'; return }
""" + _USER_TO_JSON

_CREATE_USER_SCRIPT = r"""
Import-Module ActiveDirectory -ErrorAction Stop
$u = Get-ADUser -Identity $p.sam_account_name -Properties Description,Enabled,UserPrincipalName -ErrorAction SilentlyContinue
if ($null -ne $u -and $u.Description -ne $p.management_marker) { throw 'Existing account is not managed by this APATE operation.' }
$secure = ConvertTo-SecureString $p.password -AsPlainText -Force
if ($null -eq $u) {
  $args = @{
    Name=$p.display_name; DisplayName=$p.display_name; SamAccountName=$p.sam_account_name
    UserPrincipalName=$p.user_principal_name; Path=$p.ou_dn; Description=$p.management_marker
    AccountPassword=$secure; Enabled=$true; ChangePasswordAtLogon=$false
  }
  if ($p.given_name) { $args.GivenName=$p.given_name }
  if ($p.surname) { $args.Surname=$p.surname }
  $u = New-ADUser @args -PassThru
} else {
  Set-ADAccountPassword -Identity $u -Reset -NewPassword $secure
  Enable-ADAccount -Identity $u
}
$u = Get-ADUser -Identity $p.sam_account_name -Properties Description,Enabled,UserPrincipalName
""" + _USER_TO_JSON

_ROTATE_USER_SCRIPT = r"""
Import-Module ActiveDirectory -ErrorAction Stop
$secure = ConvertTo-SecureString $p.password -AsPlainText -Force
Set-ADAccountPassword -Identity $p.identity -Reset -NewPassword $secure
Enable-ADAccount -Identity $p.identity
$u = Get-ADUser -Identity $p.identity -Properties Description,Enabled,UserPrincipalName
""" + _USER_TO_JSON

_DISABLE_USER_SCRIPT = r"""
Import-Module ActiveDirectory -ErrorAction Stop
Disable-ADAccount -Identity $p.identity
$u = Get-ADUser -Identity $p.identity -Properties Description,Enabled,UserPrincipalName
""" + _USER_TO_JSON

_LOGON_EVENTS_SCRIPT = r"""
$samEsc = [Security.SecurityElement]::Escape([string]$p.sam_account_name)
$sidEsc = [Security.SecurityElement]::Escape([string]$p.sid)
$after = [long]$p.after_record_id
$latest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
if ($null -ne $latest -and [long]$latest.RecordId -lt $after) { $after = 0 }
$identityClause = "Data[@Name='TargetUserName']='$samEsc'"
if ($sidEsc) { $identityClause = "($identityClause or Data[@Name='TargetUserSid']='$sidEsc')" }
$xpath = "*[System[(EventID=4624 or EventID=4625 or EventID=4768 or EventID=4769 or EventID=4771 or EventID=4776) and EventRecordID > $after] and EventData[$identityClause]]"
$events = Get-WinEvent -LogName Security -FilterXPath $xpath -ErrorAction Stop |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) { $fields[[string]$item.Name] = [string]$item.'#text' }
    if ($fields.TargetUserName -ieq $p.sam_account_name -or ($p.sid -and $fields.TargetUserSid -eq $p.sid)) {
      @{
        record_id=[long]$_.RecordId; event_id=[int]$_.Id; timestamp=$_.TimeCreated.ToUniversalTime().ToString('o')
        target_user=$fields.TargetUserName; target_sid=$fields.TargetUserSid; source_ip=$fields.IpAddress
        workstation=$fields.WorkstationName; logon_type=$fields.LogonType
        status=$(if ($fields.Status) { $fields.Status } elseif ($fields.ResultCode) { $fields.ResultCode } else { '' })
      }
    }
  }
ConvertTo-Json -InputObject @($events) -Compress
"""
