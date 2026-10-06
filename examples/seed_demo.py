"""Seed idempotente de operaciones de ejemplo para demo (BlackHat Arsenal).

Reemplaza `examples/quickstart.py` (M1, `apate.core` puro: una sola
Operation sin escenarios ricos, sin plugins reales, sin ningun dato de
los catalogos de MITRE ATT&CK/Engage que existen desde M12) -- ese
script quedo desactualizado frente a M10-M14 y, corrido varias veces,
es la fuente real del desorden que motivo este reemplazo (cada corrida
crea una Operation con id nuevo, sin ningun chequeo de duplicados).

Ejecutar con:

    python examples/seed_demo.py

Por defecto siembra el contenido histórico en español. Para una instancia
preparada en inglés, usar ``APATE_LOCALE=en python examples/seed_demo.py``;
el idioma se decide una sola vez antes de persistir los datos, nunca al
renderizarlos después.

Crea 3 operaciones de ejemplo, completas en los 5 pasos de la
metodologia (perfil de adversario con TTPs reales de `apate.attack`,
RoE, objetivos estrategicos/roles, al menos un escenario con
`related_ttps`, narrativa con `psychological_impact`), cada una con al
menos un plugin vinculado (`dolost` y/o `buda` segun la operacion) via
el flujo fusionado real de "Vincular plugin" (`add_plugin_binding()`,
corregido para configurar el decoy/la narrativa en la misma request).

**Fuente de los datos, desde el catálogo de plantillas de operación
(no un dataset propio de este script):** las 3 operaciones de ejemplo
de abajo eran justamente el problema que motivó el catálogo de
plantillas de la UI -- realistas y bien construidas, pero invisibles
fuera de este script de desarrollo. `apate/data/operation_templates.json`
+ `apate.web._operation_templates` (`list_templates()`/
`resolve_operation_fields()`) son ahora la ÚNICA fuente: este script
consume la plantilla completa (operación + escenario + plugins +
transiciones) para crear datos de demo reales, mientras que el
catálogo de la UI (`GET /operations/templates`) consume solo la parte
de operación para precargar el wizard -- ver el docstring de
`apate.web._operation_templates` para el detalle completo de por qué
se unificó en vez de mantener dos listas paralelas.

**Por que via `app.test_client()` y no construyendo `Operation`/
`PluginBinding` a mano:** este seed pasa por los mismos formularios
POST que usaria un operador real (`/operations/new`, `/operations/<id>
/scenarios`, `/operations/<id>/plugins`) en vez de reimplementar esa
logica -- si el formulario web cambia de forma (un campo nuevo
requerido, una validacion nueva), este script la hereda automaticamente
en vez de quedar desincronizado en silencio. La unica excepcion es la
transicion de estado final, tambien via `POST .../transition` por el
mismo motivo.

**Contexto de aplicacion:** crear la narrativa de BUDA
(`_create_buda_narrative_from_operation()`, llamada dentro de
`add_plugin_binding()`) necesita la sesion real de SQLAlchemy de BUDA
activa -- `mount_buda()`, que `create_app()` prepara solo si
`APATE_MOUNT_EXTERNAL_TOOLS` esta en `True` (el default). A diferencia
de `quickstart.py`, que nunca tocaba BUDA, este seed corre dentro de
`with app.app_context():` sobre una app real de `create_app()`, no
como script standalone de `apate.core` puro.

**Idempotencia:** antes de crear cada operacion de ejemplo se chequea
si ya existe una con el mismo `name` exacto en
`OPERATION_REPOSITORY.list()` -- si existe, se saltea entera (sin
reintentar escenario/plugins ni telemetría). La telemetría mockeada se
inyecta para las operaciones del catálogo que aún no tengan esta revisión
del fixture, mediante `TELEMETRY_COLLECTOR.handle_event(PluginEvent(...))`:
conserva el mismo camino de normalización que un plugin real y evita
duplicar Events/IoCs al volver a ejecutar el script. Cada escenario observa solo una parte de
sus `related_ttps`, para que el heatmap y esperado vs. observado muestren
coincidencias y pendientes reales en la demo. No hace falta un marcador aparte (ID
fijo, flag en `config`, etc.): los tres nombres del dataset de
plantillas son estables y unicos a proposito, y `Operation.name` ya es
el dato que un operador ve primero en la lista -- reusar el mismo
criterio que ya usaria una persona para notar "esto ya existe" es mas
simple que inventar un mecanismo de marcado nuevo.

**Incidentes y TLP mockeados:** despues de persistir la telemetria de
una operacion nueva, el seed vuelve a pasar por los POST reales de
Telemetria para crear el incidente APT28 y clasificar tres IoCs. No crea
`Incident` ni `TlpClassification` a mano: usa los IDs reales devueltos
por `TELEMETRY_COLLECTOR.list_events()` e `ioc_subject_key()` para que
la demo cubra el mismo contrato que la consola. Igual que los eventos,
estas anotaciones se limitan a los IDs cuya telemetría se creó o actualizó
en la corrida actual. Así una operación de plantilla preexistente recibe
el conjunto completo de datos de demo sin repetir anotaciones en reintentos.

**Gating Criteria de ejemplo:** el seed agrega mediante el POST real de
RoE una condicion event-driven a APT28, sin publicar el evento que la
satisface. Espera la TTP `T1021.004`, que esa operacion declara como
parte de su escenario pero la telemetria de demo deja pendiente; asi la
operacion queda `ACTIVE` con un cierre automatico explicable, en vez de
cerrarse artificialmente durante la siembra. Tambien se limita a los IDs
actualizados por el fixture, para no agregar condiciones duplicadas ni
alterar una operacion que un operador ya estuviera siguiendo."""

from __future__ import annotations


import hashlib
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from apate.plugins import EventBus, EventType, MockHoneypotPlugin, PluginEvent
from apate.rules import Action, ActionKind, Condition, Rule, RuleEngine
from apate.telemetry.classifications import ioc_subject_key
from apate.telemetry.models import TelemetryRecord
from apate.web import create_app
from apate.web._operation_templates import list_templates, resolve_operation_fields
from apate.i18n import DEFAULT_LOCALE, SUPPORTED_LOCALES
from BUDA.app import db as buda_db
from BUDA.models import Activity as BudaActivity
from BUDA.models import Narrative as BudaNarrative
from BUDA.models import UserProfile as BudaUserProfile


# Eventos de demo asociados a bindings que las plantillas ya declaran.
# Cada escenario conserva al menos una related_ttp sin observar para no
# presentar una cobertura artificialmente completa en el heatmap.
_DEMO_EVENTS_BY_PLUGIN_ID = {
    "dolost-apt28-finance": (
        (EventType.INTERACTION, {"source_ip": "198.51.100.23", "service": "ssh", "ttp_id": "T1046", "detail": "Reconocimiento de puertos contra el gateway SSH señuelo."}),
        (EventType.TTP_OBSERVED, {"source_ip": "198.51.100.23", "attempts": 7, "ttp_id": "T1110.001", "detail": "Ráfaga de fuerza bruta SSH detectada."}),
        (EventType.TTP_OBSERVED, {"source_ip": "198.51.100.23", "credential": "svc-finanzas@corp.example", "ttp_id": "T1021", "detail": "Intento de movimiento lateral con credencial financiera."}),
        (EventType.INTERACTION, {"source_ip": "198.51.100.23", "hash": "", "ttp_id": "T1059", "detail": "Comando remoto observado en el servidor de staging."}),
        (EventType.TTP_OBSERVED, {"source_ip": "198.51.100.23", "credential": "backup-finanzas@corp.example", "ttp_id": "T1003", "detail": "Acceso a credenciales de respaldo del segmento financiero."}),
        (EventType.TTP_OBSERVED, {"source_ip": "198.51.100.23", "ttp_id": "T1552", "detail": "Búsqueda de secretos fuera del plan declarado."}),
    ),
    "buda-fin7-hr": (
        (EventType.INTERACTION, {"identity": "soporte-remoto", "credential": "m.lopez@rrhh.example", "ttp_id": "T1110.001", "detail": "Intento repetido contra la cuenta de soporte remoto."}),
        (EventType.TTP_OBSERVED, {"identity": "soporte-remoto", "url": "https://portal-rh.example/remote", "ttp_id": "T1190", "detail": "Acceso al portal de RRHH desde una sesión no habitual."}),
        (EventType.TTP_OBSERVED, {"identity": "soporte-remoto", "credential": "soporte-nivel2@rrhh.example", "ttp_id": "T1078", "detail": "Uso de una cuenta válida fuera del patrón de soporte."}),
        (EventType.INTERACTION, {"identity": "soporte-remoto", "hash": "", "ttp_id": "T1210", "detail": "Intento de servicio remoto hacia el entorno de RRHH."}),
        (EventType.TTP_OBSERVED, {"identity": "soporte-remoto", "ttp_id": "T1110", "detail": "Patrón de fuerza bruta no previsto para esta operación."}),
    ),
    "dolost-lazarus-exfil": (
        (EventType.INTERACTION, {"source_ip": "203.0.113.77", "service": "ftp", "ttp_id": "T1190", "detail": "Explotación de servicio expuesto en el backup señuelo."}),
        (EventType.TTP_OBSERVED, {"source_ip": "203.0.113.77", "hash": "", "ttp_id": "T1059", "detail": "Ejecución de comandos durante el cierre contable."}),
    ),
    "buda-lazarus-exfil": (
        (EventType.TTP_OBSERVED, {"identity": "analista-finanzas", "domain": "cdn-sync.example", "ttp_id": "T1105", "detail": "Transferencia de herramienta hacia el perfil de cierre."}),
        (EventType.INTERACTION, {"identity": "analista-finanzas", "domain": "cdn-sync.example", "ttp_id": "T1071", "detail": "Canal web de control observado en la narrativa financiera."}),
    ),
    "canarytoken-lazarus-exfil": (
        (EventType.TTP_OBSERVED, {"url": "https://transfer-cierre.example/backup", "domain": "transfer-cierre.example", "ttp_id": "T1041", "detail": "Apertura de la miga de transferencia del cierre."}),
    ),
    "opencanary-lazarus-exfil": (
        (EventType.INTERACTION, {"source_ip": "203.0.113.77", "service": "ssh", "ttp_id": "T1046", "detail": "Enumeración de servicios del host de transferencia."}),
    ),
}

# Los eventos conservan sus identificadores e IoCs técnicos. Solo el detalle
# que termina persistido y visible en la demo cambia con el idioma elegido.
_DEMO_EVENT_DETAILS_EN = {
    "dolost-apt28-finance": (
        "Port scan reconnaissance against the SSH decoy gateway.",
        "SSH brute-force burst detected.",
        "Lateral-movement attempt using a financial credential.",
        "Remote command observed on the staging server.",
        "Access to backup credentials in the financial segment.",
        "Secret discovery outside the declared plan.",
    ),
    "buda-fin7-hr": (
        "Repeated attempt against the remote-support account.",
        "Access to the HR portal from an unusual session.",
        "Use of a valid account outside the support pattern.",
        "Remote-service attempt toward the HR environment.",
        "Brute-force pattern not expected for this operation.",
    ),
    "dolost-lazarus-exfil": (
        "Exploitation of an exposed service on the backup decoy.",
        "Command execution during the accounting close.",
    ),
    "buda-lazarus-exfil": (
        "Tool transfer to the quarter-close profile.",
        "Web control channel observed in the financial narrative.",
    ),
    "canarytoken-lazarus-exfil": (
        "Opening of the quarter-close transfer breadcrumb.",
    ),
    "opencanary-lazarus-exfil": (
        "Service enumeration on the transfer host.",
    ),
}

_SEED_TEXT = {
    "es": {
        "identity_context": "Sesión de identidad %(identity)s-%(context_id)04d.",
        "origin_context": "Origen correlacionado %(origin)s.",
        "domain_context": "Canal asociado %(domain)s.",
        "reference_context": "Referencia de investigación %(context_id)04d.",
        "rule_name": "Fixture de impacto: respuesta a TTP observada",
        "incident_name": "Escaneo y fuerza bruta desde %(origin)s",
        "incident_notes": "Las %(count)s observaciones agrupadas comparten el origen %(origin)s y describen el reconocimiento seguido de intentos SSH.",
        "operator": "Seed de demostración",
        "measured_outcome": "El señuelo de respaldo concentró reconocimiento y transferencia simulada durante el cierre contable.",
    },
    "en": {
        "identity_context": "Identity session %(identity)s-%(context_id)04d.",
        "origin_context": "Correlated origin %(origin)s.",
        "domain_context": "Associated channel %(domain)s.",
        "reference_context": "Investigation reference %(context_id)04d.",
        "rule_name": "Impact fixture: response to observed TTP",
        "incident_name": "Scanning and brute force from %(origin)s",
        "incident_notes": "The %(count)s grouped observations share origin %(origin)s and describe reconnaissance followed by SSH attempts.",
        "operator": "Demo seed",
        "measured_outcome": "The backup decoy concentrated reconnaissance and simulated transfer during the accounting close.",
    },
}

_IMPACT_DEMO_MARKER = "impact-v3"
# Ráfagas por operación: (antigüedad del inicio, cantidad). Las dos historias
# activas comparten el comienzo de su ráfaga reciente para que el flujo no
# quede monopolizado por una sola; `_burst_timestamps()` decide después los
# intervalos irregulares y deterministas. Al menos una operación cae tanto en
# la última hora como en la anterior, porque el centro de impacto compara esas
# ventanas y omite el delta si alguna está vacía.
_DEMO_STORIES = (
    {
        "anchor": "dolost-apt28-finance",
        "plugins": ("dolost-apt28-finance",),
        "bursts": ((timedelta(days=20), 90), (timedelta(days=17), 130), (timedelta(days=13), 50), (timedelta(days=10), 140), (timedelta(days=6), 180), (timedelta(days=3), 70), (timedelta(hours=2, minutes=30), 100), (timedelta(minutes=14), 140)),
    },
    {
        "anchor": "buda-fin7-hr",
        "plugins": ("buda-fin7-hr",),
        "bursts": ((timedelta(days=18), 80), (timedelta(days=15), 80), (timedelta(days=11), 140), (timedelta(days=7), 40), (timedelta(days=3), 160), (timedelta(hours=1, minutes=20), 90), (timedelta(minutes=14), 210)),
    },
    {
        "anchor": "dolost-lazarus-exfil",
        "plugins": ("dolost-lazarus-exfil", "buda-lazarus-exfil", "canarytoken-lazarus-exfil", "opencanary-lazarus-exfil"),
        "bursts": ((timedelta(days=19), 100), (timedelta(days=18), 110), (timedelta(days=16), 80), (timedelta(days=14), 210), (timedelta(days=11), 200)),
    },
)


# Clasificaciones TLP de ejemplo sobre IoCs que la telemetria anterior
# normaliza realmente. La IP de escaneo puede compartirse con pares de
# confianza (GREEN); la credencial identifica a una persona (AMBER); y el
# dominio ligado al señuelo financiero de Lazarus se reserva para el equipo
# que sigue esa investigacion activa (RED).
_DEMO_TLP_BY_PLUGIN_ID = {
    "dolost-apt28-finance": ("ip", "198.51.100.23", "green"),
    "buda-fin7-hr": ("credential", "m.lopez@rrhh.example", "amber"),
    "buda-lazarus-exfil": ("domain", "cdn-sync.example", "red"),
}


# Inventario y cobertura que materializan los activos objetivo ya declarados
# por las plantillas. Los identificadores coinciden a propósito con
# `target_assets`: así el mapa no depende de aproximar texto libre.
_DEMO_ASSETS = (
    {"identifier": "Segmento de red financiero", "name": "Segmento de red financiero", "asset_type": "service", "criticality": "critical", "technical_identifier": "172.16.50.0/24"},
    {"identifier": "Servidores de archivos internos", "name": "Servidores de archivos internos", "asset_type": "server", "criticality": "high", "technical_identifier": "files-int.demo.example"},
    {"identifier": "Buzones de correo de RRHH", "name": "Buzones de correo de RRHH", "asset_type": "account", "criticality": "high", "technical_identifier": "mail-rrhh.demo.example"},
    {"identifier": "Credenciales de acceso remoto", "name": "Credenciales de acceso remoto", "asset_type": "account", "criticality": "critical", "technical_identifier": "remote-rrhh.demo.example"},
    {"identifier": "Repositorios de datos financieros", "name": "Repositorios de datos financieros", "asset_type": "data", "criticality": "critical", "technical_identifier": "fin-data-demo.example"},
    {"identifier": "Infraestructura de respaldo", "name": "Infraestructura de respaldo", "asset_type": "server", "criticality": "critical", "technical_identifier": "backup-demo.example"},
)

_DEMO_ASSETS_EN = (
    {"identifier": "Financial network segment", "name": "Financial network segment", "asset_type": "service", "criticality": "critical", "technical_identifier": "172.16.50.0/24"},
    {"identifier": "Internal file servers", "name": "Internal file servers", "asset_type": "server", "criticality": "high", "technical_identifier": "files-int.demo.example"},
    {"identifier": "HR mailboxes", "name": "HR mailboxes", "asset_type": "account", "criticality": "high", "technical_identifier": "mail-rrhh.demo.example"},
    {"identifier": "Remote access credentials", "name": "Remote access credentials", "asset_type": "account", "criticality": "critical", "technical_identifier": "remote-rrhh.demo.example"},
    {"identifier": "Financial data repositories", "name": "Financial data repositories", "asset_type": "data", "criticality": "critical", "technical_identifier": "fin-data-demo.example"},
    {"identifier": "Backup infrastructure", "name": "Backup infrastructure", "asset_type": "server", "criticality": "critical", "technical_identifier": "backup-demo.example"},
)

_DEMO_ASSET_COVERAGE = {
    "dolost-apt28-finance": ["Segmento de red financiero"],
    "buda-fin7-hr": ["Credenciales de acceso remoto"],
    "dolost-lazarus-exfil": ["Infraestructura de respaldo"],
    "buda-lazarus-exfil": ["Repositorios de datos financieros"],
}

_DEMO_ASSET_COVERAGE_EN = {
    "dolost-apt28-finance": ["Financial network segment"],
    "buda-fin7-hr": ["Remote access credentials"],
    "dolost-lazarus-exfil": ["Backup infrastructure"],
    "buda-lazarus-exfil": ["Financial data repositories"],
}

_DEMO_BUDA_PROFILES = {
    "buda-fin7-hr": {
        "name": "Marina López — soporte remoto RRHH",
        "role": "Analista de soporte remoto",
        "behavior_pattern": "Atiende solicitudes de RRHH en horario laboral y revisa el portal de soporte cada mañana.",
        "winrm_server": "winrm-demo-rrhh.example.invalid",
        "winrm_username": "DEMO\\marina.lopez",
        "winrm_password": "DEMO_ONLY_NOT_A_REAL_SECRET",
        "activity_type": "Revisión de tickets de soporte",
        "activity_details": "Consulta matinal de solicitudes de acceso remoto del equipo de RRHH.",
    },
    "buda-lazarus-exfil": {
        "name": "Camila Rojas — cierre contable",
        "role": "Analista de finanzas",
        "behavior_pattern": "Revisa respaldos financieros y conciliaciones durante el cierre de trimestre.",
        "winrm_server": "winrm-demo-finanzas.example.invalid",
        "winrm_username": "DEMO\\camila.rojas",
        "winrm_password": "DEMO_ONLY_NOT_A_REAL_SECRET",
        "activity_type": "Revisión de respaldos financieros",
        "activity_details": "Validación de respaldos antes del cierre contable trimestral.",
    },
}

_DEMO_BUDA_PROFILES_EN = {
    "buda-fin7-hr": {
        "name": "Marina López — HR remote support",
        "role": "Remote support analyst",
        "behavior_pattern": "Handles HR requests during working hours and reviews the support portal every morning.",
        "winrm_server": "winrm-demo-rrhh.example.invalid",
        "winrm_username": "DEMO\\marina.lopez",
        "winrm_password": "DEMO_ONLY_NOT_A_REAL_SECRET",
        "activity_type": "Review support tickets",
        "activity_details": "Morning review of the HR team's remote-access requests.",
    },
    "buda-lazarus-exfil": {
        "name": "Camila Rojas — accounting close",
        "role": "Financial analyst",
        "behavior_pattern": "Reviews financial backups and reconciliations during the quarter close.",
        "winrm_server": "winrm-demo-finanzas.example.invalid",
        "winrm_username": "DEMO\\camila.rojas",
        "winrm_password": "DEMO_ONLY_NOT_A_REAL_SECRET",
        "activity_type": "Review financial backups",
        "activity_details": "Validate backups before the quarterly accounting close.",
    },
}

_DEMO_SECOND_SCENARIO = {
    "description": "Validar movimiento lateral posterior al gateway SSH financiero",
    "related_ttps": "T1021.004,T1078",
    "deception_level": "complete",
}

_DEMO_SECOND_SCENARIO_EN = {
    "description": "Validate lateral movement after the financial SSH gateway",
    "related_ttps": "T1021.004,T1078",
    "deception_level": "complete",
}


def _seed_text(locale: str, key: str, **variables: object) -> str:
    """Texto humano persistido por el fixture en el idioma de la siembra."""

    return _SEED_TEXT[locale][key] % variables


def _seed_locale(locale: str) -> str:
    """Valida el locale explícito del seed sin depender de una request."""

    if locale not in SUPPORTED_LOCALES:
        raise ValueError(f"Idioma de seed no soportado: {locale!r}")
    return locale


def _event_details(locale: str, plugin_id: str) -> tuple[str, ...]:
    if locale == DEFAULT_LOCALE:
        return tuple(event[1]["detail"] for event in _DEMO_EVENTS_BY_PLUGIN_ID[plugin_id])
    return _DEMO_EVENT_DETAILS_EN[plugin_id]


def _demo_assets(locale: str):
    return _DEMO_ASSETS if locale == DEFAULT_LOCALE else _DEMO_ASSETS_EN


def _demo_asset_coverage(locale: str):
    return _DEMO_ASSET_COVERAGE if locale == DEFAULT_LOCALE else _DEMO_ASSET_COVERAGE_EN


def _demo_buda_profiles(locale: str):
    return _DEMO_BUDA_PROFILES if locale == DEFAULT_LOCALE else _DEMO_BUDA_PROFILES_EN


def _demo_second_scenario(locale: str):
    return _DEMO_SECOND_SCENARIO if locale == DEFAULT_LOCALE else _DEMO_SECOND_SCENARIO_EN


def _create_example_operation(client, spec: dict[str, Any]) -> str:
    response = client.post("/operations/new", data=resolve_operation_fields(spec), follow_redirects=False)
    assert response.status_code == 302, f"No se pudo crear la operacion: {response.status_code}"
    operation_id = response.headers["Location"].rsplit("/", 1)[-1]

    scenario_response = client.post(
        f"/operations/{operation_id}/scenarios", data=spec["scenario"], follow_redirects=False
    )
    assert scenario_response.status_code == 302, f"No se pudo crear el escenario: {scenario_response.status_code}"

    repo = client.application.config["OPERATION_REPOSITORY"]
    scenario_id = repo.get(operation_id).scenarios[-1].id

    for plugin in spec["plugins"]:
        data = {key: value for key, value in plugin.items() if key not in ("kind",)}
        data["plugin_kind"] = plugin["kind"]
        data["scenario_id"] = scenario_id
        plugin_response = client.post(f"/operations/{operation_id}/plugins", data=data, follow_redirects=False)
        assert plugin_response.status_code == 302, (
            f"No se pudo vincular el plugin '{plugin['plugin_id']}': {plugin_response.status_code}"
        )
        _configure_example_plugin(client, operation_id, plugin)

    for to in spec["transitions"]:
        transition_response = client.post(
            f"/operations/{operation_id}/transition", data={"to": to}, follow_redirects=False
        )
        assert transition_response.status_code == 302, f"No se pudo transicionar a '{to}': {transition_response.status_code}"

    return operation_id


def _configure_example_plugin(client, operation_id: str, plugin: dict[str, Any]) -> None:
    """Prepara Canarytoken/OpenCanary sin llamar a sus despliegues reales."""

    plugin_id = plugin["plugin_id"]
    if plugin["kind"] == "canarytoken":
        data = {
            "base_url": plugin["base_url"],
            "token_type": plugin["token_type"],
            "memo": plugin["memo"],
            "email": plugin["email"],
            "ttp_id": plugin.get("ttp_id", ""),
        }
        response = client.post(
            f"/operations/{operation_id}/plugins/{plugin_id}/canarytoken/configure",
            data=data,
            follow_redirects=False,
        )
    elif plugin["kind"] == "opencanary":
        data = {
            "services": plugin["services"],
            "network_mode": plugin.get("network_mode", "bridge"),
            "ttp_id": plugin.get("ttp_id", ""),
        }
        response = client.post(
            f"/operations/{operation_id}/plugins/{plugin_id}/opencanary/configure",
            data=data,
            follow_redirects=False,
        )
    else:
        return
    assert response.status_code == 302, f"No se pudo configurar el plugin '{plugin_id}': {response.status_code}"


def _stable_number(*parts: object) -> int:
    """Devuelve un entero reproducible sin introducir aleatoriedad global."""

    material = "|".join(str(part) for part in parts)
    return int.from_bytes(hashlib.sha256(material.encode()).digest()[:8], "big")


def _payload_for_demo_occurrence(payload: dict[str, Any], occurrence: int, plugin_id: str, locale: str) -> dict[str, Any]:
    """Varia IoCs y contexto visible manteniendo una historia trazable."""

    result = {**payload, "demo_seed": _IMPACT_DEMO_MARKER}
    if result.get("source_ip") == "198.51.100.23":
        # 179, no 180: la plantilla se elige con `occurrence % 6` y 6 divide a
        # 180, asi que con 180 cada IP recibiria *siempre* la misma plantilla y
        # por lo tanto una sola TTP para siempre -- un origen que durante veinte
        # dias solo hace una cosa no se parece a un adversario real, y ademas
        # deja sin sentido cualquier agrupacion por origen. 179 es coprimo con
        # 6, asi que cada origen recorre las seis observaciones.
        result["source_ip"] = f"198.51.100.{23 + occurrence % 179}"
    elif result.get("source_ip") == "203.0.113.77":
        result["source_ip"] = f"203.0.113.{77 + occurrence % 170}"
    if result.get("credential") and occurrence:
        local, domain = result["credential"].split("@", 1)
        result["credential"] = f"{local}-{occurrence % 90}@{domain}"
    if result.get("domain") and occurrence >= 4:
        result["domain"] = f"{occurrence % 90}.{result['domain']}"
    if "hash" in result:
        result["hash"] = hashlib.sha256(f"{result.get('ttp_id', '')}:{occurrence}".encode()).hexdigest()
    context_id = _stable_number(plugin_id, occurrence, result["detail"]) % 10_000
    if result.get("identity"):
        context = _seed_text(locale, "identity_context", identity=result["identity"], context_id=context_id)
    elif result.get("source_ip"):
        context = _seed_text(locale, "origin_context", origin=result["source_ip"])
    elif result.get("domain"):
        context = _seed_text(locale, "domain_context", domain=result["domain"])
    else:
        context = _seed_text(locale, "reference_context", context_id=context_id)
    result["detail"] = f"{result['detail']} {context}"
    return result


def _story_for_operation(plugin_ids: set[str]) -> dict[str, Any]:
    """Resuelve la historia por un binding real, no por el nombre visible."""

    return next(story for story in _DEMO_STORIES if story["anchor"] in plugin_ids)


def _burst_timestamps(reference_time: datetime, story: dict[str, Any], burst_index: int, offset: timedelta, count: int):
    """Genera la cadencia irregular y repetible de una ráfaga de demo."""

    elapsed_seconds = _stable_number(story["anchor"], burst_index, "inicio") % 19
    for index in range(count):
        yield reference_time - offset - timedelta(seconds=elapsed_seconds)
        elapsed_seconds += 4 + _stable_number(story["anchor"], burst_index, index, "intervalo") % 13
        if index and index % 37 == 0:
            elapsed_seconds += 30 + _stable_number(story["anchor"], burst_index, index, "pausa") % 61


def _seed_demo_rule_firing(app, operation, event: PluginEvent, locale: str) -> None:
    """Registra una respuesta de regla por el camino real y sin I/O externo."""

    bus = EventBus()
    plugin = MockHoneypotPlugin(
        plugin_id=event.plugin_id,
        surface=event.surface,
        operation_id=operation.id,
        bus=bus,
    )
    RuleEngine(
        operation=operation,
        plugins={plugin.plugin_id: plugin},
        bus=bus,
        rules=[
            Rule(
                name=_seed_text(locale, "rule_name"),
                when=Condition(
                    event_type=EventType.TTP_OBSERVED,
                    plugin_id=event.plugin_id,
                    payload={"demo_seed": _IMPACT_DEMO_MARKER},
                ),
                then=[Action(kind=ActionKind.DEPLOY, plugin_id=event.plugin_id)],
            )
        ],
        decision_repository=app.config["RULE_DECISION_REPOSITORY"],
    )
    bus.publish(event)


def _seed_demo_telemetry(
    app, operation_ids: list[str], *, locale: str, reference_time: datetime | None = None
) -> list[str]:
    """Inyecta ráfagas de dos a tres semanas por el colector real."""

    collector = app.config["TELEMETRY_COLLECTOR"]
    repo = app.config["OPERATION_REPOSITORY"]
    seeded_ids = []
    now = reference_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)
    for operation_id in operation_ids:
        operation = repo.get(operation_id)
        if any(event.payload.get("demo_seed") == _IMPACT_DEMO_MARKER for event in collector.list_events(operation_id)):
            continue
        bindings = {binding.plugin_id: binding for binding in operation.plugins}
        story = _story_for_operation(set(bindings))
        rule_recorded = False
        events_to_persist = []
        occurrence = 0
        for burst_index, (offset, count) in enumerate(story["bursts"]):
            for timestamp in _burst_timestamps(now, story, burst_index, offset, count):
                plugin_id = story["plugins"][occurrence % len(story["plugins"])]
                event_index = (occurrence // len(story["plugins"])) % len(_DEMO_EVENTS_BY_PLUGIN_ID[plugin_id])
                event_type, payload = _DEMO_EVENTS_BY_PLUGIN_ID[plugin_id][event_index]
                payload = {**payload, "detail": _event_details(locale, plugin_id)[event_index]}
                event = PluginEvent(
                    event_type=event_type,
                    plugin_id=plugin_id,
                    surface=bindings[plugin_id].surface,
                    operation_id=operation_id,
                    payload=_payload_for_demo_occurrence(payload, occurrence, plugin_id, locale),
                    timestamp=timestamp,
                )
                events_to_persist.append(event)
                if event_type is EventType.TTP_OBSERVED and not rule_recorded:
                    _seed_demo_rule_firing(app, operation, event, locale)
                    rule_recorded = True
                occurrence += 1
        repository = collector.repository
        if hasattr(repository, "append_many"):
            repository.append_many([TelemetryRecord.from_event(event) for event in events_to_persist])
        else:
            for event in events_to_persist:
                collector.handle_event(event)
        seeded_ids.append(operation_id)
    return seeded_ids


_APT28_INCIDENT_TTPS = ("T1046", "T1110.001")


def _apt28_incident_events(events) -> tuple[str, list[str]]:
    """Elige el origen que sostiene el titulo del incidente de ejemplo.

    Devuelve la IP con mas observaciones de reconocimiento + fuerza bruta y
    los IDs de **esas** observaciones. Si ningun origen tiene las dos TTPs,
    devuelve ("", []) y el llamador falla en vez de crear un incidente que
    su propio nombre no sostiene.
    """

    por_origen: dict[str, dict[str, list[str]]] = {}
    for event in events:
        if event.plugin_id != "dolost-apt28-finance" or event.ttp_id not in _APT28_INCIDENT_TTPS:
            continue
        origen = event.payload.get("source_ip")
        if not origen:
            continue
        por_origen.setdefault(origen, {}).setdefault(event.ttp_id, []).append(event.id)

    completos = {
        origen: ids
        for origen, ids in por_origen.items()
        if set(ids) == set(_APT28_INCIDENT_TTPS)
    }
    if not completos:
        return "", []
    origen = max(completos, key=lambda o: (sum(len(v) for v in completos[o].values()), o))
    return origen, sorted(i for ids in completos[origen].values() for i in ids)


def _seed_demo_incidents_and_tlp(client, app, operation_ids: list[str], *, locale: str) -> None:
    """Agrupa y clasifica solo telemetria creada en esta corrida.

    El incidente de APT28 agrupa **las observaciones que comparten un mismo
    origen** y describen reconocimiento seguido de fuerza bruta -- no todos
    los eventos de la capacidad. La diferencia importa: la telemetria de demo
    reparte cientos de eventos entre ~180 IPs distintas, asi que agrupar por
    `plugin_id` daria un "incidente" que es en realidad la operacion entera,
    con un nombre que nombra una sola IP y notas que hablan de dos eventos.
    Un incidente que no se puede sostener leyendolo no sirve de ejemplo.

    Los TLP usan IoCs reales ya normalizados: GREEN para la IP publica de
    escaneo, AMBER para la credencial de identidad y RED para el dominio del
    señuelo Lazarus asociado a una investigacion activa.
    """

    collector = app.config["TELEMETRY_COLLECTOR"]
    operation_repo = app.config["OPERATION_REPOSITORY"]
    for operation_id in operation_ids:
        operation = operation_repo.get(operation_id)
        plugin_ids = {binding.plugin_id for binding in operation.plugins}
        events = collector.list_events(operation_id)

        if "dolost-apt28-finance" in plugin_ids:
            origin, apt28_event_ids = _apt28_incident_events(events)
            assert apt28_event_ids, "Faltan eventos APT28 para crear el incidente de ejemplo."
            incident_response = client.post(
                f"/telemetry/{operation_id}/incidents",
                data={
                    "event_ids": apt28_event_ids,
                    "mode": "new",
                    "name": _seed_text(locale, "incident_name", origin=origin),
                    "notes": _seed_text(locale, "incident_notes", count=len(apt28_event_ids), origin=origin),
                },
                follow_redirects=False,
            )
            assert incident_response.status_code == 302, "No se pudo crear el incidente APT28 de ejemplo."

        for plugin_id, (ioc_type, ioc_value, level) in _DEMO_TLP_BY_PLUGIN_ID.items():
            if plugin_id not in plugin_ids:
                continue
            subject_key = ioc_subject_key(ioc_type, ioc_value)
            known_iocs = {ioc_subject_key(ioc.type, ioc.value) for ioc in collector.list_iocs(operation_id)}
            assert subject_key in known_iocs, f"Falta el IoC '{subject_key}' para clasificarlo."
            tlp_response = client.post(
                f"/telemetry/{operation_id}/tlp",
                data={"subject_type": "ioc", "subject_key": subject_key, "level": level},
                follow_redirects=False,
            )
            assert tlp_response.status_code == 302, f"No se pudo clasificar el IoC '{subject_key}'."


def _seed_demo_closure_criteria(client, app, operation_ids: list[str]) -> None:
    """Carga la Gating Criteria pendiente de APT28 sin disparar el cierre."""

    operation_repo = app.config["OPERATION_REPOSITORY"]
    for operation_id in operation_ids:
        operation = operation_repo.get(operation_id)
        if not any(binding.plugin_id == "dolost-apt28-finance" for binding in operation.plugins):
            continue
        response = client.post(
            f"/operations/{operation_id}/closure-criteria/trigger-conditions",
            data={
                "event_type": "ttp_observed",
                "plugin_id": "dolost-apt28-finance",
                "payload_key": "ttp_id",
                "payload_value": "T1021.004",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302, "No se pudo cargar la Gating Criteria APT28 de ejemplo."


def _seed_demo_assets_and_coverage(client, app, operation_ids: list[str], *, locale: str) -> None:
    """Crea activos reales y declara su cobertura por los formularios web."""

    asset_repository = app.config["ASSET_REPOSITORY"]
    existing_ids = {asset.identifier for asset in asset_repository.list()}
    for asset in _demo_assets(locale):
        if asset["identifier"] in existing_ids:
            continue
        response = client.post("/assets/", data=asset, follow_redirects=False)
        assert response.status_code == 302, f"No se pudo crear el activo '{asset['identifier']}'."

    operation_repository = app.config["OPERATION_REPOSITORY"]
    for operation_id in operation_ids:
        operation = operation_repository.get(operation_id)
        for binding in operation.plugins:
            protected_assets = _demo_asset_coverage(locale).get(binding.plugin_id)
            if protected_assets is None or binding.protected_asset_ids == protected_assets:
                continue
            response = client.post(
                f"/operations/{operation_id}/plugins/{binding.plugin_id}/asset-coverage",
                data={"protected_asset_ids": protected_assets},
                follow_redirects=False,
            )
            assert response.status_code == 302, f"No se pudo declarar cobertura para '{binding.plugin_id}'."


def _buda_credentials_usable() -> tuple[bool, str]:
    """Decide si sembrar perfiles de BUDA es seguro en este entorno.

    `UserProfile.winrm_username`/`winrm_password` usan `EncryptedString`, un
    `TypeDecorator` de SQLAlchemy que descifra **al cargar la fila**, no al
    leer el atributo. Consecuencia: una sola fila que no se pueda descifrar
    rompe con 500 cualquier pantalla que liste perfiles -- el catalogo de
    capacidades, el detalle de operacion y la vista de perfiles -- aunque nadie
    pida la contrasena.

    APATE entrega una clave local persistente cuando no existe la variable de
    entorno, asi que el seed puede crear perfiles en una instalación nueva sin
    configuración adicional. Si una instalación ya trae perfiles que otra
    clave dejó indescifrables, no se agregan más: primero hay que recuperar o
    reemplazar esas credenciales.

    Devuelve (puede_sembrar, motivo). El motivo se imprime; no se lanza, para
    que el resto del seed siga completandose.
    """

    profiles = BudaUserProfile.query.all()
    unreadable = [profile for profile in profiles if not profile.credentials_recoverable]
    if unreadable:
        return False, (
            f"Los {len(unreadable)} perfil(es) que ya están en buda.db no se pueden descifrar con esta clave.\n"
            "   Reemplazá sus credenciales desde la interfaz antes de volver a sembrar perfiles."
        )
    return True, ""


def _seed_demo_buda_profiles_and_activities(client, app, operation_ids: list[str], *, locale: str) -> None:
    """Completa perfiles y actividades de BUDA sin credenciales reales."""

    puede, motivo = _buda_credentials_usable()
    if not puede:
        print(f"\nOmitido: {motivo}")
        return

    operation_repository = app.config["OPERATION_REPOSITORY"]
    for operation_id in operation_ids:
        operation = operation_repository.get(operation_id)
        for binding in operation.plugins:
            profile_data = _demo_buda_profiles(locale).get(binding.plugin_id)
            if profile_data is None:
                continue

            narrative_id = binding.config.get("narrative_id")
            narrative = _buda_narrative(narrative_id)
            if narrative is None:
                response = client.post(
                    f"/operations/{operation_id}/plugins/{binding.plugin_id}/buda/narrative/create",
                    follow_redirects=False,
                )
                assert response.status_code == 302, f"No se pudo crear la narrativa para '{binding.plugin_id}'."
                operation = operation_repository.get(operation_id)
                binding = operation.find_plugin_binding(binding.plugin_id)
                narrative = _buda_narrative(binding.config.get("narrative_id"))
            assert narrative is not None, f"Falta la narrativa para '{binding.plugin_id}'."

            profile = BudaUserProfile.query.filter_by(name=profile_data["name"]).first()
            if profile is None:
                response = client.post(
                    f"/operations/{operation_id}/plugins/{binding.plugin_id}/buda/profiles",
                    data={key: value for key, value in profile_data.items() if not key.startswith("activity_")},
                    follow_redirects=False,
                )
                assert response.status_code == 302, f"No se pudo crear el perfil '{profile_data['name']}'."
                profile = BudaUserProfile.query.filter_by(name=profile_data["name"]).one()
            elif profile not in narrative.user_profiles:
                profile_ids = [str(item.id) for item in narrative.user_profiles] + [str(profile.id)]
                response = client.post(
                    f"/operations/{operation_id}/plugins/{binding.plugin_id}/buda/narrative/profiles",
                    data={"user_profile_ids": profile_ids},
                    follow_redirects=False,
                )
                assert response.status_code == 302, f"No se pudo vincular el perfil '{profile_data['name']}'."

            activity = BudaActivity.query.filter_by(
                activity_type=profile_data["activity_type"], details=profile_data["activity_details"]
            ).first()
            if activity is None:
                response = client.post(
                    f"/operations/{operation_id}/plugins/{binding.plugin_id}/buda/activities",
                    data={
                        "activity_type": profile_data["activity_type"],
                        "details": profile_data["activity_details"],
                        "profile_ids": str(profile.id),
                    },
                    follow_redirects=False,
                )
                assert response.status_code == 302, f"No se pudo crear la actividad de '{profile_data['name']}'."


def _buda_narrative(narrative_id: object) -> BudaNarrative | None:
    """Resuelve una narrativa configurada sin aceptar IDs inválidos."""

    try:
        return buda_db.session.get(BudaNarrative, int(narrative_id))
    except (TypeError, ValueError):
        return None


def _seed_demo_second_scenario_and_measurement(client, app, operation_ids: list[str], *, locale: str) -> None:
    """Añade profundidad visible y un único efecto medido a la demo."""

    operation_repository = app.config["OPERATION_REPOSITORY"]
    for operation_id in operation_ids:
        operation = operation_repository.get(operation_id)
        plugin_ids = {binding.plugin_id for binding in operation.plugins}
        if "dolost-apt28-finance" in plugin_ids and not any(
            scenario.description == _demo_second_scenario(locale)["description"] for scenario in operation.scenarios
        ):
            response = client.post(
                f"/operations/{operation_id}/scenarios", data=_demo_second_scenario(locale), follow_redirects=False
            )
            assert response.status_code == 302, "No se pudo crear el segundo escenario APT28."
        if "dolost-lazarus-exfil" in plugin_ids:
            binding = operation.find_plugin_binding("dolost-lazarus-exfil")
            if not binding.effect.measured_outcome:
                with client.session_transaction() as session:
                    session["operator"] = _seed_text(locale, "operator")
                evidence_ids = [
                    event.id
                    for event in app.config["TELEMETRY_COLLECTOR"].list_events(operation_id)
                    if event.plugin_id == "dolost-lazarus-exfil"
                ][:3]
                response = client.post(
                    f"/operations/{operation_id}/plugins/dolost-lazarus-exfil/effect/measure",
                    data={"measured_outcome": _seed_text(locale, "measured_outcome"), "evidence_event_ids": evidence_ids},
                    follow_redirects=False,
                )
                assert response.status_code == 302, "No se pudo registrar el efecto medido de Lazarus."


def seed_demo_operations(app, *, locale: str = DEFAULT_LOCALE, reference_time: datetime | None = None) -> list[str]:
    """Crea las operaciones del catálogo de plantillas que todavia no
    existan (por `name` exacto) -- devuelve los `operation_id` creados
    en esta corrida (lista vacia si ya estaban todas). Correrla dos
    veces seguidas no duplica nada, ver docstring del modulo."""

    locale = _seed_locale(locale)
    templates = list_templates(locale=locale)
    repo = app.config["OPERATION_REPOSITORY"]
    existing_names = {operation.name for operation in repo.list()}
    client = app.test_client()
    # El seed usa los formularios reales: obtiene el testigo de su propia
    # sesión y lo envía en cada POST, igual que el JavaScript de la interfaz.
    landing = client.get("/")
    token = re.search(r'name="csrf-token" content="([^"]+)"', landing.get_data(as_text=True))
    if landing.status_code != 200 or token is None:
        raise RuntimeError("No se pudo obtener el testigo CSRF para sembrar la demo")
    client.environ_base["HTTP_X_CSRF_TOKEN"] = token.group(1)

    created_ids = []
    for spec in templates:
        name = spec["operation"]["name"]
        if name in existing_names:
            print(f"Ya existe: {name!r} -- salteada.")
            continue
        operation_id = _create_example_operation(client, spec)
        created_ids.append(operation_id)
        print(f"Creada: {name!r} ({operation_id})")

    demo_ids = [
        operation.id
        for operation in repo.list()
        if operation.name in {spec["operation"]["name"] for spec in templates}
    ]
    seeded_ids = _seed_demo_telemetry(app, demo_ids, locale=locale, reference_time=reference_time)
    _seed_demo_incidents_and_tlp(client, app, seeded_ids, locale=locale)
    _seed_demo_closure_criteria(client, app, seeded_ids)
    _seed_demo_assets_and_coverage(client, app, demo_ids, locale=locale)
    _seed_demo_buda_profiles_and_activities(client, app, demo_ids, locale=locale)
    _seed_demo_second_scenario_and_measurement(client, app, demo_ids, locale=locale)
    return created_ids


def main() -> None:
    app = create_app()
    locale = os.environ.get("APATE_LOCALE", DEFAULT_LOCALE)
    with app.app_context():
        created = seed_demo_operations(app, locale=locale)

    if created:
        print(f"\n{len(created)} operacion(es) de ejemplo creada(s). Levantá el servidor con: python -m apate.web")
    else:
        print("\nNinguna operacion nueva -- las 3 operaciones de ejemplo ya existian.")


if __name__ == "__main__":
    main()
