"""Interfaz web (M4b) - documento de diseno, seccion 4.3 (modulo de
Simulacion y Entrenamiento aparte, ver seccion 6) y roadmap M4b.

Aplicacion Flask siguiendo el mismo patron que ya usan DOLOS-T y BUDA
(app factory + blueprints + templates Jinja server-rendered, ver
docs/analisis-repos-existentes.md): sin framework de JS, sin base de
datos propia - la app solo orquesta los repositorios y colectores que
ya existen (apate.core, apate.rules, apate.telemetry).

Cubre: creacion/monitoreo de operaciones (M1) con sus transiciones de
estado, edicion de las reglas del motor de decision (M3), y
visualizacion de la telemetria normalizada (M4). Desde M5 se suman las
vistas separadas de atacante/defensor (seccion 6.4 del diseno), que
arrancan/detienen el stack real de Cyber Deception Playground
(apate.playground) y muestran los eventos que su puente traduce al
bus de M2.

Hasta M8c (seccion 4.5 del diseno), esta misma app montaba ademas la UI
y la API reales de BUDA (`/buda`) y de DOLOS-T (`/dolost`) como
blueprints internos -- un unico proceso, sin capa HTTP intermedia entre
APATE y esas herramientas. Eso ya no es asi: DOLOS-T dejo de tener
blueprint propio en M14b (inventario M14a, docs/roadmap.md seccion M14)
y BUDA en M14e (inventario M14c), en los dos casos porque su UI/API
quedaban o bien redundantes con `Operation` o bien con equivalente
nativo en `apate.web.blueprints.operations`/`plugins`/`health`/`telemetry`. `/dolost/...` y
`/buda/...` no responden mas -- las dos herramientas se usan solo como
libreria Python (DOLOS-T: `DockerManager`, `WebSocketNamespace`, las
funciones de despliegue de `DOLOST.blueprints.api`; BUDA: el motor
WinRM, los modelos SQLAlchemy, `BUDA.routes.ai_integration.generate_activity()`
desde M14e), nunca mas su propia capa web dentro del proceso de APATE.
Ver `apate.web.external` para el detalle de por que eso resuelve de
raiz (no solo mitiga) los dos problemas de integracion que el diseno
original no anticipaba (colision de plantillas, assets estaticos
compartidos). `import apate` (y por lo tanto `apate.web`) requiere
`DOLOST`/`BUDA` instalados salvo que se desactive explicitamente la
preparacion de esa capa de libreria (`APATE_MOUNT_EXTERNAL_TOOLS=False`
en la config de `create_app()`) -- pensado para los tests del resto de
APATE, que no necesitan la sesion SQLAlchemy de BUDA ni el
`DockerManager`/`WebSocketNamespace` de DOLOS-T para probar
Operaciones/Reglas/Telemetria/Playground; ver `tests/conftest.py`.

**M13f -- la instancia de Flask-SocketIO ya NO depende de
`APATE_MOUNT_EXTERNAL_TOOLS`.** Hasta M13f, `mount_dolost()`
(`apate.web.external`) era el unico lugar que creaba
`SocketIO(app, ...)`, y solo se llamaba con el flag en `True` -- con
el flag en `False` (el modo en que corre casi toda la suite de tests,
`tests/conftest.py`) no existia ninguna instancia de `SocketIO` en
absoluto, asi que ninguna notificacion propia de APATE (no de
DOLOS-T) podia asumir que hubiera una disponible. `create_app()` ahora
crea esa instancia de forma incondicional, apenas se construye la app
-- `mount_dolost()` la recibe como parametro en vez de crearla (sigue
gateada por el flag, porque si depende de que `DOLOST` este
instalado). Ver `apate.web.blueprints.playground` para la primera
notificacion real construida sobre esta instancia ya desacoplada
(actividad de una `PlaygroundSession` activa, M5, emitida por
`socketio.emit()` en el namespace `/playground`)."""

from __future__ import annotations

import os
import secrets
import threading
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

import click
from flask import Flask, abort, current_app, flash, g, has_request_context, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from flask_babel import Babel
from flask_socketio import SocketIO
from werkzeug.middleware.proxy_fix import ProxyFix

from ..audit import JSONFileOperatorActionRepository, OperatorAction
from ..deployment import (
    ActiveDirectoryHoneyuserConnector,
    DeploymentService,
    EncryptedJSONCredentialStore,
    HoneyuserEventMonitor,
    JSONFileDeploymentRepository,
    JSONFileDeploymentTargetRepository,
    JSONFileHoneyuserCheckpointRepository,
    WinRMActiveDirectoryTransport,
)
from ..i18n import DEFAULT_LOCALE, LOCALE_NAMES, SUPPORTED_LOCALES, gettext as _
from ..assets import JSONFileAssetImportPreviewRepository, JSONFileAssetRepository
from ..core import JSONFileBehaviorContextRepository, OperationNotFoundError
from ..identity.oidc import EMERGENCY_IDENTITY_ID
from ..identity import (
    Identity,
    IdentityProviderRegistry,
    IdentityRole,
    LocalIdentityProvider,
    supports_redirect_login,
)
from ..playground.config import ENV_VAR as PLAYGROUND_ENV_VAR
from ..provenance import THIRD_PARTY_COMPONENTS, build_info
from ..runtime_paths import publish as _publicar_directorio_de_estado
from ..runtime_paths import runtime_path
from ..schema_version import ensure_compatible
from ..sbom import CYCLONEDX_MEDIA_TYPE, build_json
from ..playground.config import VENDORED_PLAYGROUND_PATH
from ..playground.elastic import DEFAULT_ELASTIC_URL
from ..secrets import (
    EncryptedSiemSoarConfigRepository,
    EncryptedJSONFileOperationRepository,
    EncryptedVirusTotalConfigRepository,
    SecretCipher,
    configure_default_secret_cipher,
)
from ..rules import SQLiteRuleDecisionRepository
from ..telemetry import (
    JSONFileIncidentRepository,
    JSONFileTlpClassificationRepository,
    JSONFileVirusTotalEnrichmentRepository,
    SQLiteTelemetryRepository,
    TelemetryCollector,
)
from ._csrf import register as _register_csrf
from ._request_observability import register_observability
from . import _sessions
from ._dashboard import dashboard_kpis
from .access import can_access_operation, permits, required_role, visible_operations
from ._activity_ingestion import ActivityIngestionService
from ._honeyuser_monitoring import HoneyuserMonitoringService
from ._enum_labels import (
    capability_kind_label,
    criticality_label,
    provider_label,
    deception_level_label,
    environment_label,
    event_type_label,
    operation_status_label,
    tactic_label,
    outcome_label,
    resource_status_label,
    strategic_objective_label,
)
from .blueprints.operations import operations_bp
from .blueprints.playground import playground_bp
from .blueprints.plugins import capabilities_bp, plugins_bp
from .blueprints.rules import rules_bp
from .blueprints.telemetry import telemetry_bp
from .blueprints.health import health_bp
from .blueprints.impact import impact_bp
from .blueprints.assets import assets_bp
from .blueprints.deployments import deployments_bp
from .blueprints.attention import attention_bp
from .blueprints.api import api_bp
from .external import mount_buda, mount_dolost

# Documento YAML vacio: se usa para inicializar APATE_RULES_PATH la
# primera vez que se levanta la app contra un directorio de datos
# nuevo, para que la vista de reglas siempre tenga un archivo valido
# que leer (en vez de tener que distinguir "no existe" de "esta vacio").
_EMPTY_RULES_DOCUMENT = "rules: []\n"

_APATE_STATIC_DIR = Path(__file__).resolve().parent / "static"


def _environment_flag(name: str, default: bool = False) -> bool:
    """Lee flags de entorno sin aceptar valores ambiguos como verdaderos."""

    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes"}


def _environment_number(name: str, default: float, *, minimum: float) -> float:
    """Lee un número de entorno y falla temprano si queda fuera de rango."""

    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} debe ser un número.") from exc
    if value < minimum:
        raise RuntimeError(f"{name} debe ser mayor o igual a {minimum}.")
    return value


def _verificar_directorio_de_datos(data_dir: Path) -> None:
    """Falla temprano y con un mensaje util si no se puede escribir ahi.

    Crea el directorio si falta -- es lo esperable en un primer arranque -- y
    prueba una escritura real, porque existir y ser escribible no son lo mismo:
    el caso concreto es un volumen montado con otro dueño, donde `mkdir` sobre
    un directorio ya existente no falla y el primer `open()` si.
    """

    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        prueba = data_dir / ".apate-escritura"
        prueba.write_text("", encoding="utf-8")
        prueba.unlink()
    except OSError as error:
        raise RuntimeError(
            f"APATE no puede escribir en su directorio de datos ({data_dir}): {error}. "
            "Revisa APATE_DATA_DIR y los permisos de esa ruta; ahi viven las operaciones, "
            "la clave de cifrado de secretos y las identidades."
        ) from error


def create_app(config: Optional[dict[str, Any]] = None) -> Flask:
    """Construye la aplicacion Flask de APATE. `config` permite
    sobreescribir APATE_DATA_DIR/APATE_RULES_PATH (usado por los
    tests, que apuntan a un directorio temporal en vez de
    `.apate_data`), APATE_MOUNT_EXTERNAL_TOOLS (M8c/M14b/M14e/M13f: si
    es False, no prepara la sesion SQLAlchemy de BUDA ni el
    `DockerManager`/`WebSocketNamespace` de DOLOS-T en absoluto --
    desde M14e ninguna de las dos herramientas registra ningun
    blueprint, asi que el flag ya no "monta" nada en el sentido de
    exponer rutas HTTP: gatea exclusivamente la instanciacion de esos
    recursos de libreria puntuales. **Desde M13f, la instancia de
    `SocketIO` en si ya NO esta gateada por este flag** -- existe
    siempre, la use o no DOLOS-T.) y SQLALCHEMY_DATABASE_URI (la base
    de BUDA, ver apate.web.external.mount_buda)."""

    # static_folder=None desactiva el endpoint 'static' automatico de
    # Flask: se registra uno propio mas abajo que busca en varios
    # directorios (APATE + cada herramienta montada), porque las tres
    # apps usan el mismo nombre de endpoint global 'static' en sus
    # plantillas -- ver apate.web.external para el detalle completo.
    app = Flask(__name__, static_folder=None)
    secret_from_env = os.environ.get("APATE_SECRET_KEY")
    data_dir_from_env = Path(os.environ.get("APATE_DATA_DIR", ".apate_data"))
    rules_path_from_env = Path(os.environ.get("APATE_RULES_PATH", data_dir_from_env / "rules.yaml"))
    app.config.from_mapping(
        # Desde la Fase 02 comercial, la cookie de sesión identifica a
        # operadores autenticados. Una clave efímera permite el primer
        # arranque sin configuración, pero invalida las sesiones al reiniciar.
        SECRET_KEY=secret_from_env or secrets.token_urlsafe(48),
        APATE_DATA_DIR=data_dir_from_env,
        APATE_RULES_PATH=rules_path_from_env,
        # Ruta al stack del Playground (M5) -- APATE_PLAYGROUND_PATH
        # para quien quiera apuntar a un checkout propio; si no esta
        # definida, la copia vendorizada en playground-stack/ (ver
        # apate.playground.config, correccion post-M14) sirve de
        # default, asi que esto ya no puede quedar en None.
        APATE_PLAYGROUND_PATH=os.environ.get(PLAYGROUND_ENV_VAR) or str(VENDORED_PLAYGROUND_PATH),
        # URL de Elasticsearch para PlaygroundSession.fetch_elastic_events()
        # (gap real cerrado en la verificacion manual pendiente desde M5,
        # ver docs/roadmap.md y apate/playground/session.py) -- mismo
        # patron que APATE_PLAYGROUND_PATH, variable de entorno opcional
        # con default al puerto convencional de Elasticsearch.
        APATE_ELASTIC_URL=os.environ.get("APATE_ELASTIC_URL") or DEFAULT_ELASTIC_URL,
        # M8c: montado por defecto (asi es como corre el demo real),
        # desactivable para los tests del resto de APATE que no lo
        # necesitan -- ver tests/conftest.py.
        APATE_MOUNT_EXTERNAL_TOOLS=_environment_flag("APATE_MOUNT_EXTERNAL_TOOLS", default=True),
        # Fase 6 de integración: None deriva a habilitado fuera de tests
        # cuando las librerías externas están preparadas.
        APATE_ACTIVITY_INGESTION_ENABLED=None,
        # La telemetría autónoma usa por defecto el mismo motor
        # determinista; False conserva la recolección sin accionar reglas.
        APATE_TELEMETRY_RULES_ENABLED=True,
        APATE_ACTIVITY_INGESTION_INTERVAL=5.0,
        APATE_HONEYUSER_MONITORING_ENABLED=(
            _environment_flag("APATE_HONEYUSER_MONITORING_ENABLED")
            if os.environ.get("APATE_HONEYUSER_MONITORING_ENABLED") is not None
            else None
        ),
        APATE_HONEYUSER_MONITORING_INTERVAL=_environment_number(
            "APATE_HONEYUSER_MONITORING_INTERVAL", 30.0, minimum=5.0
        ),
        APATE_HONEYUSER_RECONCILE_INTERVAL=_environment_number(
            "APATE_HONEYUSER_RECONCILE_INTERVAL", 300.0, minimum=30.0
        ),
        # Elegir proveedor no habilita/deshabilita login: para el proveedor
        # local lo determina exclusivamente si ya existe el primer usuario.
        APATE_IDENTITY_PROVIDER=os.environ.get("APATE_IDENTITY_PROVIDER", "local"),
        # Idioma de la instalacion, por debajo de la preferencia por
        # usuario. Sin definir queda en None **a proposito**: darle
        # `DEFAULT_LOCALE` como valor por defecto lo volveria un escalon
        # siempre presente y `Accept-Language` no se consultaria nunca.
        # Ver `_select_locale()`.
        APATE_LOCALE=os.environ.get("APATE_LOCALE"),
        BABEL_DEFAULT_LOCALE=DEFAULT_LOCALE,
        BABEL_TRANSLATION_DIRECTORIES="translations",
        # Solo se activa detrás de un único proxy reverso propio. Confiar
        # estas cabeceras directamente desde Internet permite suplantar el
        # esquema, host e IP del cliente.
        APATE_TRUSTED_PROXY=_environment_flag("APATE_TRUSTED_PROXY"),
        APATE_STRUCTURED_ACCESS_LOG=_environment_flag("APATE_STRUCTURED_ACCESS_LOG"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        # Límite global antes de que Flask materialice un upload en memoria o
        # disco temporal. El valor admite CTI y EVTX grandes sin dejar el
        # proceso expuesto a cuerpos ilimitados.
        MAX_CONTENT_LENGTH=int(
            _environment_number(
                "APATE_MAX_UPLOAD_BYTES", 128 * 1024 * 1024, minimum=1024
            )
        ),
    )
    if config:
        app.config.update(config)
    app.config.setdefault("APATE_EXTENSIONS", os.environ.get("APATE_EXTENSIONS", ""))
    from ..extensions import configure_extensions
    configure_extensions(app)

    # La base de BUDA la fija `mount_buda()` (apate.web.external) con un URI
    # relativo por defecto (`sqlite:///buda.db`), que Flask resuelve contra
    # `instance_path` -- en una instalacion empaquetada eso cae dentro del
    # entorno de Python, fuera de `APATE_DATA_DIR` y de cualquier volumen
    # persistente: las narrativas simuladas se perderian en cada
    # reinstalacion mientras los `PluginBinding` que las referencian
    # sobreviven en el almacenamiento de operaciones. Esta variable permite
    # apuntarla al mismo almacenamiento persistente, con el mismo patron que
    # `APATE_DATA_DIR`. `setdefault` deja intacta la prioridad existente: un
    # `SQLALCHEMY_DATABASE_URI` explicito en `config` (los tests que montan
    # BUDA) sigue ganando, y sin la variable el default de `mount_buda()` no
    # cambia para nadie.
    buda_database_uri = os.environ.get("APATE_BUDA_DATABASE_URI")
    if not buda_database_uri:
        # Sin variable explicita, la base va al directorio de datos y no al
        # `instance_path` de Flask. Ese default historico (`sqlite:///buda.db`,
        # relativo) caia dentro del entorno de Python: en una instalacion de
        # sistema o no se podia escribir, o las narrativas se perdian en la
        # proxima reinstalacion mientras los `PluginBinding` que las
        # referencian sobrevivian en el almacenamiento de operaciones.
        buda_database_uri = f"sqlite:///{Path(app.config['APATE_DATA_DIR']).resolve() / 'buda.db'}"
    app.config.setdefault("SQLALCHEMY_DATABASE_URI", buda_database_uri)

    if app.config["APATE_TRUSTED_PROXY"]:
        # Un único proxy delante de APATE agrega estas cabeceras. El proxy
        # documentado termina TLS y es el único que puede llegar al puerto
        # local de Gunicorn.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
        app.config["SESSION_COOKIE_SECURE"] = True

    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = secrets.token_urlsafe(48)
        app.logger.warning(
            "APATE_SECRET_KEY no está configurada: se generó una clave efímera y las sesiones no sobrevivirán un reinicio."
        )
    elif secret_from_env is None and not (config and config.get("SECRET_KEY")):
        app.logger.warning(
            "APATE_SECRET_KEY no está configurada: se generó una clave efímera y las sesiones no sobrevivirán un reinicio."
        )

    data_dir = Path(app.config["APATE_DATA_DIR"])
    rules_path = Path(app.config["APATE_RULES_PATH"])
    app.config["APATE_DATA_DIR"] = data_dir
    app.config["APATE_RULES_PATH"] = rules_path

    # Preflight: se comprueba que el directorio de datos exista y sea
    # escribible **antes** de construir ningun repositorio. Sin esto, el
    # primer fallo real ocurria dentro de `SecretCipher`, y salia como un
    # `PermissionError` crudo desde el import de `apate.web.wsgi` -- que
    # gunicorn reporta como "Worker failed to boot", sin decir que directorio
    # ni por que.
    _verificar_directorio_de_datos(data_dir)

    # Y con el directorio ya escribible, el sello de formato: una instalacion
    # no debe arrancar sobre datos de una version que no entiende, porque lo
    # que sigue a leerlos es un `save()` que los reescribe en el formato viejo.
    # Ver `apate.schema_version`.
    ensure_compatible(data_dir)

    # Se publica en el entorno para el codigo vendorizado de DOLOS-T y BUDA,
    # que no puede leer `app.config` (no conoce a Flask ni a APATE) y que
    # historicamente escribia con rutas relativas al directorio de trabajo.
    # Ver `apate.runtime_paths`.
    _publicar_directorio_de_estado(data_dir)
    secret_cipher = SecretCipher.from_environment_or_data_dir(data_dir, logger=app.logger)
    app.config["SECRET_CIPHER"] = secret_cipher
    configure_default_secret_cipher(secret_cipher)

    if os.environ.get("APATE_VAULT_ADDR"):
        from ..deployment import VaultCredentialStore

        deployment_credentials = VaultCredentialStore.from_environment()
    else:
        deployment_credentials = EncryptedJSONCredentialStore(
            data_dir / "deployment_credentials", secret_cipher
        )
    deployment_repository = JSONFileDeploymentRepository(data_dir / "deployments")
    from ..deployment.approvals import PlanApprovalRepository
    app.config["PLAN_APPROVAL_REPOSITORY"] = PlanApprovalRepository(data_dir / "plan_approvals.db")
    app.config["TWO_PERSON_APPROVAL_ENABLED"] = os.getenv("APATE_TWO_PERSON_APPROVAL_ENABLED", "false").lower() in {"1", "true", "yes"}
    deployment_targets = JSONFileDeploymentTargetRepository(data_dir / "deployment_targets")
    honeyuser_connector = ActiveDirectoryHoneyuserConnector(
        credential_store=deployment_credentials,
        transport=WinRMActiveDirectoryTransport(),
    )
    from ..deployment import FilesystemHoneyfileConnector

    filesystem_connector = FilesystemHoneyfileConnector(data_dir / "filesystem_receipts")
    app.config["DEPLOYMENT_CREDENTIAL_STORE"] = deployment_credentials
    app.config["DEPLOYMENT_REPOSITORY"] = deployment_repository
    app.config["DEPLOYMENT_TARGET_REPOSITORY"] = deployment_targets
    app.config["DEPLOYMENT_CONNECTORS"] = {
        honeyuser_connector.kind: honeyuser_connector,
        filesystem_connector.kind: filesystem_connector,
    }
    app.config["DEPLOYMENT_SERVICE"] = DeploymentService(
        repository=deployment_repository,
        connectors=app.config["DEPLOYMENT_CONNECTORS"],
    )
    app.config["HONEYUSER_EVENT_MONITOR"] = HoneyuserEventMonitor(
        connector=honeyuser_connector,
        checkpoint_repository=JSONFileHoneyuserCheckpointRepository(
            data_dir / "honeyuser_checkpoints"
        ),
    )
    honeyuser_monitoring_enabled = app.config["APATE_HONEYUSER_MONITORING_ENABLED"]
    if honeyuser_monitoring_enabled is None:
        honeyuser_monitoring_enabled = not app.testing
    honeyuser_monitoring = HoneyuserMonitoringService(
        app,
        enabled=bool(honeyuser_monitoring_enabled),
        interval_seconds=app.config["APATE_HONEYUSER_MONITORING_INTERVAL"],
        reconcile_interval_seconds=app.config["APATE_HONEYUSER_RECONCILE_INTERVAL"],
    )
    app.config["HONEYUSER_MONITORING_SERVICE"] = honeyuser_monitoring

    identity_provider = IdentityProviderRegistry.create(
        app.config["APATE_IDENTITY_PROVIDER"], data_dir / "identities"
    )
    app.config["IDENTITY_PROVIDER"] = identity_provider

    rules_path.parent.mkdir(parents=True, exist_ok=True)
    if not rules_path.exists():
        rules_path.write_text(_EMPTY_RULES_DOCUMENT, encoding="utf-8")

    app.config["OPERATION_REPOSITORY"] = EncryptedJSONFileOperationRepository(
        data_dir / "operations", secret_cipher
    )
    # El inventario es global: describe infraestructura compartida y no se
    # particiona por equipo ni por operación (ver apate.assets).
    app.config["ASSET_REPOSITORY"] = JSONFileAssetRepository(data_dir / "assets")
    app.config["ASSET_IMPORT_PREVIEW_REPOSITORY"] = JSONFileAssetImportPreviewRepository(
        data_dir / "asset_import_previews"
    )
    behavior_context_repository = JSONFileBehaviorContextRepository(data_dir / "behavior_context")
    app.config["BEHAVIOR_CONTEXT_REPOSITORY"] = behavior_context_repository
    app.config["BEHAVIOR_CONTEXT_UPLOAD_DIR"] = data_dir / "behavior_context_uploads"
    # Historia aprobada y documento de trabajo separado. La adopción explícita
    # conecta los ejecutores compatibles; nunca equivale a una aprobación.
    from ..ledger import OperationPlanService, SQLiteOperationLedger

    operation_ledger = SQLiteOperationLedger(data_dir / "operation_ledger.db", secret_cipher)
    app.config["OPERATION_LEDGER"] = operation_ledger
    app.config["OPERATION_PLAN_SERVICE"] = OperationPlanService(
        operation_ledger, app.config["OPERATION_REPOSITORY"], rules_path,
        contexts=behavior_context_repository, assets=app.config["ASSET_REPOSITORY"], deployments=deployment_repository,
        credentials=deployment_credentials,
    )
    # El contexto global vendorizado se copia una sola vez como fuente
    # heredada. No se elimina ni se selecciona para ninguna operación.
    try:
        behavior_context_repository.import_legacy(runtime_path("context.json"))
    except (OSError, TypeError, ValueError):
        # Un archivo global heredado corrupto no debe impedir que APATE
        # arranque. Se conserva intacto para diagnóstico y la biblioteca
        # queda disponible para una importación válida posterior.
        app.logger.warning("No se pudo importar el context.json heredado", exc_info=True)
    # Fase 4 post-BlackHat (ver docs/roadmap.md): SQLiteTelemetryRepository
    # reemplaza a JSONFileTelemetryRepository como backend por defecto --
    # un unico archivo .db permite la consulta agregada cross-operacion
    # que el Portafolio (M13g) necesita (ver apate.web._portfolio).
    # JSONFileTelemetryRepository sigue existiendo y sigue implementando
    # el mismo contrato (TelemetryRepository), sin deprecar.
    app.config["TELEMETRY_COLLECTOR"] = TelemetryCollector(
        repository=SQLiteTelemetryRepository(data_dir / "telemetry.db")
    )
    from ..attention import AttentionService, SQLiteAttentionRepository

    app.config["ATTENTION_REPOSITORY"] = SQLiteAttentionRepository(data_dir / "attention.db")
    app.config["ATTENTION_SERVICE"] = AttentionService(
        app.config["ATTENTION_REPOSITORY"], app.config["TELEMETRY_COLLECTOR"].repository
    )
    app.config["TELEMETRY_COLLECTOR"].attention_evaluator = app.config["ATTENTION_SERVICE"].on_record
    from ..api import MachineTokenRepository

    app.config["MACHINE_TOKEN_REPOSITORY"] = MachineTokenRepository(data_dir / "machine_tokens.db")
    # Primera de la tanda de mejoras de UI/UX con referencia CounterCraft
    # (ver docs/roadmap.md): agrupacion manual de eventos en "Incidentes"
    # -- mismo patron de persistencia que OPERATOR_ACTION_REPOSITORY (un
    # archivo JSON por operacion), pero editable/borrable, no append-only
    # (ver apate.telemetry.incidents).
    app.config["INCIDENT_REPOSITORY"] = JSONFileIncidentRepository(data_dir / "incidents")
    # Segunda de la tanda de mejoras de UI/UX con referencia CounterCraft
    # (ver docs/roadmap.md): clasificacion manual TLP (Traffic Light
    # Protocol, estandar de FIRST) sobre IoCs/eventos ya observados --
    # mismo patron de persistencia que INCIDENT_REPOSITORY (un archivo
    # JSON por operacion), pero upsert por sujeto en vez de por id (ver
    # apate.telemetry.classifications).
    app.config["TLP_CLASSIFICATION_REPOSITORY"] = JSONFileTlpClassificationRepository(
        data_dir / "tlp_classifications"
    )
    app.config["VIRUSTOTAL_ENRICHMENT_REPOSITORY"] = JSONFileVirusTotalEnrichmentRepository(
        data_dir / "virustotal_enrichments"
    )
    app.config["VIRUSTOTAL_CONFIG_REPOSITORY"] = EncryptedVirusTotalConfigRepository(
        data_dir / "virustotal_config.json", secret_cipher
    )
    app.config["SIEM_SOAR_CONFIG_REPOSITORY"] = EncryptedSiemSoarConfigRepository(
        data_dir / "siem_soar_config.json", secret_cipher
    )
    # Fase 1 post-BlackHat (ver docs/roadmap.md): atribucion y
    # auditoria de acciones manuales de operador, separada de la
    # telemetria (eventos observados por plugins/Playground) -- ver
    # apate.audit.
    app.config["OPERATOR_ACTION_REPOSITORY"] = JSONFileOperatorActionRepository(data_dir / "operator_actions")
    app.config["RULE_DECISION_REPOSITORY"] = SQLiteRuleDecisionRepository(data_dir / "rule_decisions.db")
    from ..rules import RuleRevisionRepository

    app.config["RULE_REVISION_REPOSITORY"] = RuleRevisionRepository(data_dir / "rule_revisions")
    app.config["RULE_REVISION_REPOSITORY"].save(rules_path.read_text(encoding="utf-8"))
    # Sesiones de Playground activas (operation_id -> PlaygroundSession),
    # en memoria y por proceso: ver blueprints/playground.py.
    app.config["PLAYGROUND_SESSIONS"] = {}
    # La corrida de attacker-tools comparte un único contenedor, por lo que el
    # candado debe ser global a las operaciones. Como las sesiones, este
    # estado es efímero: un reinicio no puede recuperar ni cancelar un
    # docker exec que haya quedado huérfano.
    app.config["PLAYGROUND_ATTACKER_RUN"] = None
    app.config["PLAYGROUND_ATTACKER_LOCK"] = threading.Lock()

    # M13f: instancia unica de Flask-SocketIO, incondicional -- ya no
    # depende de APATE_MOUNT_EXTERNAL_TOOLS ni de que DOLOST este
    # instalado (flask-socketio es dependencia de apate desde M8c, esto
    # no suma una dependencia nueva). Flask-SocketIO la guarda sola en
    # app.extensions['socketio'] (de ahi la toma apate.web.__main__ para
    # servir websockets, y cualquier notificacion propia de APATE que
    # necesite emitir en vivo -- ver apate.web.blueprints.playground).
    # async_mode="threading": no agrega una dependencia de eventlet/gevent
    # nueva solo para esto -- threading alcanza para el uso de demo de
    # este hito y es el mismo modo que usa DOLOS-T en su propio main()
    # cuando production=False (ese main() en si nunca se llama desde
    # apate, ver docs/roadmap.md -- housekeeping post-vendorizado,
    # gevent-websocket se saco de pyproject.toml por no tener ningun
    # uso real). namespaces="*": sin esto, python-socketio solo
    # acepta conexiones al namespace por defecto ('/', el que ya usa el
    # WebSocketNamespace de DOLOS-T) -- las notificaciones propias de
    # APATE (M13f, apate.web.blueprints.playground) usan su propio
    # namespace ad-hoc ('/playground'), sin una clase Namespace
    # registrada para el (no hace falta manejar eventos entrantes del
    # cliente ahi, solo emitir), asi que el servidor tiene que aceptar
    # conexiones a namespaces no registrados explicitamente.
    #
    # Sin cors_allowed_origins explicito (default None de python-engineio):
    # el origen permitido se calcula dinamicamente contra el propio
    # scheme+host de cada request (mismo origen, respeta X-Forwarded-*
    # detras de un proxy) -- alcanza para el uso real (la propia UI de
    # APATE conectandose a si misma) sin abrir el namespace de DOLOS-T
    # (`on_request_data`, WebSocketNamespace -- reenvia el container_id
    # recibido tal cual a la API de Docker sin validar que sea un decoy
    # propio) a cualquier pagina de otro origen en la misma red -- ver
    # revision de seguridad post-vendorizado, docs/roadmap.md. Antes se
    # pasaba "*" (sin ninguna razon documentada, a diferencia de
    # async_mode/namespaces mas arriba) -- retirado por no tener
    # justificacion real y ampliar la superficie sin necesidad. La identidad
    # local de la Fase 02 no requiere ni justifica abrir CORS.
    socketio = SocketIO(app, async_mode="threading", namespaces="*")

    def _authentication_active() -> bool:
        """La ausencia/presencia de usuarios locales gobierna el login.

        No es una bandera de configuración: un checkout recién clonado sigue
        abierto y, desde el primer usuario, no vuelve a abrirse aunque todos
        sean desactivados. Proveedores externos pueden exponer el mismo
        método opcional sin agrandar el contrato mínimo de IdentityProvider.
        """

        if app.config.get("APATE_AUTHENTICATION_REQUIRED", False):
            return True
        has_identities = getattr(identity_provider, "has_identities", None)
        return bool(has_identities()) if callable(has_identities) else False

    def _current_identity() -> Identity | None:
        identity_id = session.get("identity_id")
        if not isinstance(identity_id, str):
            return None
        identity = identity_provider.get(identity_id)
        if identity is None:
            return None
        # Una credencial reseteada expulsa a quien ya estaba dentro. Sin esto,
        # resetear la contrasena de una cuenta comprometida solo impide el
        # proximo login: el intruso sigue operando con la sesion que ya tenia.
        # Las sesiones anteriores a este campo no lo tienen; se leen como 0,
        # que es la version de una identidad a la que nunca le cambiaron la
        # clave, asi que nadie queda deslogueado por actualizar.
        if int(session.get("credential_version", 0)) != identity.credential_version:
            session.clear()
            return None
        return identity

    def _select_locale() -> str:
        """Resuelve el idioma de esta request, de lo mas especifico a lo mas general.

        1. `session["locale"]` -- lo que la persona acaba de elegir.
        2. `Identity.locale` -- su preferencia persistida, que es lo que
           hace que el idioma la siga a otro navegador. La sesion va
           primero para que el cambio se vea de inmediato incluso cuando
           el proveedor de identidad no sabe persistir la preferencia.
        3. `APATE_LOCALE` -- el idioma de la instalacion.
        4. `Accept-Language` -- lo unico que se sabe de un visitante sin
           sesion ni identidad, tipicamente en la pantalla de login.
        5. El idioma fuente del proyecto.
        """

        if has_request_context():
            requested = session.get("locale")
            if isinstance(requested, str) and requested in SUPPORTED_LOCALES:
                return requested
            identity = _current_identity()
            if identity is not None and identity.locale in SUPPORTED_LOCALES:
                return str(identity.locale)

        configured = app.config.get("APATE_LOCALE")
        if isinstance(configured, str) and configured in SUPPORTED_LOCALES:
            return configured

        if has_request_context():
            negotiated = request.accept_languages.best_match(SUPPORTED_LOCALES)
            if negotiated:
                return negotiated

        return DEFAULT_LOCALE

    Babel(app, locale_selector=_select_locale)

    def _safe_next_url(value: str | None) -> str:
        """Acepta solo rutas locales para no abrir redirects externos."""

        if value and "\\" not in value and not any(ord(char) < 32 for char in value):
            parsed = urlsplit(value)
            if not parsed.scheme and not parsed.netloc and parsed.path.startswith("/") and not parsed.path.startswith("//"):
                return value
        return url_for("index")

    # Antes que la guarda de identidad a proposito: Flask corre los
    # `before_request` en orden de registro, y una peticion falsificada tiene
    # que rebotar sin llegar a tocar ningun repositorio.
    register_observability(app)
    _register_csrf(app)

    @app.before_request
    def _require_machine_identity():
        """Las rutas API requieren bearer, scope y cuota aun en modo web abierto."""
        transport = app.extensions.get("apate.machine_transports", {}).get(request.blueprint)
        if transport is not None:
            response = transport()
            if response is not None:
                return response
            if getattr(g, "transport_identity", None) is None:
                abort(401)
            return None
        if request.blueprint != "api":
            return None
        from .access import machine_scope_for_endpoint

        authorization = request.headers.get("Authorization", "")
        bearer = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
        token_repository = app.config["MACHINE_TOKEN_REPOSITORY"]
        token = token_repository.authenticate(bearer)
        if token is None:
            return jsonify(error="Token de máquina inválido o vencido."), 401
        scope = machine_scope_for_endpoint(request.endpoint, (request.view_args or {}).get("action"))
        operation_id = (request.view_args or {}).get("operation_id")
        if scope is None or not token.permits(scope, operation_id):
            return jsonify(error="Scope u operación no permitidos."), 403
        if not token_repository.allow_request(token.id):
            return jsonify(error="Cuota de API excedida."), 429
        g.machine_token = token
        return None

    # Por aplicacion y en memoria: ver la advertencia del docstring de
    # `apate.web._sessions` sobre que eso significa con varios procesos.
    _control_de_intentos = _sessions.ControlDeIntentos()
    app.config["LOGIN_ATTEMPTS"] = _control_de_intentos

    @app.before_request
    def _require_authenticated_identity() -> Any:
        """Guarda única para toda la app cuando ya hay usuarios locales."""

        if request.blueprint == "api" or getattr(g, "transport_identity", None) is not None:
            return None
        if not _authentication_active():
            return None
        # Los assets siguen siendo públicos para que la pantalla de login
        # cargue estilos y scripts; no contienen datos de operación.
        if request.endpoint in {"login", "oidc_start", "oidc_callback", "static", "about"}:
            return None
        if request.endpoint is None:
            return None
        identity = _current_identity()
        if identity is None:
            session.clear()
            return redirect(url_for("login", next=request.full_path))
        # Vencimiento antes de dejar pasar: una cookie capturada no puede
        # valer para siempre. Dos relojes, y los dos hacen falta -- ver
        # `apate.web._sessions`.
        if _sessions.vencida(session):
            session.clear()
            flash(_("Tu sesión venció. Iniciá sesión de nuevo."), "error")
            return redirect(url_for("login", next=request.full_path))
        _sessions.refrescar_actividad(session)
        g.current_identity = identity
        required = required_role(request.endpoint, request.method)
        if not permits(identity, required):
            abort(403)
        policy = app.extensions.get("apate.web_authorization")
        if policy is not None and not policy(identity, request.endpoint, request.method, request.view_args or {}):
            abort(403)
        operation_id = (request.view_args or {}).get("operation_id")
        if isinstance(operation_id, str):
            try:
                operation = app.config["OPERATION_REPOSITORY"].get(operation_id)
            except OperationNotFoundError:
                # El blueprint conserva la respuesta 404 específica para
                # una operación inexistente; acá solo se decide aislamiento.
                operation = None
            if operation is not None and not can_access_operation(identity, operation):
                abort(404)
        return None

    def _auditar_login(nombre: str, resultado: str, detalle: str) -> None:
        """Deja en la auditoria quien entro, y quien lo intento y fallo.

        **No existia ninguno de los dos.** Habia registro de alta, baja y
        cambio de contrasenia, pero no de inicios de sesion: la fuerza bruta
        era libre y ademas invisible. Un intento fallido es tan informativo
        como uno exitoso -- muchas veces, mas.

        El nombre se guarda tal como lo escribieron, sin confirmar que exista:
        un intento contra una cuenta inexistente es justamente lo que se
        quiere poder ver.
        """

        try:
            app.config["OPERATOR_ACTION_REPOSITORY"].append(
                OperatorAction(
                    operation_id="identity-management",
                    action="login",
                    operator=nombre or "(sin nombre)",
                    outcome=resultado,
                    detail=detalle,
                )
            )
        except Exception:  # la auditoria no puede impedir entrar
            app.logger.warning("No se pudo auditar el inicio de sesión", exc_info=True)

    def _auditar_emergencia(identity: Identity) -> None:
        """Deja rastro de cada uso del acceso de emergencia de OIDC.

        Es una credencial local que evita el inicio de sesion corporativo: que
        se use puede ser perfectamente legitimo (el IdP se cayo) o no serlo en
        absoluto, y la unica forma de distinguirlo despues es que haya quedado
        registrado. Antes no quedaba en ningun lado.
        """

        if identity.id != EMERGENCY_IDENTITY_ID:
            return
        try:
            app.config["OPERATOR_ACTION_REPOSITORY"].append(
                OperatorAction(
                    operation_id="identity-management",
                    action="emergency_login",
                    operator=identity.display_name,
                    outcome="success",
                    detail=_(
                        "Inicio de sesión con el acceso de emergencia de OIDC, que evita el "
                        "proveedor de identidad corporativo."
                    ),
                )
            )
        except Exception:  # la auditoria no puede impedir el rescate
            app.logger.warning("No se pudo auditar el acceso de emergencia", exc_info=True)

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Any:
        """Inicia sesión únicamente cuando ya hay usuarios configurados."""

        if not _authentication_active():
            return redirect(_safe_next_url(request.args.get("next")))
        if _current_identity() is not None:
            return redirect(_safe_next_url(request.values.get("next")))
        if request.method == "POST":
            nombre = request.form.get("display_name", "")
            origen = request.remote_addr or "desconocido"
            espera = _control_de_intentos.segundos_de_espera(nombre, origen)
            if espera > 0:
                _auditar_login(nombre, "error", _(
                    "Intento de inicio de sesión rechazado: demasiados fallos recientes."
                ))
                flash(_(
                    "Demasiados intentos fallidos. Probá de nuevo en %(minutos)s minutos.",
                    minutos=max(1, int(espera // 60) + 1),
                ), "error")
                return _pantalla_de_login()
            identity = identity_provider.authenticate(nombre, request.form.get("password", ""))
            if identity is None:
                _control_de_intentos.registrar_fallo(nombre, origen)
                _auditar_login(nombre, "error", _("Credenciales inválidas."))
                flash(_("Credenciales inválidas."), "error")
            else:
                _control_de_intentos.registrar_exito(nombre, origen)
                _auditar_emergencia(identity)
                session.clear(); session["identity_id"] = identity.id
                session["credential_version"] = identity.credential_version
                _sessions.marcar_inicio(session)
                _auditar_login(identity.display_name, "success", _("Inicio de sesión."))
                return redirect(_safe_next_url(request.form.get("next")))
        return _pantalla_de_login()

    def _pantalla_de_login() -> Any:
        return render_template(
            "login.html",
            next_url=_safe_next_url(request.values.get("next")),
            redirect_login=supports_redirect_login(identity_provider),
        )

    @app.get("/login/oidc/start")
    def oidc_start() -> Any:
        if not supports_redirect_login(identity_provider):
            abort(404)
        state = secrets.token_urlsafe(32)
        session["oidc_state"] = state
        session["oidc_next"] = _safe_next_url(request.args.get("next"))
        return redirect(identity_provider.authorization_url(url_for("oidc_callback", _external=True), state))

    @app.get("/login/oidc/callback")
    def oidc_callback() -> Any:
        """Completa el retorno OIDC solo si coincide el state de sesión.

        La capacidad se consulta **antes** que el `state`: en una instalación
        sin proveedor de redirección esta ruta no existe, y responder 400 a
        una petición mal formada admitiría que hay algo del otro lado.
        """
        if not supports_redirect_login(identity_provider):
            abort(404)
        state = request.args.get("state", "")
        expected = session.pop("oidc_state", "")
        next_url = session.pop("oidc_next", url_for("index"))
        if not state or not secrets.compare_digest(state, expected):
            abort(400)
        try:
            identity = identity_provider.complete_authorization(request.args["code"], url_for("oidc_callback", _external=True))
        except Exception:
            app.logger.warning("El retorno OIDC fue rechazado.", exc_info=True)
            abort(401)
        if identity is None:
            abort(403)
        session.clear(); session["identity_id"] = identity.id
        session["credential_version"] = identity.credential_version
        # El mismo sello que el login local: el vencimiento no depende de por
        # que puerta se entro.
        _sessions.marcar_inicio(session)
        _auditar_login(identity.display_name, "success", _("Inicio de sesión por el proveedor corporativo."))
        return redirect(_safe_next_url(next_url))

    @app.route("/logout", methods=["POST"])
    def logout() -> Any:
        """Cierra la sesión autenticada y elimina toda atribución residual."""

        session.clear()
        flash(_("Sesión cerrada."), "success")
        return redirect(url_for("login") if _authentication_active() else url_for("index"))

    def _local_identity_provider() -> LocalIdentityProvider:
        if not isinstance(identity_provider, LocalIdentityProvider):
            raise click.ClickException("La gestión por consola requiere el proveedor local de identidad.")
        return identity_provider

    @app.cli.command("create-user")
    @click.argument("display_name")
    @click.option("--role", type=click.Choice([role.value for role in IdentityRole]), default=None)
    @click.option("--team", "team_id", default=None)
    def create_user_command(display_name: str, role: str | None, team_id: str | None) -> None:
        """Crea el primer usuario (o uno posterior) sin exponer su contraseña."""

        # Interactivo por defecto: no deja la contrasena en el historial del
        # shell ni en los argumentos del proceso. Pero `click.prompt` con
        # `hide_input` usa getpass, que lee de la consola y **se cuelga** si no
        # hay terminal -- justo el caso de una instalacion desatendida
        # (contenedor, Ansible), que es como se instala un producto on-premise.
        # La variable de entorno es la valvula de escape estandar para eso.
        password = os.environ.get("APATE_INITIAL_PASSWORD")
        if password:
            click.echo("Usando la contraseña de APATE_INITIAL_PASSWORD.")
        else:
            password = click.prompt("Contraseña", hide_input=True, confirmation_prompt=True)
        try:
            identity = _local_identity_provider().create(display_name, password, role=role, team_id=team_id)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"Usuario creado: {identity.display_name} ({identity.id}), {identity.role.value}, equipo: {identity.team_id or '-'}")

    @app.cli.command("provision-oidc-user")
    @click.argument("subject")
    @click.argument("display_name")
    @click.option("--role", type=click.Choice([role.value for role in IdentityRole]), required=True)
    @click.option("--team", "team_id", default=None)
    def provision_oidc_user_command(subject: str, display_name: str, role: str, team_id: str | None) -> None:
        """Da de alta un sujeto OIDC previamente, sin credenciales interactivas.

        SUBJECT es el claim `sub` del proveedor de identidad, no el correo ni
        el nombre de usuario: es lo que viaja en el `id_token` y con lo que se
        hace el match al entrar. Elegir el correo es el error clásico -- un
        correo cambia cuando alguien se casa o cambia de área, y ahí la persona
        deja de poder entrar; el `sub` es estable por definición.

        En Okta y Azure AD el `sub` se ve en el token de prueba de la consola
        de administración, o en el endpoint `/userinfo`.
        """

        provision = getattr(identity_provider, "provision", None)
        if not callable(provision):
            raise click.ClickException("El proveedor configurado no admite aprovisionamiento OIDC.")
        try:
            identity = provision(subject=subject, display_name=display_name, role=role, team_id=team_id)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(f"Sujeto OIDC aprovisionado: {identity.display_name} ({identity.id}), {identity.role.value}, equipo: {identity.team_id or '-'}")

    @app.cli.command("list-users")
    def list_users_command() -> None:
        """Lista usuarios locales sin revelar hashes ni contraseñas."""

        identities = _local_identity_provider().list()
        if not identities:
            click.echo("No hay usuarios configurados.")
            return
        for identity in identities:
            state = "activo" if identity.active else "desactivado"
            click.echo(f"{identity.id}\t{identity.display_name}\t{identity.role.value}\t{identity.team_id or '-'}\t{state}")

    @app.cli.command("deactivate-user")
    @click.argument("identity_id")
    def deactivate_user_command(identity_id: str) -> None:
        """Desactiva un usuario local sin borrar su identidad histórica."""

        try:
            identity = _local_identity_provider().deactivate(identity_id)
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        except KeyError as exc:
            raise click.ClickException("No existe una identidad con ese id.") from exc
        click.echo(f"Usuario desactivado: {identity.display_name} ({identity.id})")

    app.register_blueprint(operations_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(telemetry_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(impact_bp)
    app.register_blueprint(playground_bp)
    app.register_blueprint(plugins_bp)
    app.register_blueprint(capabilities_bp)
    app.register_blueprint(deployments_bp)
    app.register_blueprint(attention_bp)
    app.register_blueprint(api_bp)

    static_dirs = [_APATE_STATIC_DIR]
    if app.config["APATE_MOUNT_EXTERNAL_TOOLS"]:
        # M14e: con mount_buda() habiendo perdido sus nueve blueprints
        # (mismo camino que mount_dolost() en M14b), ninguna de las dos
        # funciones monta ya nada bajo /static ni /templates -- las dos
        # son pura preparacion de recursos de libreria (DockerManager +
        # WebSocketNamespace para DOLOS-T; sesion SQLAlchemy para BUDA).
        # El flag paso a gatear una unica cosa consistente ("preparar la
        # integracion de libreria con DOLOS-T/BUDA") en vez de la
        # asimetria transitoria que hubo entre M14b y M14e (DOLOS-T ya
        # sin blueprint, BUDA todavia con uno) -- no hace falta
        # revisarlo de nuevo salvo que alguna de las dos vuelva a sumar
        # una superficie HTTP propia. La instancia de SocketIO en si
        # (arriba) ya no es parte de esta lista desde M13f -- existe
        # siempre, mount_dolost() la recibe en vez de crearla.
        # BUDA conserva su contrato standalone: fuera de APATE requiere
        # una variable de entorno. Al montarlo acá, una clave local estable
        # evita que un perfil creado durante un demo quede ilegible al
        # reiniciar; la variable sigue teniendo prioridad sobre el archivo.
        buda_credential_key = SecretCipher.fernet_key_from_environment_or_data_dir(
            data_dir,
            environment_variable="BUDA_CREDENTIAL_ENCRYPTION_KEY",
            key_filename="buda_credential_encryption.key",
            logger=app.logger,
        )
        app.config["BUDA_CREDENTIAL_ENCRYPTION_KEY"] = buda_credential_key
        mount_dolost(app, socketio)
        mount_buda(app, database_uri=app.config.get("SQLALCHEMY_DATABASE_URI"))

    ingestion_enabled = app.config["APATE_ACTIVITY_INGESTION_ENABLED"]
    if ingestion_enabled is None:
        ingestion_enabled = not app.testing and app.config["APATE_MOUNT_EXTERNAL_TOOLS"]
    ingestion_service = ActivityIngestionService(
        app,
        enabled=bool(ingestion_enabled and app.config["APATE_MOUNT_EXTERNAL_TOOLS"]),
        rules_enabled=bool(app.config["APATE_TELEMETRY_RULES_ENABLED"]),
        interval_seconds=app.config["APATE_ACTIVITY_INGESTION_INTERVAL"],
    )
    app.config["ACTIVITY_INGESTION_SERVICE"] = ingestion_service

    @app.context_processor
    def _inject_external_tools_flag() -> dict[str, Any]:
        return {"apate_external_tools_mounted": app.config["APATE_MOUNT_EXTERNAL_TOOLS"]}

    @app.context_processor
    def _inject_build_info() -> dict[str, Any]:
        # El pie de `base.html` lleva el aviso de licencia a todas las
        # pantallas, incluida la de login, asi que la informacion tiene que
        # estar disponible sin que cada `render_template()` la pase --
        # mismo mecanismo que `_inject_enum_labels()`. `build_info()` esta
        # cacheada, asi que esto no cuesta nada por request.
        return {"apate_build": build_info()}

    @app.context_processor
    def _inject_current_operator() -> dict[str, Any]:
        # Sin usuarios se conserva la atribución libre de la Fase 1. Desde
        # el primer usuario, el nombre sale exclusivamente de la identidad
        # autenticada y deja de ser editable desde la sesión.
        identity = _current_identity()
        authentication_active = _authentication_active()
        role_class = f" role-{identity.role.value}" if identity is not None else ""
        return {
            "current_operator": identity.display_name if identity else session.get("operator", ""),
            "current_identity": identity,
            "identity_authentication_active": authentication_active,
            "can_operate": not authentication_active or bool(
                identity and permits(identity, IdentityRole.OPERATION)
            ),
            "can_administer": not authentication_active or bool(
                identity and permits(identity, IdentityRole.ADMINISTRATION)
            ),
            "identity_role_class": role_class,
            # Una puerta que evita el SSO no puede ser invisible: mientras
            # este abierta, la interfaz lo dice en todas las pantallas.
            "emergency_access_open": bool(getattr(identity_provider, "emergency_enabled", False)),
        }

    @app.context_processor
    def _inject_navigation_operations() -> dict[str, Any]:
        """Operaciones disponibles para el selector rapido global.

        Es una ayuda de navegacion, no una busqueda ni una decision del
        sistema: usa el mismo repositorio local y solo expone id/nombre.
        """

        if request.endpoint == "impact.dashboard":
            return {"navigation_operations": []}

        operations = sorted(
            visible_operations(_current_identity(), app.config["OPERATION_REPOSITORY"].list()),
            key=lambda op: op.updated_at,
            reverse=True,
        )
        return {"navigation_operations": operations}

    @app.context_processor
    def _inject_locale() -> dict[str, Any]:
        # `<html lang>` y el selector visible. El nombre de cada idioma va
        # en ese idioma, nunca traducido.
        return {
            "current_locale": _select_locale(),
            "available_locales": [(code, LOCALE_NAMES[code]) for code in SUPPORTED_LOCALES],
        }

    @app.context_processor
    def _inject_enum_labels() -> dict[str, Any]:
        # Etiquetas legibles para enums que se mostraban crudos en la UI
        # (hallazgo real del usuario) -- ver apate.web._enum_labels para
        # el detalle completo y los contratos que permanecen crudos.
        return {
            "strategic_objective_label": strategic_objective_label,
            "environment_label": environment_label,
            "tactic_label": tactic_label,
            "event_type_label": event_type_label,
            "operation_status_label": operation_status_label,
            "resource_status_label": resource_status_label,
            "outcome_label": outcome_label,
            "deception_level_label": deception_level_label,
            "capability_kind_label": capability_kind_label,
            "criticality_label": criticality_label,
            "provider_label": provider_label,
        }

    @app.route("/locale", methods=["POST"])
    def set_locale() -> Any:
        """Cambia el idioma de quien esta usando la aplicacion.

        La preferencia es por usuario, no por instalacion: se guarda en la
        sesion (efecto inmediato, y unica opcion sin login) y ademas en la
        identidad cuando el proveedor sabe persistirla, que es lo que hace
        que el idioma acompane a la persona a otro navegador. Un proveedor
        externo sin `set_locale()` no es un error: la preferencia
        simplemente vive lo que dura la sesion.
        """

        requested = request.form.get("locale", "").strip()
        if requested not in SUPPORTED_LOCALES:
            flash(_("Idioma no disponible."), "error")
            return redirect(_safe_next_url(request.form.get("next")))

        session["locale"] = requested
        identity = _current_identity()
        if identity is not None:
            persist = getattr(identity_provider, "set_locale", None)
            if callable(persist):
                persist(identity.id, requested)
        return redirect(_safe_next_url(request.form.get("next")))

    @app.route("/operator", methods=["POST"])
    def set_operator() -> Any:
        """Setea atribución libre solo mientras no haya usuarios locales.

        Fase 1 post-BlackHat: setea/limpia el
        nombre de operador de la sesion actual, usado para atribuir
        las acciones manuales que se registren en
        `OPERATOR_ACTION_REPOSITORY` (ver
        `apate.web.blueprints.operations`). Texto libre, sin
        validacion contra ninguna lista (ni siquiera contra
        `StrategicDecisions.roles`, que es por-operacion, mientras que
        el operador es un valor de sesion cruzando operaciones) -- no
        es autenticacion, es atribucion."""

        if _authentication_active():
            session.pop("operator", None)
            flash(_("La auditoría usa la identidad autenticada."), "info")
            return redirect(_safe_next_url(request.form.get("next")))

        operator = request.form.get("operator", "").strip()
        if operator:
            session["operator"] = operator
            flash(_("Operando como '%(operator)s'.", operator=operator), "success")
        else:
            session.pop("operator", None)
            flash(_("Nombre de operador limpiado."), "success")
        return redirect(_safe_next_url(request.form.get("next")))

    @app.route("/static/<path:filename>", endpoint="static")
    def _serve_static(filename: str) -> Any:
        for directory in static_dirs:
            if (directory / filename).is_file():
                return send_from_directory(directory, filename)
        abort(404)

    @app.route("/")
    def index() -> Any:
        # Landing propia (antes: redirect a /operations/) -- pitch +
        # tarjetas de las secciones principales + un vistazo de KPIs
        # reales via dashboard_kpis() (M13d, extraida a
        # apate.web._dashboard para no duplicarla, ver ese modulo).
        # Sin operaciones todavia, la landing lo dice explicito en vez
        # de mostrar KPIs vacios (mismo criterio que el dashboard de
        # Operaciones).
        operations = visible_operations(_current_identity(), app.config["OPERATION_REPOSITORY"].list())
        kpis = dashboard_kpis(operations) if operations else None
        # La accion principal del hero es la *siguiente accion*, no un
        # destino: ir al listado ya lo cubre la tarjeta "Operaciones" y
        # duplicarlo desperdicia el lugar mas visible de la pantalla. Con
        # operaciones cargadas, retomar la ultima que se toco; sin ellas,
        # crear la primera. Ninguna de las dos se alcanza desde las tarjetas.
        latest = max(operations, key=lambda op: op.updated_at) if operations else None
        return render_template("landing.html", kpis=kpis, latest_operation=latest)

    @app.get("/about")
    def about() -> Any:
        """Aviso de licencia y oferta de fuente correspondiente (AGPLv3 §13).

        **Publica a proposito, incluso con autenticacion activa** (esta en la
        allowlist de `_require_authenticated_identity`): el articulo 13 habla
        de "todos los usuarios que interactuan remotamente" con el programa, y
        alguien detenido en la pantalla de login ya esta interactuando. Dejar
        el aviso detras de la sesion lo volveria inalcanzable justo para quien
        no tiene cuenta.

        No expone ningun dato de operacion: version, commit, licencia y los
        componentes de terceros que viajan en la misma imagen.
        """

        return render_template("about.html", build=build_info(), components=THIRD_PARTY_COMPONENTS)

    @app.get("/about/sbom.json")
    def sbom() -> Any:
        """Inventario de materiales (SBOM) de esta instalacion, en CycloneDX 1.6.

        **Requiere sesion, a diferencia de `/about`, y la diferencia es
        deliberada.** El articulo 13 de la AGPLv3 obliga a ofrecer el fuente
        correspondiente, no un inventario de versiones: `/about` ya cumple esa
        obligacion y por eso es publico. Un SBOM dice otra cosa -- que version
        exacta de cada dependencia corre -- y eso, servido sin autenticar
        desde una herramienta que vive **dentro** de la red que protege, es un
        mapa de superficie de ataque regalado a quien lo pida. Quien necesite
        el SBOM sin tener cuenta lo recibe fuera de banda, generado en el
        build con `python -m apate.sbom`.

        Se sirve desde la aplicacion igual porque es la unica forma de que el
        documento describa lo que **realmente** esta instalado en esta
        maquina, y no lo que el repositorio declaraba cuando se armo el
        paquete.
        """

        return current_app.response_class(
            build_json(), mimetype=CYCLONEDX_MEDIA_TYPE
        )

    @app.errorhandler(404)
    def not_found(_error: Any) -> tuple[str, int]:
        """Mantiene los errores de navegación dentro del shell de APATE."""

        return render_template("errors/404.html"), 404

    from ._operation_execution import install_execution
    install_execution(app)
    from ..extensions import initialize_extensions
    initialize_extensions(app)
    ingestion_service.start(socketio)
    honeyuser_monitoring.start()
    return app
