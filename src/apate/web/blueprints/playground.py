"""Vistas de atacante y defensor del modo Playground (M5) - documento
de diseno, seccion 6.4.

Arranca/detiene el stack Cyber Deception Playground sobre el checkout
local configurado (APATE_PLAYGROUND_PATH, ver apate.playground.config)
y arma una PlaygroundSession por operacion (RuleEngine + bus propios,
TelemetryCollector central de M4) mientras esta activa. Las sesiones
viven en memoria, en app.config["PLAYGROUND_SESSIONS"] -- se pierden
al reiniciar el proceso, ya que el stack detras es por definicion
desechable (seccion 6.1 del diseno); la telemetria ya persistida via
M4 sobrevive igual.

- Vista de atacante: acciones del contenedor atacante (eventos del
  puente con payload['source'] == 'attacker'), tal como pide la
  seccion 6.4 del diseno.
- Vista de defensor: la misma telemetria normalizada que ya expone la
  vista de Telemetria de M4b, más las decisiones persistidas del motor
  de reglas, aun después de terminar la sesión o reiniciar el proceso.
  Desde M14f, ademas, la comparacion "esperado vs. observado" contra
  lo que la operacion planifico -- mismo `generate_report()` (M6) y
  heatmap de TTPs (M13a) que usa la vista de detalle de operacion,
  pero sin el gate de `CLOSED` que impone esa vista: el Playground
  corre sobre una operacion activa por definicion, tiene sentido verla
  en vivo mientras corre, no solo despues de cerrarla -- generate_report()
  en si nunca exigio CLOSED, esa restriccion vivia solo en
  operations.py::detail().

**M13f -- notificaciones en tiempo real sobre la instancia de
`SocketIO` ya desacoplada (`apate.web`, incondicional desde este
hito).** `_start_session()` suscribe un handler nuevo al mismo
`EventBus` que ya arma `PlaygroundSession.create()` (el mismo bus que
`RuleEngine`/`TelemetryCollector` ya escuchan, sin tocar
`apate.playground`/`apate.rules` en si) -- cada vez que ese bus recibe
un evento `interaction`/`ttp_observed` real (via
`PlaygroundEventBridge`, nunca fabricado ni simulado, exactamente lo
mismo que ya alimenta `RuleEngine.history`/`TelemetryCollector`), este
handler emite por `socketio.emit()` en el namespace `/playground`
(propio de APATE, no el `/` que ya usa el `WebSocketNamespace` de
DOLOS-T) -- incluye si ese evento puntual disparo alguna regla
(cruzando `RuleFiring.triggering_event_id` contra `RuleEngine.history`,
sin duplicar la logica de disparo del motor). `playground/defender.html`
lo consume del lado del cliente para actualizar una vista en vivo sin
recargar la pagina.

**M14g -- cobertura del escenario fijo del Playground.** Alcance chico
de la investigacion M14g (ver docs/roadmap.md): el escenario simulado
del Playground ("Andesfinance") es fijo, no varia segun la `Operation`
vinculada, salvo `DECEPTION_LEVEL`. `defender_view()` cruza
`Scenario.related_ttps` de cada escenario de la operacion contra
`apate.playground.scenario_ttps.match_scenario_ttps()` (dataset propio,
investigacion puntual contra el repo real) para mostrar, por escenario,
que TTPs esperadas el escenario fijo puede llegar a producir en esta
corrida y cuales no tiene ninguna chance de generar -- distinto de
`matched_ttps`/`ttps_not_observed` de `generate_report()` (M14f), que
es sobre lo ya observado, no sobre lo que el escenario fijo puede
producir en principio."""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from ...core.exceptions import OperationNotFoundError
from ...core.models import DeceptionLevel, Operation
from ...engage import get_activity as _get_engage_activity
from ...i18n import gettext as _
from ...plugins.base import EventType, PluginEvent
from ...playground.config import PlaygroundConfig
from ...playground.events import PLAYGROUND_PLUGIN_ID
from ...playground.exceptions import PlaygroundConfigError, PlaygroundError
from ...playground.lifecycle import run_attacker_script_streaming, start_stack, stop_stack
from ...playground.scenario_ttps import match_scenario_ttps
from ...playground.session import PlaygroundSession
from ...reporting import generate_report
from ...rules.engine import RuleEngine
from ...rules.models import parse_rules
from .._ttp_presentation import ttp_heatmap as _ttp_heatmap
from ..access import visible_operations

playground_bp = Blueprint("playground", __name__, url_prefix="/playground")

# Namespace propio de APATE (M13f) -- deliberadamente distinto del '/'
# que ya usa el WebSocketNamespace de DOLOS-T (apate.web.external), asi
# que las dos integraciones nunca compiten por los mismos nombres de
# evento sobre la misma conexion logica.
_NOTIFICATIONS_NAMESPACE = "/playground"


@playground_bp.route("/")
def index():
    repo = current_app.config["OPERATION_REPOSITORY"]
    sessions = current_app.config["PLAYGROUND_SESSIONS"]
    operations = sorted(visible_operations(getattr(g, "current_identity", None), repo.list()), key=lambda op: op.created_at, reverse=True)
    return render_template(
        "playground/index.html",
        operations=operations,
        levels=list(DeceptionLevel),
        active_operation_ids={op.id for op in operations if op.id in sessions},
    )


@playground_bp.route("/<operation_id>/start", methods=["POST"])
def start(operation_id: str):
    operation = _get_operation_or_404(operation_id)

    try:
        level = DeceptionLevel(request.form.get("level", ""))
    except ValueError:
        flash(
            _(
                "Nivel de engano invalido: '%(level)s'.",
                level=request.form.get("level"),
            ),
            "error",
        )
        return redirect(url_for("playground.index"))

    try:
        config = _resolve_config()
        start_stack(config, level)
    except PlaygroundError as exc:
        flash(str(exc), "error")
        return redirect(url_for("playground.index"))

    _start_session(operation)
    flash(
        _(
            "Playground iniciado para '%(name)s' (nivel '%(level)s').",
            name=operation.name,
            level=level.value,
        ),
        "success",
    )
    return redirect(url_for("playground.index"))


@playground_bp.route("/<operation_id>/stop", methods=["POST"])
def stop(operation_id: str):
    _get_operation_or_404(operation_id)
    sessions = current_app.config["PLAYGROUND_SESSIONS"]
    attacker_run = current_app.config["PLAYGROUND_ATTACKER_RUN"]
    if attacker_run is not None and attacker_run["status"] == "running":
        flash(_("No se puede detener el stack mientras el atacante está corriendo."), "error")
        return redirect(url_for("playground.index"))

    try:
        config = _resolve_config()
        stop_stack(config)
    except PlaygroundError as exc:
        flash(str(exc), "error")
        return redirect(url_for("playground.index"))

    sessions.pop(operation_id, None)
    flash(_("Playground detenido."), "success")
    return redirect(url_for("playground.index"))


@playground_bp.route("/<operation_id>/attacker")
def attacker_view(operation_id: str):
    operation = _get_operation_or_404(operation_id)
    collector = current_app.config["TELEMETRY_COLLECTOR"]

    events = [
        e
        for e in collector.list_events(operation_id)
        if e.plugin_id == PLAYGROUND_PLUGIN_ID and e.payload.get("source") == "attacker"
    ]
    attacker_run = current_app.config["PLAYGROUND_ATTACKER_RUN"]
    return render_template(
        "playground/attacker.html",
        operation=operation,
        events=events,
        session_active=operation_id in current_app.config["PLAYGROUND_SESSIONS"],
        attacker_run=attacker_run,
    )


@playground_bp.route("/<operation_id>/attacker/run", methods=["POST"])
def run_attacker(operation_id: str):
    operation = _get_operation_or_404(operation_id)
    session = current_app.config["PLAYGROUND_SESSIONS"].get(operation_id)

    if current_app.config["OPERATION_EXECUTOR"].managed(operation_id):
        # La sesión heredada no es una fuente aprobada ni una cuota B2.
        session = None
    if session is None:
        flash(
            _(
                "No hay una sesión activa para esta operación: iniciá el stack Playground antes de lanzar el atacante."
            ),
            "error",
        )
        return redirect(url_for("playground.attacker_view", operation_id=operation_id))

    try:
        config = _resolve_config()
    except PlaygroundError as exc:
        flash(str(exc), "error")
        return redirect(url_for("playground.attacker_view", operation_id=operation_id))

    lock = current_app.config["PLAYGROUND_ATTACKER_LOCK"]
    with lock:
        existing = current_app.config["PLAYGROUND_ATTACKER_RUN"]
        if existing is not None and existing["status"] == "running":
            flash(
                _(
                    "El atacante ya está corriendo para la operación '%(name)s'. Esperá a que termine antes de iniciar otra corrida.",
                    name=existing["operation_name"],
                ),
                "error",
            )
            return redirect(url_for("playground.attacker_view", operation_id=operation_id))
        attacker_run = {
            "operation_id": operation_id,
            "operation_name": operation.name,
            "status": "running",
            "started_at": datetime.now(timezone.utc),
            "finished_at": None,
            "error": None,
            "phases": [],
        }
        current_app.config["PLAYGROUND_ATTACKER_RUN"] = attacker_run

    app = current_app._get_current_object()
    socketio = app.extensions.get("socketio")
    if socketio is None:
        _finish_attacker_run(app, attacker_run, status="failed", error=_("SocketIO no está disponible."))
        flash(
            _("No se pudo iniciar la tarea de atacante porque SocketIO no está disponible."),
            "error",
        )
        return redirect(url_for("playground.attacker_view", operation_id=operation_id))
    socketio.start_background_task(_run_attacker_in_background, app, session, config, attacker_run)
    flash(
        _(
            "Atacante iniciado en segundo plano. Las fases MITRE aparecerán en vivo en la vista Defensor."
        ),
        "success",
    )
    return redirect(url_for("playground.attacker_view", operation_id=operation_id))


@playground_bp.route("/<operation_id>/defender")
def defender_view(operation_id: str):
    operation = _get_operation_or_404(operation_id)
    collector = current_app.config["TELEMETRY_COLLECTOR"]
    session = current_app.config["PLAYGROUND_SESSIONS"].get(operation_id)
    if current_app.config["OPERATION_EXECUTOR"].managed(operation_id):
        session = None

    # Gap real cerrado tras la verificacion manual de M5 (ver
    # docs/roadmap.md y session.py): sin esto, la vista de defensor
    # nunca tenia ninguna via para la telemetria indexada por Filebeat
    # (ssh_honeypot/frontend/backend/mysql) -- solo el contenedor
    # atacante llegaba a esta vista. Envuelto en try/except: una falla
    # transitoria de Elasticsearch (stack recien arrancado, ES todavia
    # no healthy) no debe tirar abajo la pagina, misma logica que ya
    # usan start()/stop() con PlaygroundError.
    if session is not None:
        try:
            session.fetch_elastic_events(elastic_url=current_app.config["APATE_ELASTIC_URL"])
        except PlaygroundError as exc:
            flash(_("No se pudo consultar Elasticsearch: %(error)s", error=exc), "error")

    # M14f: comparacion esperado-vs-observado, independiente de si hay
    # una PlaygroundSession activa en memoria para esta operacion (esa
    # es la fuente de `history`, mas abajo) -- generate_report() solo
    # depende de TELEMETRY_COLLECTOR, ya persistido via M4.
    operation_report = generate_report(operation, collector)

    # M14g: cobertura del escenario fijo del Playground, distinta de
    # matched_ttps/ttps_not_observed de generate_report() -- esto no es
    # "que se observo en esta corrida", es "que puede llegar a
    # observarse en esta corrida" (el escenario fijo "Andesfinance" solo
    # puede producir 9 tecnicas reales, ver
    # apate.playground.scenario_ttps). Una por cada Scenario vinculado
    # a la operacion, no una sola cobertura global.
    scenario_ttp_coverage = [
        (scenario, match_scenario_ttps(scenario.related_ttps)) for scenario in operation.scenarios
    ]

    return render_template(
        "playground/defender.html",
        operation=operation,
        events=collector.list_events(operation_id),
        iocs=collector.list_iocs(operation_id),
        ttps=collector.list_ttps(operation_id),
        history=current_app.config["RULE_DECISION_REPOSITORY"].list_firings_for_operation(operation_id),
        rejected_actions=current_app.config["RULE_DECISION_REPOSITORY"].list_rejections_for_operation(operation_id),
        ttp_heatmap=_ttp_heatmap(operation_report),
        get_engage_activity=_get_engage_activity,
        scenario_ttp_coverage=scenario_ttp_coverage,
    )


def _start_session(operation: Operation) -> None:
    sessions = current_app.config["PLAYGROUND_SESSIONS"]
    telemetry = current_app.config["TELEMETRY_COLLECTOR"]
    rules_path = current_app.config["APATE_RULES_PATH"]
    rules = parse_rules(rules_path.read_text(encoding="utf-8"))
    session = PlaygroundSession.create(
        operation=operation,
        rules=rules,
        telemetry=telemetry,
        decision_repository=current_app.config["RULE_DECISION_REPOSITORY"],
        operation_executor=current_app.config["OPERATION_EXECUTOR"],
    )
    sessions[operation.id] = session

    # M13f: notificaciones en tiempo real -- ver docstring del modulo.
    # current_app.extensions['socketio'] existe siempre desde este hito
    # (apate.web.create_app(), incondicional), pero el `.get()` defensivo
    # se mantiene por si algun dia deja de serlo; sin socketio, el
    # Playground sigue funcionando igual, solo sin push en vivo.
    socketio = current_app.extensions.get("socketio")
    if socketio is not None:
        notify = _make_playground_notifier(socketio, operation.id, session.engine)
        session.bus.subscribe(EventType.INTERACTION, notify)
        session.bus.subscribe(EventType.TTP_OBSERVED, notify)


def _make_playground_notifier(socketio, operation_id: str, engine: RuleEngine):
    """Arma el handler de `EventBus` que emite la notificacion en vivo
    (M13f) -- `socketio`/`operation_id`/`engine` se capturan por
    clausura en vez de leerse de `current_app` dentro del handler en
    si: el handler puede terminar disparandose fuera de un contexto de
    request/app real (por ejemplo, si en el futuro algo alimenta el
    bus desde un hilo de fondo en vez de una vista HTTP), y
    `socketio.emit()` (el metodo de instancia, a diferencia de
    `flask_socketio.emit()`) esta pensado justo para eso -- no depende
    de un request activo.

    El namespace (`_NOTIFICATIONS_NAMESPACE`) es propio de APATE, no
    el que ya usa DOLOS-T. `triggered_rules` se calcula cruzando
    `RuleFiring.triggering_event_id` contra el `id` del evento
    entrante -- el `RuleEngine` ya esta suscripto al mismo bus *antes*
    que este handler (se suscribe en `PlaygroundSession.create()`,
    llamado antes de que `_start_session()` agregue este handler), asi
    que `EventBus.publish()` -- que llama a los handlers en el orden
    en que se suscribieron -- garantiza que `engine.history` ya
    refleja cualquier disparo de este evento puntual para cuando este
    handler corre; no se reimplementa la logica de disparo del motor,
    solo se lee su resultado ya calculado."""

    def _notify(event: PluginEvent) -> None:
        triggered_rules = [
            firing.rule_name for firing in engine.history if firing.triggering_event_id == event.id
        ]
        socketio.emit(
            "playground_event",
            {
                "operation_id": operation_id,
                "event_type": event.event_type.value,
                "plugin_id": event.plugin_id,
                "ttp_id": event.payload.get("ttp_id"),
                "detail": event.payload.get("detail"),
                "timestamp": event.timestamp.isoformat(),
                "triggered_rules": triggered_rules,
            },
            namespace=_NOTIFICATIONS_NAMESPACE,
        )

    return _notify


def _run_attacker_in_background(app, session: PlaygroundSession, config: PlaygroundConfig, attacker_run: dict) -> None:
    """Ejecuta el stream sin depender de un contexto de request de Flask."""

    def _ingest_line(line: str) -> None:
        _record_attacker_events(app, attacker_run, session.bridge.ingest_attacker_output_line(line))

    try:
        run_attacker_script_streaming(config, _ingest_line)
        _record_attacker_events(app, attacker_run, session.bridge.finish_attacker_output_stream())
    except PlaygroundError as exc:
        _finish_attacker_run(app, attacker_run, status="failed", error=str(exc))
    except Exception as exc:  # la tarea no debe dejar el candado en estado "running"
        _finish_attacker_run(app, attacker_run, status="failed", error=f"{type(exc).__name__}: {exc}")
    else:
        _finish_attacker_run(app, attacker_run, status="completed")


def _record_attacker_events(app, attacker_run: dict, events: list[PluginEvent]) -> None:
    if not events:
        return
    with app.config["PLAYGROUND_ATTACKER_LOCK"]:
        attacker_run["phases"].extend(event.payload["ttp_id"] for event in events)


def _finish_attacker_run(app, attacker_run: dict, *, status: str, error: str | None = None) -> None:
    with app.config["PLAYGROUND_ATTACKER_LOCK"]:
        attacker_run["status"] = status
        attacker_run["finished_at"] = datetime.now(timezone.utc)
        attacker_run["error"] = error


def _resolve_config() -> PlaygroundConfig:
    configured = current_app.config.get("APATE_PLAYGROUND_PATH")
    if configured is None:
        raise PlaygroundConfigError(
            _(
                "No hay ninguna ruta configurada hacia un checkout local del repositorio Cyber Deception Playground. Definir la variable de entorno APATE_PLAYGROUND_PATH antes de iniciar el servidor (ver README.md)."
            )
        )
    return PlaygroundConfig.from_path(configured)


def _get_operation_or_404(operation_id: str) -> Operation:
    repo = current_app.config["OPERATION_REPOSITORY"]
    try:
        return repo.get(operation_id)
    except OperationNotFoundError:
        abort(404)
