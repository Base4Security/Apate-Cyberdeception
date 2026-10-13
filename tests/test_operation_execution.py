"""K1/K2: efectos reales locales, carreras y recuperación sin repetir a ciegas."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import os
import subprocess
import sys
import threading

from cryptography.fernet import Fernet
import pytest

from apate.core import AdversaryProfile, ClosureCriteria, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.deployment import DeploymentService, DeploymentTarget, FilesystemHoneyfileConnector
from apate.deployment.repository import JSONFileDeploymentRepository
from apate.ledger import ExecutionPrincipal, LedgerError, OperationExecutor, OperationPlanService, RecordDraft, SQLiteOperationLedger
from apate.ledger.plugins import approved_plugins
from apate.plugins import EventBus, EventType, PluginEvent
from apate.rules import parse_rules
from apate.rules.engine import RuleEngine
from apate.rules.models import Condition
from apate.secrets import EncryptedJSONFileOperationRepository, SecretCipher


def policy(operation_id, *, limit=3, attempts=2, autonomous=True):
    return {"contract": 1, "budget_window": operation_id, "modification_limit": limit,
        "max_attempts": attempts, "autonomous": autonomous, "query_limit": 1000, "query_autonomous": True}


def activate(service, operation_id, *, execution_policy=None, parent=None, dispositions=None):
    ledger = service.ledger
    plan = service.propose(operation_id, parent_id=parent, reason="Diseño verificable", actor="autor",
        execution_policy=execution_policy or policy(operation_id), dispositions=dispositions)
    ledger.approve(operation_id, plan["id"], expected_digest=plan["digest"], actor="revisor")
    ledger.activate(operation_id, plan["id"], expected_digest=plan["digest"], actor="operador")
    return plan


@pytest.fixture
def setup(tmp_path):
    directory = tmp_path / "data"
    directory.mkdir()
    key = Fernet.generate_key()
    (directory / "secret_encryption.key").write_bytes(key)
    cipher = SecretCipher(key)
    repo = EncryptedJSONFileOperationRepository(directory / "operations", cipher)
    operation = Operation(name="K1/K2", adversary_profile=AdversaryProfile("Hipótesis"),
        narrative=Narrative("Historia"), roe=RulesOfEngagement(), team_id="soc")
    operation.bind_plugin(PluginBinding("p1", "network", plugin_kind="mock"))
    operation.bind_plugin(PluginBinding("p2", "network", plugin_kind="mock"))
    repo.save(operation)
    rules = directory / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    ledger = SQLiteOperationLedger(directory / "operation_ledger.db", cipher)
    deployments = JSONFileDeploymentRepository(directory / "deployments")
    service = OperationPlanService(ledger, repo, rules, deployments=deployments)
    service.adopt(operation.id, actor="admin")
    executor = OperationExecutor(ledger, lambda op: ExecutionPrincipal("admin", frozenset({op}), administrator=True))
    return operation, service, executor


def admit(executor, operation, plan, *, capability="p1", key="intención-1", action="deploy", **kwargs):
    return executor.admit(operation.id, expected_plan_id=plan["id"], capability_id=capability,
        action=action, idempotency_key=key, **kwargs)


def test_k1_preserva_decision_orden_reserva_y_configuracion(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    parameters = {"input": ["aprobado"]}
    command = admit(executor, operation, plan, parameters=parameters)
    parameters["input"].append("mutado")
    assert executor.ledger.record(operation.id, command["id"])["payload"]["parameters"] == {"input": ["aprobado"]}
    assert [r["kind"] for r in executor.ledger.history(operation.id)][-2:] == ["decision", "command"]
    assert executor.status(operation.id)["reserved_modifications"] == 1


def test_fallo_de_persistencia_no_deja_decision_ni_reserva_parcial(setup, monkeypatch):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    original = executor.ledger._insert
    def fail(connection, operation_id, draft, actor):
        if draft.kind == "command":
            raise OSError("Disco no disponible")
        return original(connection, operation_id, draft, actor)
    monkeypatch.setattr(executor.ledger, "_insert", fail)
    effects = []
    with pytest.raises(OSError):
        executor.run(operation.id, expected_plan_id=plan["id"], capability_id="p1", action="deploy", idempotency_key="a", callback=lambda: effects.append(1))
    assert effects == []
    assert not [r for r in executor.ledger.history(operation.id) if r["kind"] in {"decision", "command", "attempt"}]


def test_carrera_por_ultima_unidad_de_presupuesto(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id, execution_policy=policy(operation.id, limit=1))
    barrier = threading.Barrier(2)
    def race(capability):
        barrier.wait()
        try:
            return admit(executor, operation, plan, capability=capability, key=capability)["id"]
        except LedgerError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(race, ("p1", "p2")))
    assert outcomes.count("admission_budget") == 1
    assert executor.status(operation.id)["reserved_modifications"] == 1
    assert len([r for r in executor.ledger.history(operation.id) if r["kind"] == "decision" and r["payload"]["outcome"] == "rejected"]) == 1


@pytest.mark.parametrize("invalid", [True, -1, 1.5, "1", None])
def test_presupuesto_invalido_no_es_aprobable(setup, invalid):
    operation, service, _ = setup
    with pytest.raises(LedgerError, match="invalid_modification_limit"):
        activate(service, operation.id, execution_policy=policy(operation.id, limit=invalid))


def test_idempotencia_no_crea_segunda_reserva_ni_segundo_efecto(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    first = admit(executor, operation, plan)
    assert admit(executor, operation, plan)["id"] == first["id"]
    effects = []
    executor.invoke(operation.id, first, lambda: effects.append(1))
    with pytest.raises(LedgerError, match="already_disposed"):
        executor.invoke(operation.id, first, lambda: effects.append(2))
    assert effects == [1]
    with pytest.raises(LedgerError, match="idempotency_conflict"):
        admit(executor, operation, plan, action="rotate")


def test_dos_claims_simultaneos_solo_invocan_una_vez(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    barrier = threading.Barrier(2)
    def claim(_):
        barrier.wait()
        try:
            return executor.claim(operation.id, command["id"])["id"]
        except LedgerError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, range(2)))
    assert results.count("explicit_retry_required") == 1
    assert executor.status(operation.id)["pending"][0]["attempts"] == 1


def test_parada_antes_de_claim_cancela_orden_sin_reembolso(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    state = executor.ledger.operation(operation.id)
    executor.ledger.stop(operation.id, target="paused", expected_revision=state["revision"], reason="Freno", actor="admin")
    with pytest.raises(LedgerError, match="already_disposed"):
        executor.claim(operation.id, command["id"])
    assert executor.status(operation.id)["reserved_modifications"] == 1
    assert executor.status(operation.id)["pending"] == []
    with pytest.raises(LedgerError, match="admission_state"):
        admit(executor, operation, plan, capability="p2", key="después")


def test_claim_previo_puede_retornar_despues_de_parada_pero_no_se_reclama_otro(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    claimed = threading.Event()
    finish = threading.Event()
    effects = []
    def external():
        claimed.set()
        assert finish.wait(5)
        effects.append("respuesta remota posterior")
    with ThreadPoolExecutor(max_workers=1) as pool:
        worker = pool.submit(executor.invoke, operation.id, command, external)
        assert claimed.wait(5)
        state = executor.ledger.operation(operation.id)
        executor.ledger.stop(operation.id, target="closing", expected_revision=state["revision"], reason="Freno", actor="admin")
        with pytest.raises(LedgerError, match="admission_state"):
            admit(executor, operation, plan, capability="p2", key="prohibida")
        finish.set()
        worker.result(timeout=5)
    assert effects == ["respuesta remota posterior"]
    assert executor.ledger.operation(operation.id)["state"] == "closing"


def test_caida_real_despues_de_claim_consume_intento_y_no_repite(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    script = """
import os, sys
from apate.ledger import OperationPlanService, OperationExecutor, ExecutionPrincipal
s=OperationPlanService.from_data_dir(sys.argv[1], sys.argv[2])
e=OperationExecutor(s.ledger, lambda op: ExecutionPrincipal('admin', frozenset({op}), administrator=True))
e.claim(sys.argv[3], sys.argv[4])
os._exit(23)
"""
    result = subprocess.run([sys.executable, "-c", script, str(service.ledger.path.parent), str(service.rules_path), operation.id, command["id"]], capture_output=True, timeout=20)
    assert result.returncode == 23, result.stderr.decode()
    restarted = OperationExecutor(SQLiteOperationLedger(executor.ledger.path, executor.ledger.cipher), executor.authorize)
    with pytest.raises(LedgerError, match="reconciliation_required"):
        restarted.claim(operation.id, command["id"], retry=True, reconciliation_note="Reinicio")
    assert restarted.status(operation.id)["pending"][0]["attempts"] == 1


@pytest.mark.parametrize("cut", ["before_claim", "after_claim", "after_effect", "after_receipt"])
def test_cortes_de_proceso_alrededor_del_efecto_no_reintentan_a_ciegas(setup, tmp_path, cut):
    """El corte es un proceso terminado, no una excepción atrapada por Python."""
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    marker = tmp_path / "efecto.txt"
    script = """
import os, pathlib, sys
from apate.ledger import OperationPlanService, OperationExecutor, ExecutionPrincipal
s=OperationPlanService.from_data_dir(sys.argv[1], sys.argv[2])
e=OperationExecutor(s.ledger, lambda op: ExecutionPrincipal('admin', frozenset({op}), administrator=True))
operation_id, command_id, cut, marker = sys.argv[3:]
if cut == 'before_claim':
    os._exit(27)
attempt=e.claim(operation_id, command_id)
if cut == 'after_claim':
    os._exit(27)
pathlib.Path(marker).write_text('efecto-uno', encoding='utf-8')
if cut == 'after_effect':
    os._exit(27)
e.finish(operation_id, attempt['id'], outcome='accepted')
os._exit(27)
"""
    result = subprocess.run([sys.executable, "-c", script, str(service.ledger.path.parent),
        str(service.rules_path), operation.id, command["id"], cut, str(marker)],
        capture_output=True, timeout=20)
    assert result.returncode == 27, result.stderr.decode()
    restarted = OperationExecutor(SQLiteOperationLedger(executor.ledger.path, executor.ledger.cipher), executor.authorize)
    status = restarted.status(operation.id)

    if cut == "before_claim":
        assert status["pending"][0]["attempts"] == 0
        restarted.invoke(operation.id, command, lambda: marker.write_text("efecto-uno", encoding="utf-8"))
    elif cut == "after_receipt":
        assert status["pending"] == []
        with pytest.raises(LedgerError, match="already_disposed"):
            restarted.invoke(operation.id, command, lambda: marker.write_text("efecto-dos", encoding="utf-8"))
    else:
        assert status["pending"][0]["attempts"] == 1
        with pytest.raises(LedgerError, match="reconciliation_required"):
            restarted.invoke(operation.id, command, lambda: marker.write_text("efecto-dos", encoding="utf-8"),
                             retry=True, reconciliation_note="Reinicio")
    if cut == "after_claim":
        assert not marker.exists()
    else:
        assert marker.read_text(encoding="utf-8") == "efecto-uno"


def test_caida_despues_de_reserva_k1_conserva_clave_e_intento_cero(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    script = """
import os, sys
from apate.ledger import OperationPlanService, OperationExecutor, ExecutionPrincipal
s=OperationPlanService.from_data_dir(sys.argv[1], sys.argv[2])
e=OperationExecutor(s.ledger, lambda op: ExecutionPrincipal('admin', frozenset({op}), administrator=True))
e.admit(sys.argv[3], expected_plan_id=sys.argv[4], capability_id='p1', action='deploy', idempotency_key='corte-k1')
os._exit(27)
"""
    result = subprocess.run([sys.executable, "-c", script, str(service.ledger.path.parent),
        str(service.rules_path), operation.id, plan["id"]], capture_output=True, timeout=20)
    assert result.returncode == 27, result.stderr.decode()
    restarted = OperationExecutor(SQLiteOperationLedger(executor.ledger.path, executor.ledger.cipher), executor.authorize)
    command = admit(restarted, operation, plan, key="corte-k1")
    assert restarted.status(operation.id)["pending"][0]["attempts"] == 0
    assert restarted.claim(operation.id, command["id"])["payload"]["number"] == 1


def test_error_externo_es_desconocido_hasta_conciliacion_y_maximo_no_se_resetea(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    def fail():
        raise TimeoutError("Puede haber efecto")
    with pytest.raises(TimeoutError):
        executor.invoke(operation.id, command, fail)
    assert executor.ledger.history(operation.id)[-1]["payload"]["outcome"] == "unknown"
    with pytest.raises(LedgerError, match="reconciliation_required"):
        executor.invoke(operation.id, command, fail, retry=True, reconciliation_note="Timeout")
    with pytest.raises(LedgerError, match="executor_quiescence_required"):
        executor.reconcile_failed(operation.id, command["id"], reason="Comprobado", executor_quiescent=False)
    executor.reconcile_failed(operation.id, command["id"], reason="Worker detenido y recurso conciliado", executor_quiescent=True)
    with pytest.raises(TimeoutError):
        executor.invoke(operation.id, command, fail, retry=True, reconciliation_note="Reintento explícito")
    executor.reconcile_failed(operation.id, command["id"], reason="Comprobado de nuevo", executor_quiescent=True)
    with pytest.raises(LedgerError, match="attempt_limit"):
        executor.claim(operation.id, command["id"], retry=True, reconciliation_note="Tercero")
    assert executor.status(operation.id)["reserved_modifications"] == 1
    assert executor.status(operation.id)["pending"][0]["attempts"] == 2


def test_fallo_de_recibo_deja_intento_desconocido_sin_repeticion(setup, monkeypatch):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    effects = []
    monkeypatch.setattr(executor, "finish", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("Disco")))
    with pytest.raises(OSError):
        executor.invoke(operation.id, command, lambda: effects.append(1))
    assert effects == [1]
    with pytest.raises(LedgerError, match="reconciliation_required"):
        executor.claim(operation.id, command["id"], retry=True, reconciliation_note="Reintento")


def test_revision_no_reembolsa_ni_cambia_ventana(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id, execution_policy=policy(operation.id, limit=1))
    command = admit(executor, operation, plan)
    next_plan = activate(service, operation.id, execution_policy=policy(operation.id, limit=1), parent=plan["id"], dispositions={command["id"]: "cancel"})
    with pytest.raises(LedgerError, match="admission_budget"):
        admit(executor, operation, next_plan, capability="p2", key="nueva")
    with pytest.raises(LedgerError, match="budget_window_immutable"):
        activate(service, operation.id, execution_policy=policy(operation.id, limit=2), parent=next_plan["id"])
    assert executor.ledger.operation(operation.id)["active_plan_id"] == next_plan["id"]


def test_revision_no_cancela_claim_incierto_y_no_reclama_version_obsoleta(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    executor.claim(operation.id, command["id"])
    with pytest.raises(LedgerError, match="claimed_command_requires_reconciliation"):
        activate(service, operation.id, parent=plan["id"], dispositions={command["id"]: "cancel"})
    activate(service, operation.id, parent=plan["id"], dispositions={command["id"]: "wait"})
    with pytest.raises(LedgerError, match="stale_command_version"):
        executor.claim(operation.id, command["id"], retry=True, reconciliation_note="Cambio")


@pytest.mark.parametrize("autonomous", [False, True])
def test_roe_igual_manual_y_automatica_con_rechazo_durable(setup, autonomous):
    operation, service, executor = setup
    operation.roe.forbidden_actions = ["deploy:p1"]
    service.operations.save(operation)
    plan = activate(service, operation.id)
    executor.authorize = lambda op: ExecutionPrincipal("system:rules" if autonomous else "admin", frozenset({op}), administrator=not autonomous, autonomous=autonomous)
    with pytest.raises(LedgerError, match="admission_roe"):
        admit(executor, operation, plan)
    decision = executor.ledger.history(operation.id)[-1]
    assert decision["kind"] == "decision" and decision["payload"]["guards"]["roe"] is False
    assert executor.status(operation.id)["reserved_modifications"] == 0


@pytest.mark.parametrize("principal,code", [
    (ExecutionPrincipal("intruso", frozenset()), "identity_scope"),
    (ExecutionPrincipal("otro equipo", frozenset({"placeholder"}), team_id="otro"), "identity_team"),
    (None, "authenticated_principal_required"),
])
def test_identidad_alcance_y_equipo_en_k1(setup, principal, code):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    if principal and principal.team_id:
        principal = ExecutionPrincipal(principal.actor, frozenset({operation.id}), team_id=principal.team_id)
    executor.authorize = lambda op: principal
    with pytest.raises(LedgerError, match=code):
        admit(executor, operation, plan)


def test_k2_revalida_identidad(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    command = admit(executor, operation, plan)
    executor.authorize = lambda op: None
    with pytest.raises(LedgerError, match="authenticated_principal_required"):
        executor.claim(operation.id, command["id"])
    assert executor.status(operation.id)["pending"][0]["attempts"] == 0


def test_scope_de_maquina_no_otorga_conciliacion_administrativa(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    executor.authorize = lambda op: ExecutionPrincipal("machine:token", frozenset({op}), machine=True)
    command = admit(executor, operation, plan)
    executor.claim(operation.id, command["id"])
    with pytest.raises(LedgerError, match="administrator_required"):
        executor.abandon(operation.id, command["id"], reason="No autorizado")
    with pytest.raises(LedgerError, match="administrator_required"):
        executor.reconcile_failed(operation.id, command["id"], reason="No autorizado", executor_quiescent=True)


def test_capacidad_observada_no_recibe_orden(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    with pytest.raises(LedgerError, match="admission_controlled"):
        admit(executor, operation, plan, capability="fuente_observada")


def test_evento_de_otra_operacion_no_dispara_parada_o_respuesta(setup):
    operation, service, executor = setup
    activate(service, operation.id)
    event = PluginEvent(event_type=EventType.INTERACTION, plugin_id="sensor", surface="network", operation_id="otra", payload={})
    with pytest.raises(LedgerError, match="cross_operation_event"):
        executor.observe(operation.id, event)
    assert executor.ledger.operation(operation.id)["state"] == "active"


def test_append_no_puede_fabricar_autorizacion_b(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    with pytest.raises(LedgerError, match="execution_service_required"):
        executor.ledger.append(operation.id, [RecordDraft("decision", {}, plan["id"])], actor="manual")


def test_vencimiento_se_confirma_antes_de_admitir_efectos(setup):
    operation, service, executor = setup
    operation.closure_criteria.end_date = datetime.now(timezone.utc) - timedelta(seconds=1)
    service.operations.save(operation)
    plan = activate(service, operation.id)
    with pytest.raises(LedgerError, match="admission_state"):
        admit(executor, operation, plan)
    assert executor.ledger.operation(operation.id)["state"] == "closing"
    assert executor.status(operation.id)["reserved_modifications"] == 0


def test_criterio_del_evento_precede_a_regla_y_no_depende_de_roe(setup):
    operation, service, executor = setup
    operation.roe.forbidden_actions = ["transition:closed"]
    operation.closure_criteria = ClosureCriteria(trigger_conditions=[Condition(event_type=EventType.INTERACTION, payload={"kind": "peligro"})])
    service.operations.save(operation)
    rules = "rules:\n  - name: respuesta\n    when:\n      event_type: interaction\n      payload: {kind: peligro}\n    then:\n      - action: deploy\n        plugin_id: p1\n"
    service.rules_path.write_text(rules, encoding="utf-8")
    plan = activate(service, operation.id)
    bus = EventBus()
    plugins = approved_plugins(executor, operation.id, bus)
    engine = RuleEngine(operation=operation, plugins=plugins, bus=bus, rules=parse_rules(rules), operation_executor=executor, approved_plan_id=plan["id"])
    bus.publish(PluginEvent(event_type=EventType.INTERACTION, plugin_id="p2", surface="network", operation_id=operation.id, payload={"kind": "peligro"}))
    assert executor.ledger.operation(operation.id)["state"] == "closing"
    assert executor.status(operation.id)["reserved_modifications"] == 0 and engine.history == []


def test_guardas_no_autorizan_autonomia_implicita(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id, execution_policy=policy(operation.id, autonomous=False))
    executor.authorize = lambda op: ExecutionPrincipal("system:rules", frozenset({op}), autonomous=True)
    with pytest.raises(LedgerError, match="autonomous_not_approved"):
        admit(executor, operation, plan)


def test_plugins_usan_plan_congelado_y_recibo_en_vez_del_editor(setup, tmp_path):
    operation, service, executor = setup
    protected = tmp_path / "aprobado"
    protected.mkdir()
    unapproved = tmp_path / "borrador"
    unapproved.mkdir()
    operation.plugins = [PluginBinding("file", "data", plugin_kind="honeytoken", config={"directory": str(protected), "filenames": ["secret.txt"]})]
    service.operations.save(operation)
    plan = activate(service, operation.id)
    operation.plugins[0].config["directory"] = str(unapproved)
    service.operations.save(operation)
    bus = EventBus()
    plugin = approved_plugins(executor, operation.id, bus)["file"]
    plugin.deploy()
    assert (protected / "secret.txt").is_file() and not (unapproved / "secret.txt").exists()
    state = executor.ledger.operation(operation.id)
    executor.ledger.stop(operation.id, target="paused", expected_revision=state["revision"], reason="Freno", actor="admin")
    restored = approved_plugins(executor, operation.id, EventBus())["file"]
    restored.retire()
    assert not (protected / "secret.txt").exists()
    records = executor.ledger.history(operation.id)
    assert [r["payload"]["purpose"] for r in records if r["kind"] == "command"] == ["ordinary", "cleanup"]
    assert all(r["payload"]["outcome"] == "accepted" for r in records if r["kind"] == "receipt")


@pytest.mark.parametrize("paused", [False, True])
def test_observacion_honeytoken_no_rearma_ni_gasta_modificaciones(setup, tmp_path, monkeypatch, paused):
    from apate.plugins.honeytoken import HoneytokenPlugin
    operation, service, executor = setup
    root = tmp_path / "observado"
    root.mkdir()
    operation.plugins = [PluginBinding("file", "data", plugin_kind="honeytoken", config={"directory": str(root), "filenames": ["secret.txt"]})]
    service.operations.save(operation)
    activate(service, operation.id)
    plugin = approved_plugins(executor, operation.id, EventBus())["file"]
    plugin.deploy()
    target = root / "secret.txt"
    stamp = target.stat()
    os.utime(target, (stamp.st_mtime + 5, stamp.st_mtime))
    before = target.stat()
    if paused:
        state = executor.ledger.operation(operation.id)
        executor.ledger.stop(operation.id, target="paused", expected_revision=state["revision"], reason="Observar", actor="admin")
    def forbidden_rearm(*args, **kwargs):
        raise AssertionError("Una observación no debe escribir")
    monkeypatch.setattr(HoneytokenPlugin, "_arm", forbidden_rearm)
    plugin.check_access()
    after = target.stat()
    assert before.st_mtime_ns == after.st_mtime_ns
    assert executor.status(operation.id)["reserved_modifications"] == 1


def test_despliegue_filesystem_congelado_no_toca_destino_editado(setup, tmp_path):
    operation, service, executor = setup
    root = tmp_path / "share"
    root.mkdir()
    connector = FilesystemHoneyfileConnector(tmp_path / "receipts")
    control = DeploymentService(repository=service.deployments, connectors={connector.kind: connector}, operation_executor=executor)
    target = DeploymentTarget("Share", connector.kind, str(root))
    deploy_plan = control.prepare(operation_id=operation.id, plugin_id="p1", target=target, configuration={"relative_path": "secret.txt", "content": "señuelo", "rotation_content": "renovado"})
    activate(service, operation.id)
    changed = service.deployments.get_plan(deploy_plan.id)
    changed.parameters["relative_path"] = "otro.txt"
    service.deployments.save_plan(changed)
    with pytest.raises(LedgerError, match="approved_deployment_plan_required"):
        control.execute(deploy_plan.id)
    assert list(root.iterdir()) == []
    service.deployments.save_plan(deploy_plan)
    record = control.execute(deploy_plan.id)
    assert (root / "secret.txt").read_text(encoding="utf-8") == "señuelo"
    # El recibo editado tampoco puede cambiar la identidad de un recurso.
    changed_record = service.deployments.get_record(record.id)
    changed_record.external_resource_ids = [str(root / "otro.txt")]
    service.deployments.save_record(changed_record)
    control.rotate(record.id)
    assert (root / "secret.txt").read_text(encoding="utf-8") == "renovado"
    state = executor.ledger.operation(operation.id)
    executor.ledger.stop(operation.id, target="closing", expected_revision=state["revision"], reason="Retiro", actor="admin")
    control.retire(record.id)
    assert list(root.iterdir()) == []
    assert executor.status(operation.id)["reserved_modifications"] == 3


def web_operation(app, client, tmp_path, *, authenticated=True):
    operation = Operation(name="HTTP trazable", adversary_profile=AdversaryProfile("Hipótesis"), narrative=Narrative("H"), roe=RulesOfEngagement(), team_id="soc")
    root = tmp_path / "destino"
    root.mkdir()
    operation.bind_plugin(PluginBinding("file", "data", plugin_kind="honeytoken", config={"directory": str(root), "filenames": ["secret.txt"]}))
    app.config["OPERATION_REPOSITORY"].save(operation)
    app.config["APATE_RULES_PATH"].write_text("rules: []\n", encoding="utf-8")
    if authenticated:
        app.config["IDENTITY_PROVIDER"].create("Admin", "Clave-de-prueba")
        assert client.post("/login", data={"display_name": "Admin", "password": "Clave-de-prueba"}).status_code == 302
    service = app.config["OPERATION_PLAN_SERVICE"]
    service.adopt(operation.id, actor="admin")
    return operation, root, service


def test_http_abierto_no_equivale_a_identidad_autorizada(app, client, tmp_path):
    operation, root, service = web_operation(app, client, tmp_path, authenticated=False)
    activate(service, operation.id)
    response = client.post(f"/operations/{operation.id}/plugins/file/honeytoken/deploy")
    assert response.status_code == 409 and response.json["error"] == "authenticated_principal_required"
    assert list(root.iterdir()) == []


def test_http_manual_usa_k1_k2_y_parada_admite_solo_retiro(app, client, tmp_path):
    operation, root, service = web_operation(app, client, tmp_path)
    activate(service, operation.id)
    deployed = client.post(f"/operations/{operation.id}/plugins/file/honeytoken/deploy")
    assert deployed.status_code == 302 and (root / "secret.txt").is_file()
    executor = app.config["OPERATION_EXECUTOR"]
    state = executor.ledger.operation(operation.id)
    assert client.post(f"/operations/{operation.id}/control/stop", json={"target": "paused", "revision": state["revision"], "reason": "Freno"}).status_code == 200
    blocked = client.post(f"/operations/{operation.id}/plugins/file/honeytoken/rotate")
    assert blocked.status_code == 302
    assert service.ledger.history(operation.id)[-1]["payload"]["reason"] == "state"
    retired = client.post(f"/operations/{operation.id}/plugins/file/honeytoken/retire")
    assert retired.status_code == 302 and not (root / "secret.txt").exists()
    assert executor.status(operation.id)["reserved_modifications"] == 2


@pytest.mark.parametrize("route", ["dolost/deploy", "dolost/rotate", "dolost/retire", "dolost/decoys/test/deploy", "dolost/decoys/test/undeploy", "dolost/decoys/test/start", "dolost/decoys/test/stop", "buda/start", "buda/stop", "opencanary/deploy", "opencanary/rotate", "opencanary/retire"])
def test_http_subacciones_sin_adaptador_no_eluden_admision(app, client, tmp_path, route):
    operation, root, service = web_operation(app, client, tmp_path)
    activate(service, operation.id)
    response = client.post(f"/operations/{operation.id}/plugins/file/{route}")
    assert response.status_code == 409 and response.json["error"] == "adapter_not_frozen"
    assert list(root.iterdir()) == []


@pytest.mark.parametrize("route", ["start", "stop", "attacker/run"])
def test_playground_adoptado_no_ejecuta_stack_o_scripts_sin_contrato(app, client, tmp_path, route):
    operation, _, service = web_operation(app, client, tmp_path)
    activate(service, operation.id)
    response = client.post(f"/playground/{operation.id}/{route}")
    assert response.status_code == 409 and response.json["error"] == "adapter_not_frozen"


def test_http_aprobacion_exacta_y_revision_stale(app, client, tmp_path):
    operation, _, service = web_operation(app, client, tmp_path)
    proposed = client.post(f"/operations/{operation.id}/control/propose", json={"reason": "Diseño", "execution_policy": policy(operation.id)})
    assert proposed.status_code == 201
    plan = proposed.json
    endpoint = f"/operations/{operation.id}/control/plans/{plan['plan_id']}"
    reviewed = client.get(endpoint)
    assert reviewed.status_code == 200 and reviewed.headers["Cache-Control"] == "no-store"
    wrong = client.post(endpoint + "/approve", json={"digest": "incorrecto"})
    assert wrong.status_code == 409 and wrong.json["error"] == "approval_digest_mismatch"
    assert client.post(endpoint + "/approve", json={"digest": plan["digest"]}).status_code == 200
    assert client.post(endpoint + "/activate", json={"digest": plan["digest"]}).status_code == 200
    state = service.ledger.operation(operation.id)
    assert client.post(f"/operations/{operation.id}/control/stop", json={"target": "paused", "revision": state["revision"] - 1, "reason": "Freno"}).json["error"] == "stale_revision"


def test_reglas_web_usan_yaml_y_plugins_aprobados_despues_de_editar_borrador(app, client, tmp_path):
    from apate.web._rule_engine_runtime import build_rule_engine
    operation, root, service = web_operation(app, client, tmp_path)
    from apate.core import ExternalTelemetrySource
    operation.telemetry_bridges.append(ExternalTelemetrySource("Sensor", "http://localhost:9200", "events", id="sensor"))
    service.operations.save(operation)
    service.rules_path.write_text("rules:\n  - name: respuesta\n    when:\n      event_type: interaction\n      plugin_id: sensor\n    then:\n      - action: deploy\n        plugin_id: file\n", encoding="utf-8")
    activate(service, operation.id)
    service.rules_path.write_text("rules: []\n", encoding="utf-8")
    changed = service.operations.get(operation.id)
    changed.plugins = []
    service.operations.save(changed)
    with app.app_context():
        bus = EventBus()
        engine = build_rule_engine(operation=changed, bus=bus, plugins={})
        bus.publish(PluginEvent(event_type=EventType.INTERACTION, plugin_id="sensor", surface="network", operation_id=operation.id, payload={}))
    assert (root / "secret.txt").is_file()
    commands = [r for r in service.ledger.history(operation.id) if r["kind"] == "command"]
    assert len(commands) == 1 and commands[0]["actor"] == "system:rules"
    assert engine.operation.find_plugin_binding("file") is not None
    assert service.operations.get(operation.id).plugins == []


def test_motor_en_memoria_previo_a_adopcion_no_sigue_controlando(setup):
    operation, service, executor = setup
    bus = EventBus()
    # Una sesión creada en modo heredado carece de ID de plan efectivo.
    engine = RuleEngine(operation=operation, plugins={}, bus=bus,
        rules=parse_rules("rules: []\n"), operation_executor=executor)
    activate(service, operation.id)
    bus.publish(PluginEvent(event_type=EventType.INTERACTION, plugin_id="sensor", surface="network", operation_id=operation.id, payload={}))
    assert engine.history == [] and executor.status(operation.id)["reserved_modifications"] == 0


def test_http_no_activa_plan_sin_politica_ni_transicion_heredada(app, client, tmp_path):
    operation, root, service = web_operation(app, client, tmp_path)
    old = service.propose(operation.id, parent_id=None, reason="Solo historia A", actor="admin")
    service.ledger.approve(operation.id, old["id"], expected_digest=old["digest"], actor="revisor")
    service.ledger.activate(operation.id, old["id"], expected_digest=old["digest"], actor="admin")
    assert client.post(f"/operations/{operation.id}/transition", data={"to": "active"}).json["error"] == "approved_activation_required"
    response = client.post(f"/operations/{operation.id}/plugins/file/honeytoken/deploy")
    assert response.status_code == 409 and response.json["error"] == "execution_policy_required"
    assert list(root.iterdir()) == []


def test_limite_cero_bloquea_incluso_si_roe_permite(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id, execution_policy=policy(operation.id, limit=0))
    with pytest.raises(LedgerError, match="admission_budget"):
        admit(executor, operation, plan)


def test_version_obsoleta_no_crea_orden_y_primera_reclamacion_requiere_k1(setup):
    operation, service, executor = setup
    plan = activate(service, operation.id)
    current = activate(service, operation.id, parent=plan["id"])
    with pytest.raises(LedgerError, match="admission_version"):
        admit(executor, operation, plan)
    with pytest.raises(LedgerError, match="invalid_reference"):
        executor.claim(operation.id, "orden-no-admitida")
    assert executor.status(operation.id)["reserved_modifications"] == 0
    assert service.ledger.operation(operation.id)["active_plan_id"] == current["id"]


def test_presupuesto_y_orden_sobreviven_backup_restauracion(setup, tmp_path):
    from apate.backup import create_backup, restore_backup
    operation, service, executor = setup
    plan = activate(service, operation.id, execution_policy=policy(operation.id, limit=1))
    command = admit(executor, operation, plan)
    executor.claim(operation.id, command["id"])
    snapshot = tmp_path / "copia"
    create_backup(service.ledger.path.parent, snapshot)
    restored = tmp_path / "restaurado"
    restore_backup(snapshot, restored)
    restored_service = OperationPlanService.from_data_dir(restored, service.rules_path)
    recovered = OperationExecutor(restored_service.ledger, executor.authorize)
    assert recovered.status(operation.id) == executor.status(operation.id)
    with pytest.raises(LedgerError, match="admission_budget"):
        admit(recovered, operation, plan, capability="p2", key="otra")


def test_api_ad_usa_guardas_presupuesto_y_credencial_congelada(app, client, tmp_path):
    from apate.deployment import ActiveDirectoryHoneyuserConnector, ActiveDirectoryUser
    operation, _, service = web_operation(app, client, tmp_path)
    credential_ref = "secret://ad/admin"
    store = app.config["DEPLOYMENT_CREDENTIAL_STORE"]
    store.save(credential_ref, {"username": "svc-original", "password": "original"})
    effects = []
    class Transport:
        def validate(self, target, credential, ou_dn):
            pass
        def find_user(self, target, credential, sam_account_name):
            return None
        def create_or_update_user(self, target, credential, parameters, password):
            effects.append((target.address, credential["username"], parameters["sam_account_name"]))
            return ActiveDirectoryUser(sid="S-1-5-21-1", distinguished_name="CN=Señuelo," + parameters["ou_dn"],
                sam_account_name=parameters["sam_account_name"], user_principal_name=parameters["user_principal_name"],
                description=parameters["management_marker"], enabled=True)
    connector = ActiveDirectoryHoneyuserConnector(credential_store=store, transport=Transport())
    control = DeploymentService(repository=service.deployments, connectors={connector.kind: connector}, operation_executor=app.config["OPERATION_EXECUTOR"])
    app.config["DEPLOYMENT_SERVICE"] = control
    target = DeploymentTarget("DC", connector.kind, "dc.original.test", credential_ref=credential_ref,
        config={"ou_allowlist": ["OU=Deception,DC=example,DC=test"], "allowed_upn_suffixes": ["example.test"]})
    deploy_plan = control.prepare(operation_id=operation.id, plugin_id="file", target=target,
        configuration={"sam_account_name": "honey.user", "display_name": "Honey User", "given_name": "Honey", "surname": "User",
            "ou_dn": "OU=Deception,DC=example,DC=test", "upn_suffix": "example.test"})
    activate(service, operation.id, execution_policy=policy(operation.id, limit=1))
    store.save(credential_ref, {"username": "svc-borrador", "password": "cambiada"})
    bearer = app.config["MACHINE_TOKEN_REPOSITORY"].create(name="API", scopes={"honeyuser:execute"}, operation_ids={operation.id}, expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    headers = {"Authorization": f"Bearer {bearer}", "Idempotency-Key": "crear-1"}
    endpoint = f"/api/v1/operations/{operation.id}/honeyusers/plans/{deploy_plan.id}/execute"
    result = client.post(endpoint, headers=headers, json={})
    assert result.status_code == 200, result.json
    assert client.post(endpoint, headers=headers, json={}).json == result.json
    assert effects == [("dc.original.test", "svc-original", "honey.user")]
    assert app.config["OPERATION_EXECUTOR"].status(operation.id)["reserved_modifications"] == 1
