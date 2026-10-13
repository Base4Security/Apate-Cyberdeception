"""Consultas, adopción y evidencia: fallas observables sobre registros durables."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import subprocess
import sys
import threading

import pytest

from apate.core import ExternalTelemetrySource, PluginBinding
from apate.ledger import ExecutionPrincipal, LedgerError, OperationExecutor, RecordDraft
from apate.ledger.adoption import AdoptionGate
from apate.ledger.evidence import EvidenceBus, OperationEvidence
from apate.ledger.plugins import approved_plugins
from apate.ledger.queries import OperationQueries
from apate.plugins import EventBus, EventType, PluginEvent
from tests.test_operation_execution import setup, activate, policy, web_operation


def prepare(setup, *, queries=10, auto=True):
    operation, service, executor = setup
    values = dict(policy(operation.id, limit=10), query_limit=queries, query_autonomous=auto)
    plan = activate(service, operation.id, execution_policy=values)
    return operation, service, executor, plan


def event(operation_id, *, source="p1", external="1", generation="boot-1", value="T1078"):
    return PluginEvent(EventType.TTP_OBSERVED, source, "network", operation_id,
        payload={"ttp_id": value}, provenance={"raw": {"ttp": value}, "external_id": external,
            "generation": generation, "origin_time": None, "transformation": "test-source-v1"})


def stop(executor, operation_id):
    state = executor.ledger.operation(operation_id)
    executor.ledger.stop(operation_id, target="closing", expected_revision=state["revision"], reason="Corte", actor="admin")


def close(executor, operation_id):
    stop(executor, operation_id)
    return OperationEvidence(executor.ledger).close(operation_id,
        expected_revision=executor.ledger.operation(operation_id)["revision"],
        criterion="Fin de ensayo", judgment="Juicio declarado, sin eficacia defensiva.", actor="admin")


def test_consultas_separadas_de_modificaciones_y_rechazo_durable(setup):
    operation, _, executor, _ = prepare(setup, queries=1)
    received = []
    executor.query(operation.id, "p1", lambda: received.append("lectura"))
    with pytest.raises(LedgerError, match="query_budget"):
        executor.query(operation.id, "p2", lambda: received.append("indebida"))
    assert received == ["lectura"]
    assert executor.status(operation.id)["reserved_modifications"] == 0
    assert OperationQueries(executor).status(operation.id)["reserved_queries"] == 1
    assert executor.ledger.history(operation.id)[-1]["payload"]["outcome"] == "rejected"


def test_ultima_consulta_serializada_entre_identidades(setup):
    operation, _, executor, _ = prepare(setup, queries=1)
    barrier = threading.Barrier(2)
    effects = []
    def run(name):
        local = OperationExecutor(executor.ledger, lambda op: ExecutionPrincipal(name, frozenset({op}), administrator=True))
        barrier.wait()
        try:
            local.query(operation.id, "p1", lambda: effects.append(name))
            return "accepted"
        except LedgerError as error:
            return error.code
    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(run, ["manual", "monitor"]))
    assert sorted(outcomes) == ["accepted", "query_budget"] and len(effects) == 1


def test_consulta_fallida_no_reembolsa_cupo_tras_reinicio(setup):
    operation, _, executor, _ = prepare(setup, queries=1)
    def fail():
        raise TimeoutError("secreto que no se debe registrar")
    with pytest.raises(TimeoutError):
        executor.query(operation.id, "p1", fail)
    restored = OperationExecutor(executor.ledger, executor.authorize)
    with pytest.raises(LedgerError, match="query_budget"):
        restored.query(operation.id, "p1", lambda: pytest.fail("replay"))
    body = json.dumps(executor.ledger.history(operation.id))
    assert "secreto que" not in body and "TimeoutError" in body


def test_caida_antes_de_recibo_de_consulta_conserva_reserva(setup, monkeypatch):
    operation, _, executor, _ = prepare(setup, queries=1)
    def fail(*args, **kwargs):
        raise OSError("fallo de disco")
    monkeypatch.setattr(OperationQueries, "_receipt", fail)
    invoked = []
    with pytest.raises(OSError):
        executor.query(operation.id, "p1", lambda: invoked.append(1))
    assert invoked == [1] and len(OperationQueries(executor).status(operation.id)["unknown_queries"]) == 1


def test_fallo_de_reserva_impide_consulta(setup, monkeypatch):
    operation, _, executor, _ = prepare(setup)
    original = executor.ledger._insert
    def insert(connection, op, draft, actor):
        if draft.payload.get("category") == "query_reservation":
            raise OSError("disco")
        return original(connection, op, draft, actor)
    monkeypatch.setattr(executor.ledger, "_insert", insert)
    with pytest.raises(OSError):
        executor.query(operation.id, "p1", lambda: pytest.fail("consulta sin compromiso"))
    assert OperationQueries(executor).status(operation.id)["reserved_queries"] == 0


@pytest.mark.parametrize("value", [True, -1, "3", 1.5])
def test_politica_rechaza_cupo_de_lectura_ambiguo(setup, value):
    operation, service, _ = setup
    with pytest.raises(LedgerError, match="invalid_query_limit"):
        activate(service, operation.id, execution_policy=dict(policy(operation.id), query_limit=value))


def test_revision_no_crea_otra_ventana_de_consultas(setup):
    operation, service, executor, plan = prepare(setup, queries=1)
    executor.query(operation.id, "p1", lambda: None)
    newer = activate(service, operation.id, parent=plan["id"], execution_policy=dict(policy(operation.id, limit=10), query_limit=1))
    with pytest.raises(LedgerError, match="query_budget"):
        executor.query(operation.id, "p1", lambda: pytest.fail("cupo reiniciado"))
    changed = service.propose(operation.id, parent_id=newer["id"], reason="Más lecturas", actor="admin",
        execution_policy=dict(policy(operation.id, limit=10), query_limit=2))
    service.ledger.approve(operation.id, changed["id"], expected_digest=changed["digest"], actor="admin")
    with pytest.raises(LedgerError, match="query_budget_window_immutable"):
        service.ledger.activate(operation.id, changed["id"], expected_digest=changed["digest"], actor="admin")


def test_consulta_de_fuente_solo_observada_no_concede_control(setup):
    operation, service, executor = setup
    operation.telemetry_bridges.append(ExternalTelemetrySource("Sensor", "http://localhost", "events", id="sensor"))
    service.operations.save(operation)
    plan = activate(service, operation.id)
    executor.query(operation.id, "sensor", lambda: None)
    with pytest.raises(LedgerError, match="admission_controlled"):
        executor.admit(operation.id, expected_plan_id=plan["id"], capability_id="sensor", action="deploy", idempotency_key="fuente")


def test_consulta_autonoma_exige_delegacion_de_lectura(setup):
    operation, _, executor, _ = prepare(setup, auto=False)
    monitor = OperationExecutor(executor.ledger, lambda op: ExecutionPrincipal("monitor", frozenset({op}), autonomous=True))
    with pytest.raises(LedgerError, match="autonomous_not_approved"):
        monitor.query(operation.id, "p1", lambda: pytest.fail("delegación implícita"))


def test_consultas_permitidas_despues_del_cierre_con_cupo_original(setup):
    operation, _, executor, _ = prepare(setup, queries=1)
    close(executor, operation.id)
    executor.query(operation.id, "p1", lambda: None, purpose="reconcile")
    with pytest.raises(LedgerError, match="query_budget"):
        executor.query(operation.id, "p1", lambda: None)


def test_cerco_bloquea_adopcion_y_nuevos_despachos_heredados(setup):
    operation, service, _ = setup
    other = deepcopy(operation)
    other.id = "legacy-running"
    service.operations.save(other)
    gate = service.adoption_gate
    job = gate.enter(other.id, kind="legacy:control", actor="operador")
    with pytest.raises(LedgerError, match="legacy_work_in_flight"):
        service.adopt(other.id, actor="admin")
    with pytest.raises(LedgerError, match="legacy_admission_fenced"):
        gate.enter(other.id, kind="otro", actor="operador")
    with pytest.raises(LedgerError, match="legacy_local_executor_still_alive"):
        gate.reconcile(other.id, job, actor="admin", reason="Intento", workers_quiescent=True, legacy_authority_disabled=True)
    gate.finish(job)
    service.adopt(other.id, actor="admin")


def test_inventario_obsoleto_no_acredita_quiescencia(setup):
    operation, service, _ = setup
    other = deepcopy(operation)
    other.id = "legacy-source"
    other.plugins = [PluginBinding("remote", "network", plugin_kind="buda", config={"narrative_id": 1})]
    service.operations.save(other)
    report = service.prepare_adoption(other.id)
    other.name = "Edición posterior"
    service.operations.save(other)
    with pytest.raises(LedgerError, match="explicit_legacy_quiescence_required"):
        service.adopt(other.id, actor="admin", quiescence={"inventory_digest": report["digest"], "workers_quiescent": True,
            "legacy_authority_disabled": True, "reason": "Declaración antigua"})


def test_ejecutor_externo_requiere_atestacion_y_no_se_inventa_verificacion(setup):
    operation, service, _ = setup
    other = deepcopy(operation)
    other.id = "legacy-external"
    other.plugins = [PluginBinding("remote", "network", plugin_kind="opencanary", config={})]
    service.operations.save(other)
    with pytest.raises(LedgerError, match="explicit_legacy_quiescence_required"):
        service.adopt(other.id, actor="admin")
    report = service.prepare_adoption(other.id)
    state = service.adopt(other.id, actor="admin", quiescence={"inventory_digest": report["digest"],
        "workers_quiescent": True, "legacy_authority_disabled": True, "reason": "Entorno controlado sin trabajadores."})
    assert state["baseline"]["adoption_protocol"]["basis"] == "administrator_attestation"
    assert state["baseline"]["adoption_protocol"]["external_verification"] == "not_established"


def test_trabajo_sin_fin_durable_sobrevive_caida_del_proceso(setup):
    operation, service, _ = setup
    script = "from apate.ledger.adoption import AdoptionGate; import sys; print(AdoptionGate(sys.argv[1]).enter(sys.argv[2],kind='worker',actor='proceso'))"
    operation_id = "legacy-process"
    job = subprocess.check_output([sys.executable, "-c", script, str(service.adoption_gate.path), operation_id], text=True).strip()
    gate = AdoptionGate(service.adoption_gate.path)
    report = gate.fence(operation_id, {"external_executors": []})
    assert report["jobs"][0]["id"] == job and report["jobs"][0]["state"] == "running"
    gate.reconcile(operation_id, job, actor="admin", reason="Proceso terminado; autoridad retirada.", workers_quiescent=True, legacy_authority_disabled=True)
    assert gate.fence(operation_id, {"external_executors": []})["jobs"] == []


def test_retransmision_dedupe_y_reinicio_de_contador_no_se_confunden(setup):
    operation, _, executor, _ = prepare(setup)
    evidence = OperationEvidence(executor.ledger)
    first, admitted = evidence.ingest(operation.id, event(operation.id))
    duplicate, admitted_duplicate = evidence.ingest(operation.id, event(operation.id))
    next_generation, admitted_reset = evidence.ingest(operation.id, event(operation.id, generation="boot-2"))
    assert admitted and not admitted_duplicate and admitted_reset
    assert duplicate["id"] == first["id"] != next_generation["id"]


def test_conflicto_de_identidad_externa_se_conserva_en_cuarentena(setup):
    operation, _, executor, _ = prepare(setup)
    evidence = OperationEvidence(executor.ledger)
    evidence.ingest(operation.id, event(operation.id))
    conflict, admitted = evidence.ingest(operation.id, event(operation.id, value="T1110"))
    assert not admitted and conflict["payload"]["category"] == "quarantine"
    assert conflict["payload"]["reason"] == "external_identity_conflict"


def test_sin_generacion_no_se_declara_dedupe_del_emisor(setup):
    operation, _, executor, _ = prepare(setup)
    evidence = OperationEvidence(executor.ledger)
    a, _ = evidence.ingest(operation.id, event(operation.id, generation=None))
    b, _ = evidence.ingest(operation.id, event(operation.id, generation=None))
    assert a["id"] != b["id"] and a["payload"]["source_generation"] is None


def test_origen_operacion_fijado_y_fuente_no_aprobada_en_cuarentena(setup):
    operation, _, executor, _ = prepare(setup)
    evidence = OperationEvidence(executor.ledger)
    with pytest.raises(LedgerError, match="cross_operation_event"):
        evidence.ingest(operation.id, event("otra-operacion"))
    record, admitted = evidence.ingest(operation.id, event(operation.id, source="no-aprobada"))
    assert not admitted and record["payload"]["reason"] == "source_not_approved"


def test_cuarentena_no_alimenta_colector_ni_reglas(setup):
    operation, _, executor, _ = prepare(setup)
    bus = EventBus()
    received = []
    bus.subscribe(EventType.TTP_OBSERVED, received.append)
    scoped = EvidenceBus(executor.ledger, operation.id, bus)
    scoped.publish(event(operation.id, source="externa-no-declarada"))
    assert received == []


def test_fallo_de_persistencia_impide_publicacion_en_bus(setup, monkeypatch):
    operation, _, executor, _ = prepare(setup)
    received = []
    bus = EventBus()
    bus.subscribe(EventType.TTP_OBSERVED, received.append)
    scoped = EvidenceBus(executor.ledger, operation.id, bus)
    monkeypatch.setattr(executor.ledger, "_insert", lambda *args: (_ for _ in ()).throw(OSError("disco")))
    with pytest.raises(OSError):
        scoped.publish(event(operation.id))
    assert received == []


def test_decision_enlaza_entrada_regla_y_version_exacta(setup):
    operation, _, executor, plan = prepare(setup)
    record, _ = OperationEvidence(executor.ledger).ingest(operation.id, event(operation.id))
    command = executor.admit(operation.id, expected_plan_id=plan["id"], capability_id="p1", action="deploy",
        idempotency_key="decisión", input_event_id=record["payload"]["event"]["id"], rule_name="regla")
    decision = executor.ledger.record(operation.id, command["references"]["decision"]["record_id"])
    assert decision["references"]["input"]["record_id"] == record["id"]
    assert decision["payload"]["rules_sha256"] == plan["payload"]["content"]["rules"]["sha256"]


def test_decision_sin_entrada_persistida_no_admite_orden(setup):
    operation, _, executor, plan = prepare(setup)
    with pytest.raises(LedgerError, match="admission_persisted_input"):
        executor.admit(operation.id, expected_plan_id=plan["id"], capability_id="p1", action="deploy",
            idempotency_key="inválida", input_event_id="inexistente")
    assert executor.status(operation.id)["reserved_modifications"] == 0


def test_revision_no_reconstruye_exposicion_por_reloj(setup):
    operation, service, executor, plan = prepare(setup)
    newer = activate(service, operation.id, parent=plan["id"], execution_policy=plan["payload"]["content"]["execution_policy"])
    record, _ = OperationEvidence(executor.ledger).ingest(operation.id, event(operation.id))
    assert record["payload"]["plan_at_ingest"] == newer["id"]
    assert record["payload"]["exposure_plan"] is None and record["payload"]["origin_time"] is None


def test_corte_inmutable_recursos_pendientes_y_adenda_tardia(setup):
    operation, _, executor, _ = prepare(setup)
    evidence = OperationEvidence(executor.ledger)
    first, _ = evidence.ingest(operation.id, event(operation.id))
    result = close(executor, operation.id)
    assert result["payload"]["evidence_ids"] == [first["id"]]
    assert result["payload"]["pending_resources"] and result["payload"]["coverage"] == "unknown"
    late, _ = evidence.ingest(operation.id, event(operation.id, external="2", value="T1110"))
    after = executor.ledger.record(operation.id, result["id"])
    assert after["digest"] == result["digest"] and late["sequence"] > result["payload"]["cut_sequence"]
    adenda = [r for r in executor.ledger.history(operation.id) if r["payload"].get("category") == "addendum"]
    assert len(adenda) == 1 and adenda[0]["references"]["closure"]["record_id"] == result["id"]


def test_cerrar_sin_transicion_ni_revision_correcta_no_fabrica_resultado(setup):
    operation, _, executor, _ = prepare(setup)
    with pytest.raises(LedgerError, match="closing_revision_required"):
        OperationEvidence(executor.ledger).close(operation.id, expected_revision=0, criterion="Fin", judgment="Juicio", actor="admin")
    assert not [r for r in executor.ledger.history(operation.id) if r["kind"] == "result"]


def test_cierre_conserva_orden_reclamada_sin_recibo(setup):
    operation, _, executor, plan = prepare(setup)
    command = executor.admit(operation.id, expected_plan_id=plan["id"], capability_id="p1", action="deploy", idempotency_key="incierta")
    executor.claim(operation.id, command["id"])
    result = close(executor, operation.id)
    assert result["payload"]["pending_commands"] == [command["id"]]
    with pytest.raises(LedgerError, match="already_disposed|operation_stopped"):
        executor.claim(operation.id, command["id"], retry=True, reconciliation_note="No autoriza replay")


def test_retiro_tras_cierre_crea_adenda_sin_cambiar_resultado(setup):
    operation, _, executor, _ = prepare(setup)
    plugin = approved_plugins(executor, operation.id, EventBus())["p1"]
    plugin.deploy()
    result = close(executor, operation.id)
    approved_plugins(executor, operation.id, EventBus())["p1"].retire()
    assert executor.ledger.record(operation.id, result["id"])["digest"] == result["digest"]
    assert any(r["payload"].get("category") == "addendum" and r["references"]["late_record"]["kind"] == "receipt" for r in executor.ledger.history(operation.id))


def test_respuesta_de_consulta_no_fabrica_cobertura_completa(setup):
    operation, _, executor, _ = prepare(setup)
    executor.query(operation.id, "p1", lambda: [], window={"since": None})
    result = close(executor, operation.id)
    assert result["payload"]["source_windows"][0]["coverage"] == "unknown"


def test_cobertura_explicita_y_hueco_conservados_en_corte(setup):
    operation, _, executor, _ = prepare(setup)
    evidence = OperationEvidence(executor.ledger)
    evidence.coverage(operation.id, "p1", window={"start": None, "end": None}, status="gap", reason="Fuente caída", actor="monitor")
    result = close(executor, operation.id)
    assert result["payload"]["source_windows"][0]["coverage"] == "gap"


def test_hechos_de_servicios_no_se_pueden_fabricar_por_append(setup):
    operation, _, executor, _ = prepare(setup)
    with pytest.raises(LedgerError, match="managed_fact_service_required"):
        executor.ledger.append(operation.id, [RecordDraft("evidence", {"query_contract": 1})], actor="intruso")


def test_endpoint_cierre_resultado_y_cerco_clasificados(app, client, tmp_path):
    operation, _, service = web_operation(app, client, tmp_path)
    activate(service, operation.id)
    executor = app.config["OPERATION_EXECUTOR"]
    stop(executor, operation.id)
    state = executor.ledger.operation(operation.id)
    response = client.post(f"/operations/{operation.id}/control/close", json={"revision": state["revision"], "criterion": "Fin", "judgment": "Prueba"})
    assert response.status_code == 200 and response.json["state"] == "closed"
    result = client.get(f"/operations/{operation.id}/control/results/{response.json['result_id']}")
    assert result.status_code == 200 and result.headers["Cache-Control"] == "no-store"


def test_http_consulta_usa_fuente_aprobada_y_no_borrador(app, client, tmp_path, monkeypatch):
    operation, _, service = web_operation(app, client, tmp_path)
    source = ExternalTelemetrySource(name="Fuente", elastic_url="http://approved:9200", index="approved-*", field_mapping={"detail": "message"})
    operation.add_telemetry_bridge(source)
    app.config["OPERATION_REPOSITORY"].save(operation)
    activate(service, operation.id, execution_policy=dict(policy(operation.id), query_limit=1))
    operation.telemetry_bridges.clear()
    app.config["OPERATION_REPOSITORY"].save(operation)
    requests = []
    monkeypatch.setattr("apate.telemetry.external_bridge.fetch_recent_hits", lambda **args: requests.append(args) or [{"_id": "e1", "_source": {"message": "Evento"}}])
    route = f"/operations/{operation.id}/telemetry-bridges/{source.id}/fetch"
    assert client.post(route).status_code == 302
    assert requests[0]["elastic_url"] == "http://approved:9200"
    assert client.post(route).json["error"] == "query_budget" and len(requests) == 1
    evidence = [r for r in service.ledger.history(operation.id) if r["payload"].get("category") == "observation"]
    assert len(evidence) == 1 and evidence[0]["payload"]["mapping_sha256"]
    assert service.operations.get(operation.id).telemetry_bridges == []


def test_consulta_fallida_visible_como_desconocida(setup):
    operation, _, executor, _ = prepare(setup)
    def failed():
        raise TimeoutError("fuente")
    with pytest.raises(TimeoutError):
        executor.query(operation.id, "p1", failed)
    assert len(executor.status(operation.id)["unknown_queries"]) == 1


def test_consulta_tardia_agrega_adenda_sin_reescribir_corte(setup):
    operation, _, executor, _ = prepare(setup)
    result = close(executor, operation.id)
    executor.query(operation.id, "p1", lambda: [])
    assert executor.ledger.record(operation.id, result["id"])["digest"] == result["digest"]
    assert any(r["payload"].get("category") == "addendum" for r in executor.ledger.history(operation.id))


def test_cierre_sin_plan_no_declara_inventario_vacio(setup):
    operation, _, executor = setup
    stop(executor, operation.id)
    with pytest.raises(LedgerError, match="active_approved_plan_required"):
        OperationEvidence(executor.ledger).close(operation.id, expected_revision=executor.ledger.operation(operation.id)["revision"], criterion="Fin", judgment="Sin plan", actor="admin")


def test_cerco_http_impide_nueva_accion_heredada(app, client, tmp_path):
    operation, _, service = web_operation(app, client, tmp_path)
    from apate.core import Operation
    legacy = Operation.from_dict(operation.to_dict())
    legacy.id = "operacion-heredada"
    app.config["OPERATION_REPOSITORY"].save(legacy)
    response = client.post(f"/operations/{legacy.id}/control/adoption-check")
    assert response.status_code == 200
    blocked = client.post(f"/operations/{legacy.id}/plugins/file/honeytoken/deploy")
    assert blocked.status_code == 409 and blocked.json["error"] == "legacy_admission_fenced"


def test_cobertura_tiene_referencia_tipificada_en_corte(setup):
    operation, _, executor, _ = prepare(setup)
    coverage = OperationEvidence(executor.ledger).coverage(operation.id, "p1", window=None, status="unknown", reason="Sin ventana comprobada", actor="monitor")
    result = close(executor, operation.id)
    assert coverage["id"] in {ref["record_id"] for ref in result["references"].values()}
