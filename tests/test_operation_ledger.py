"""Propiedades de la entrega A: historia, concurrencia y recuperación local."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading

from cryptography.fernet import Fernet
import pytest

from apate.backup import create_backup, restore_backup
from apate.core import AdversaryProfile, Narrative, Operation, PluginBinding, RulesOfEngagement
from apate.ledger import LedgerError, OperationPlanService, RecordDraft, RecordReference, SQLiteOperationLedger
from apate.ledger.__main__ import main
from apate.secrets import SecretCipher, EncryptedJSONFileOperationRepository


@pytest.fixture
def setup(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    key = Fernet.generate_key()
    (data / "secret_encryption.key").write_bytes(key)
    cipher = SecretCipher(key)
    repo = EncryptedJSONFileOperationRepository(data / "operations", cipher)
    operation = Operation(name="Prueba", adversary_profile=AdversaryProfile("Hipótesis", expected_ttps=["T1046"]),
        roe=RulesOfEngagement(), narrative=Narrative("Historia"))
    operation.bind_plugin(PluginBinding("canary", "data", config={"auth_token": "secreto-de-prueba"}, plugin_kind="canarytoken"))
    repo.save(operation)
    rules = data / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    ledger = SQLiteOperationLedger(data / "operation_ledger.db", cipher)
    service = OperationPlanService(ledger, repo, rules)
    return data, operation, ledger, service


def adopted(setup):
    _, operation, ledger, service = setup
    service.adopt(operation.id, actor="administrador")
    return operation.id, ledger, service


def activated(setup):
    operation_id, ledger, service = adopted(setup)
    plan = service.propose(operation_id, parent_id=None, reason="Diseño inicial", actor="autor")
    ledger.approve(operation_id, plan["id"], expected_digest=plan["digest"], actor="revisor", require_distinct_actor=True)
    ledger.activate(operation_id, plan["id"], expected_digest=plan["digest"], actor="operador")
    return operation_id, ledger, service, plan


def ref(operation_id, kind, record_id):
    return RecordReference(operation_id, kind, record_id)


def decision(plan, *, outcome="accepted", record_id="decision-1"):
    return RecordDraft("decision", {"outcome": outcome, "action": "deploy", "purpose": "ordinary", "guards": {}, "scope": {}}, plan["id"], id=record_id)


def command(operation_id, plan, *, record_id="command-1", maximum=2):
    return RecordDraft("command", {"capability_id": "canary", "action": "deploy", "parameters": {}, "max_attempts": maximum, "idempotency_key": record_id},
        plan["id"], {"decision": ref(operation_id, "decision", "decision-1")}, id=record_id)


def attempt(operation_id, plan, number):
    return RecordDraft("attempt", {"number": number}, plan["id"], {"command": ref(operation_id, "command", "command-1")})


def evidence(record_id="evidence-1"):
    return RecordDraft("evidence", {"source": "sintética", "generation": "g1", "transformation": "identity:v1", "external_id": None,
        "origin_time": None, "ingested_at": None, "raw_sha256": None}, id=record_id)


def test_import_no_aprueba_ni_fabrica_historia_y_es_repetible(setup):
    data, operation, ledger, service = setup
    original = (data / "operations" / f"{operation.id}.json").read_bytes()
    first = service.migrate(actor="admin")
    second = service.migrate(actor="admin")
    assert first["imported"] == [operation.id]
    assert second["already_present"] == [operation.id]
    state = ledger.operation(operation.id)
    assert state["active_plan_id"] is None and state["state"] == "preparation"
    assert state["baseline"]["historical_provenance"] == "unknown"
    assert state["baseline"]["legacy_document_sha256"] == hashlib.sha256(original).hexdigest()
    assert [item["kind"] for item in ledger.history(operation.id)] == ["adoption"]
    assert (data / "operations" / f"{operation.id}.json").read_bytes() == original


@pytest.mark.parametrize("legacy,state,signal", [("planning", "preparation", False), ("active", "active", False), ("compromised", "active", True), ("closed", "closed", False)])
def test_estados_heredados_no_confunden_compromiso_con_suspension(setup, legacy, state, signal):
    _, operation, ledger, service = setup
    from apate.core.models import OperationStatus
    operation.status = OperationStatus(legacy)
    service.operations.save(operation)
    service.adopt(operation.id, actor="admin")
    actual = ledger.operation(operation.id)
    assert actual["state"] == state
    assert actual["baseline"]["legacy_compromised_signal"] is signal


def test_importacion_aisla_corruptos_y_rechaza_id_o_estado_ambiguo(setup):
    data, operation, _, service = setup
    folder = data / "operations"
    (folder / "corrupt.json").write_text("{", encoding="utf-8")
    document = operation.to_dict()
    document["id"] = "different"
    (folder / "mismatch.json").write_text(json.dumps(document), encoding="utf-8")
    document.pop("id")
    (folder / "noid.json").write_text(json.dumps(document), encoding="utf-8")
    report = service.migrate(actor="admin")
    assert report["imported"] == [operation.id]
    assert {item["file"] for item in report["rejected"]} == {"corrupt.json", "mismatch.json", "noid.json"}
    assert len(list(folder.glob("*.json"))) == 4


def test_fechas_ausentes_permanecen_desconocidas(setup):
    data, operation, ledger, service = setup
    path = data / "operations" / f"{operation.id}.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw.pop("created_at")
    raw.pop("updated_at")
    path.write_text(json.dumps(raw), encoding="utf-8")
    service.adopt(operation.id, actor="admin")
    baseline = ledger.operation(operation.id)["baseline"]
    assert baseline["legacy_created_at"] is None
    assert baseline["legacy_snapshot"]["created_at"] is None


def test_h_y_version_sobreviven_edicion_de_documentos_y_objetos_devuelto(setup):
    operation_id, ledger, service, plan = activated(setup)
    original = ledger.operation(operation_id)
    changed = service.operations.get(operation_id)
    changed.adversary_profile.expected_ttps.append("T1078")
    changed.plugins[0].effect.measured_outcome = "Resultado nuevo"
    service.operations.save(changed)
    service.rules_path.write_text("# nueva edición\nrules: []\n", encoding="utf-8")
    plan["payload"]["content"]["operation"]["name"] = "Mutación local"
    original["baseline"]["adversary_profile"]["expected_ttps"].append("T1059")
    saved = ledger.record(operation_id, plan["id"])
    assert saved["payload"]["content"]["operation"]["name"] == "Prueba"
    assert saved["payload"]["content"]["rules"]["content"].replace("\r\n", "\n") == "rules: []\n"
    assert ledger.operation(operation_id)["baseline"]["adversary_profile"]["expected_ttps"] == ["T1046"]
    newer = service.propose(operation_id, parent_id=plan["id"], reason="Nueva CTI", actor="autor")
    assert newer["payload"]["baseline_digest"] == saved["payload"]["baseline_digest"]
    assert newer["payload"]["content"]["operation"]["adversary_profile"]["expected_ttps"] == ["T1046", "T1078"]
    assert "measured_outcome" not in newer["payload"]["content"]["operation"]["plugins"][0]["effect"]


def test_aprobacion_exige_contenido_exacto_y_actor_distinto_si_se_pide(setup):
    operation_id, ledger, service = adopted(setup)
    plan = service.propose(operation_id, parent_id=None, reason="Inicial", actor="autor")
    before = ledger.operation(operation_id)["sequence"]
    with pytest.raises(LedgerError, match="approval_digest_mismatch"):
        ledger.approve(operation_id, plan["id"], expected_digest="0" * 64, actor="revisor")
    with pytest.raises(LedgerError, match="distinct_actor_required"):
        ledger.approve(operation_id, plan["id"], expected_digest=plan["digest"], actor="autor", require_distinct_actor=True)
    with pytest.raises(LedgerError, match="exact_approval_required"):
        ledger.activate(operation_id, plan["id"], expected_digest=plan["digest"], actor="operador")
    assert ledger.operation(operation_id)["sequence"] == before


def test_dos_revisiones_concurrentes_tienen_un_solo_ganador(setup):
    operation_id, ledger, service, initial = activated(setup)
    plans = [service.propose(operation_id, parent_id=initial["id"], reason=f"Revisión {index}", actor=f"autor-{index}") for index in range(2)]
    for plan in plans:
        ledger.approve(operation_id, plan["id"], expected_digest=plan["digest"], actor="revisor")
    barrier = threading.Barrier(2)
    def activate(plan):
        separate = SQLiteOperationLedger(ledger.path, ledger.cipher)
        barrier.wait()
        try:
            separate.activate(operation_id, plan["id"], expected_digest=plan["digest"], actor="operador")
            return "activated", plan["id"]
        except LedgerError as error:
            return error.code, plan["id"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(activate, plans))
    assert sorted(item[0] for item in results) == ["activated", "stale_parent"]
    assert ledger.operation(operation_id)["active_plan_id"] == next(item[1] for item in results if item[0] == "activated")
    assert len([row for row in ledger.history(operation_id) if row["kind"] == "activation"]) == 2


def test_suspension_invalida_propuesta_y_reanudacion_necesita_version_nueva(setup):
    operation_id, ledger, service, initial = activated(setup)
    stale = service.propose(operation_id, parent_id=initial["id"], reason="Anterior", actor="autor")
    ledger.approve(operation_id, stale["id"], expected_digest=stale["digest"], actor="revisor")
    revision = ledger.operation(operation_id)["revision"]
    ledger.stop(operation_id, target="paused", expected_revision=revision, reason="Revisión necesaria", actor="operador")
    with pytest.raises(LedgerError, match="stale_parent"):
        ledger.activate(operation_id, stale["id"], expected_digest=stale["digest"], actor="operador")
    fresh = service.propose(operation_id, parent_id=initial["id"], reason="Reevaluación", actor="autor")
    ledger.approve(operation_id, fresh["id"], expected_digest=fresh["digest"], actor="revisor")
    ledger.activate(operation_id, fresh["id"], expected_digest=fresh["digest"], actor="operador")
    assert ledger.operation(operation_id)["state"] == "active"


def test_operacion_cerrada_heredada_es_terminal(setup):
    _, operation, ledger, service = setup
    operation.close()
    service.operations.save(operation)
    service.adopt(operation.id, actor="admin")
    with pytest.raises(LedgerError, match="operation_stopped"):
        service.propose(operation.id, parent_id=None, reason="Reabrir", actor="autor")
    with pytest.raises(LedgerError, match="invalid_transition"):
        ledger.stop(operation.id, target="active", expected_revision=0, reason="Reabrir", actor="operador")


def test_lote_atomico_rechaza_enlace_ajeno_sin_consumir_secuencia(setup):
    operation_id, ledger, _, plan = activated(setup)
    before = ledger.operation(operation_id)["sequence"]
    bad = RecordDraft("result", {"criterion": "C", "judgment": "desconocido"}, plan["id"], {"evidence": ref("otra", "evidence", "evidence-1")})
    with pytest.raises(LedgerError, match="cross_operation_reference"):
        ledger.append(operation_id, [evidence(), bad], actor="evaluador")
    assert ledger.operation(operation_id)["sequence"] == before
    with pytest.raises(LedgerError, match="invalid_reference"):
        ledger.record(operation_id, "evidence-1")


@pytest.mark.parametrize("target_kind,target_id", [("result", "evidence-1"), ("evidence", "missing")])
def test_referencias_de_tipo_incorrecto_o_inexistentes_se_rechazan(setup, target_kind, target_id):
    operation_id, ledger, _, plan = activated(setup)
    ledger.append(operation_id, [evidence()], actor="fuente")
    draft = RecordDraft("result", {"criterion": "C", "judgment": "desconocido"}, plan["id"], {"input": ref(operation_id, target_kind, target_id)})
    with pytest.raises(LedgerError, match="invalid_reference"):
        ledger.append(operation_id, [draft], actor="evaluador")


def test_fallo_despues_de_insertar_revierte_todo_el_compromiso(setup, monkeypatch):
    operation_id, ledger, _ = adopted(setup)
    before = ledger.operation(operation_id)["sequence"]
    original = ledger._insert
    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("fallo inyectado antes de commit")
    monkeypatch.setattr(ledger, "_insert", fail)
    with pytest.raises(RuntimeError):
        ledger.append(operation_id, [evidence()], actor="fuente")
    reopened = SQLiteOperationLedger(ledger.path, ledger.cipher)
    assert reopened.operation(operation_id)["sequence"] == before
    assert len(reopened.history(operation_id)) == 1


def test_intentos_durables_no_se_reinician_con_version_o_reapertura(setup):
    operation_id, ledger, service, plan = activated(setup)
    ledger.append(operation_id, [decision(plan), command(operation_id, plan), attempt(operation_id, plan, 1)], actor="adaptador")
    with pytest.raises(LedgerError, match="pending_dispositions_required"):
        newer = service.propose(operation_id, parent_id=plan["id"], reason="Revisión incompleta", actor="autor")
        ledger.approve(operation_id, newer["id"], expected_digest=newer["digest"], actor="revisor")
        ledger.activate(operation_id, newer["id"], expected_digest=newer["digest"], actor="operador")
    newer = service.propose(operation_id, parent_id=plan["id"], reason="Conciliar pendiente", actor="autor", dispositions={"command-1": "reconcile"})
    ledger.approve(operation_id, newer["id"], expected_digest=newer["digest"], actor="revisor")
    ledger.activate(operation_id, newer["id"], expected_digest=newer["digest"], actor="operador")
    reopened = SQLiteOperationLedger(ledger.path, ledger.cipher)
    reopened.append(operation_id, [attempt(operation_id, plan, 2)], actor="adaptador")
    with pytest.raises(LedgerError, match="attempt_limit_or_sequence"):
        reopened.append(operation_id, [attempt(operation_id, plan, 3)], actor="adaptador")
    assert reopened.record(operation_id, "command-1")["plan_id"] == plan["id"]
    assert reopened.pending_commands(operation_id) == ["command-1"]


@pytest.mark.parametrize("maximum", [0, -1, True, 1.5, "2"])
def test_orden_exige_maximo_finito_entero_positivo(setup, maximum):
    operation_id, ledger, _, plan = activated(setup)
    with pytest.raises(LedgerError, match="invalid_command"):
        ledger.append(operation_id, [decision(plan), command(operation_id, plan, maximum=maximum)], actor="adaptador")


def test_rechazo_no_admite_orden_y_fuente_observada_no_es_capacidad_controlada(setup):
    operation_id, ledger, _, plan = activated(setup)
    with pytest.raises(LedgerError, match="rejected_or_different_decision"):
        ledger.append(operation_id, [decision(plan, outcome="rejected"), command(operation_id, plan)], actor="adaptador")
    draft = command(operation_id, plan)
    draft.payload["capability_id"] = "fuente-externa"
    with pytest.raises(LedgerError, match="controlled_capability_required"):
        ledger.append(operation_id, [decision(plan), draft], actor="adaptador")


def test_idempotencia_rechaza_duplicado_y_disposicion_resuelve_pendiente(setup):
    operation_id, ledger, _, plan = activated(setup)
    ledger.append(operation_id, [decision(plan), command(operation_id, plan)], actor="adaptador")
    duplicate = command(operation_id, plan, record_id="command-2")
    duplicate.payload["idempotency_key"] = "command-1"
    with pytest.raises(LedgerError, match="duplicate_or_invalid_record"):
        ledger.append(operation_id, [duplicate], actor="adaptador")
    terminal = RecordDraft("disposition", {"outcome": "abandoned", "reason": "Resultado incierto"}, plan["id"], {"command": ref(operation_id, "command", "command-1")})
    ledger.append(operation_id, [terminal], actor="operador")
    assert ledger.pending_commands(operation_id) == []
    with pytest.raises(LedgerError, match="already_disposed"):
        ledger.append(operation_id, [terminal], actor="operador")


def test_sql_impide_sobrescribir_h_plan_y_enlaces(setup):
    operation_id, ledger, _, plan = activated(setup)
    with sqlite3.connect(ledger.path) as connection:
        for query, arguments in [
            ("UPDATE operations SET baseline='{}' WHERE id=?", (operation_id,)),
            ("UPDATE records SET payload='{}' WHERE id=?", (plan["id"],)),
            ("DELETE FROM records WHERE id=?", (plan["id"],)),
            ("DELETE FROM record_refs WHERE operation_id=?", (operation_id,)),
        ]:
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                connection.execute(query, arguments)


def test_esquema_futuro_no_se_modifica(setup):
    _, _, ledger, _ = setup
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("PRAGMA user_version=999")
    before = ledger.path.read_bytes()
    with pytest.raises(LedgerError, match="schema_too_new"):
        SQLiteOperationLedger(ledger.path, ledger.cipher)
    assert ledger.path.read_bytes() == before


def test_cifrado_en_disco_clave_equivocada_y_backup_completo(setup, tmp_path, monkeypatch):
    monkeypatch.delenv("APATE_SECRET_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("APATE_BUDA_DATABASE_URI", raising=False)
    data, _, ledger, _ = setup
    operation_id, _, _, plan = activated(setup)
    assert b"secreto-de-prueba" not in ledger.path.read_bytes()
    wrong = SQLiteOperationLedger(ledger.path, SecretCipher(Fernet.generate_key()))
    with pytest.raises(ValueError):
        wrong.record(operation_id, plan["id"])
    create_backup(data, tmp_path / "backup")
    restore_backup(tmp_path / "backup", tmp_path / "restored")
    restored = OperationPlanService.from_data_dir(tmp_path / "restored", tmp_path / "restored" / "rules.yaml")
    assert restored.ledger.history(operation_id) == ledger.history(operation_id)
    assert restored.ledger.operation(operation_id) == ledger.operation(operation_id)


def test_cli_recorrido_revisable_sin_imprimir_secretos(setup, tmp_path, capsys):
    data, operation, _, service = setup
    prefix = ["--data-dir", str(data), "--rules", str(service.rules_path)]
    assert main(prefix + ["migrate", "--actor", "admin"]) == 0
    capsys.readouterr()
    assert main(prefix + ["propose", operation.id, "--reason", "Inicial", "--actor", "autor"]) == 0
    proposed = capsys.readouterr().out
    assert "secreto-de-prueba" not in proposed
    plan = json.loads(proposed)
    review = tmp_path / "review.json"
    assert main(prefix + ["review", operation.id, plan["id"], "--output", str(review)]) == 0
    assert "secreto-de-prueba" in review.read_text(encoding="utf-8")
    assert main(prefix + ["approve", operation.id, plan["id"], "--digest", plan["digest"], "--actor", "revisor", "--distinct-actor"]) == 0
    assert main(prefix + ["activate", operation.id, plan["id"], "--digest", plan["digest"], "--actor", "operador"]) == 0
    assert main(prefix + ["status", operation.id]) == 0
    assert "secreto-de-prueba" not in capsys.readouterr().out


def test_flask_expone_servicio_sin_aprobar_operaciones_existentes(app):
    assert isinstance(app.config["OPERATION_LEDGER"], SQLiteOperationLedger)
    assert app.config["OPERATION_PLAN_SERVICE"].operations is app.config["OPERATION_REPOSITORY"]
    with sqlite3.connect(app.config["OPERATION_LEDGER"].path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0] == 0


def test_reinicio_en_otro_proceso_conserva_version_y_secuencia(setup):
    operation_id, ledger, _, plan = activated(setup)
    data = setup[0]
    result = subprocess.run([sys.executable, "-m", "apate.ledger", "--data-dir", str(data), "--rules", str(data / "rules.yaml"), "status", operation_id],
        capture_output=True, text=True, check=True)
    state = json.loads(result.stdout)
    assert state["active_plan_id"] == plan["id"]
    assert state["sequence"] == ledger.operation(operation_id)["sequence"]


@pytest.mark.parametrize("payload", [{"x": float("nan")}, {1: "clave implícita"}, {"x": object()}])
def test_serializacion_rechaza_perdida_o_conversion_implicita(setup, payload):
    operation_id, ledger, _ = adopted(setup)
    with pytest.raises(LedgerError):
        ledger.propose(operation_id, payload, parent_id=None, reason="Inválido", actor="autor")


def test_caida_real_antes_de_commit_no_deja_filas_ni_secuencia_parcial(setup):
    operation_id, ledger, _ = adopted(setup)
    before = ledger.operation(operation_id)["sequence"]
    script = """
import os, sys
from apate.ledger import OperationPlanService, RecordDraft
service = OperationPlanService.from_data_dir(sys.argv[1], sys.argv[2])
ledger = service.ledger
original = ledger._insert
def crash(*args, **kwargs):
    original(*args, **kwargs)
    os._exit(42)
ledger._insert = crash
ledger.append(sys.argv[3], [RecordDraft('evidence', {
 'source':'synthetic','generation':'g1','transformation':'identity:v1',
 'external_id':None,'origin_time':None,'ingested_at':None,'raw_sha256':None
})], actor='source')
"""
    data = setup[0]
    result = subprocess.run([sys.executable, "-c", script, str(data), str(data / "rules.yaml"), operation_id], capture_output=True)
    assert result.returncode == 42
    reopened = SQLiteOperationLedger(ledger.path, ledger.cipher)
    assert reopened.operation(operation_id)["sequence"] == before
    assert len(reopened.history(operation_id)) == 1


def test_reclamacion_concurrente_no_duplica_numero_de_intento(setup):
    operation_id, ledger, _, plan = activated(setup)
    ledger.append(operation_id, [decision(plan), command(operation_id, plan)], actor="adaptador")
    barrier = threading.Barrier(2)
    def claim(_):
        other = SQLiteOperationLedger(ledger.path, ledger.cipher)
        barrier.wait()
        try:
            other.append(operation_id, [attempt(operation_id, plan, 1)], actor="adaptador")
            return "recorded"
        except LedgerError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(claim, range(2)))
    assert sorted(results) == ["attempt_limit_or_sequence", "recorded"]
    assert len([item for item in ledger.history(operation_id) if item["kind"] == "attempt"]) == 1


def test_arranque_concurrente_crea_un_solo_esquema(tmp_path):
    path = tmp_path / "new.db"
    cipher = SecretCipher(Fernet.generate_key())
    barrier = threading.Barrier(4)
    def start(_):
        barrier.wait()
        return SQLiteOperationLedger(path, cipher)
    with ThreadPoolExecutor(max_workers=4) as pool:
        instances = list(pool.map(start, range(4)))
    assert len(instances) == 4
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_fallo_al_activar_no_cambia_puntero_ni_estado(setup, monkeypatch):
    operation_id, ledger, service, initial = activated(setup)
    newer = service.propose(operation_id, parent_id=initial["id"], reason="Revisión", actor="autor")
    ledger.approve(operation_id, newer["id"], expected_digest=newer["digest"], actor="revisor")
    before = ledger.operation(operation_id)
    original = ledger._insert
    def fail(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("antes de actualizar puntero")
    monkeypatch.setattr(ledger, "_insert", fail)
    with pytest.raises(RuntimeError):
        ledger.activate(operation_id, newer["id"], expected_digest=newer["digest"], actor="operador")
    assert SQLiteOperationLedger(ledger.path, ledger.cipher).operation(operation_id) == before


def test_orden_posterior_a_revision_impide_activar_disposicion_incompleta(setup):
    operation_id, ledger, service, initial = activated(setup)
    newer = service.propose(operation_id, parent_id=initial["id"], reason="Revisión", actor="autor")
    ledger.approve(operation_id, newer["id"], expected_digest=newer["digest"], actor="revisor")
    ledger.append(operation_id, [decision(initial), command(operation_id, initial)], actor="adaptador")
    with pytest.raises(LedgerError, match="pending_dispositions_required"):
        ledger.activate(operation_id, newer["id"], expected_digest=newer["digest"], actor="operador")
    assert ledger.operation(operation_id)["active_plan_id"] == initial["id"]


def test_no_se_puede_ampliar_lineage_sin_detectar_mutacion(setup):
    operation_id, ledger, _, plan = activated(setup)
    adoption = ledger.history(operation_id)[0]
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("INSERT INTO record_refs VALUES (?,?,?,?,?)", (operation_id, plan["id"], "intruso", adoption["id"], "adoption"))
    with pytest.raises(LedgerError, match="reference_digest_mismatch"):
        ledger.record(operation_id, plan["id"])


def test_diseno_no_acepta_fuente_alterada_o_identidad_ajena(setup):
    operation_id, ledger, service = adopted(setup)
    content = service.capture_design(operation_id)
    content["rules"]["content"] += "# cambio\n"
    with pytest.raises(LedgerError, match="source_digest_mismatch"):
        ledger.propose(operation_id, content, parent_id=None, reason="Inválido", actor="autor")
    content = service.capture_design(operation_id)
    content["operation"]["id"] = "otra"
    with pytest.raises(LedgerError, match="invalid_plan_identity"):
        ledger.propose(operation_id, content, parent_id=None, reason="Inválido", actor="autor")


def test_fuentes_y_activos_se_congelan_y_fuente_corrupta_no_se_aprueba(setup):
    from apate.core import BehaviorContextSource, JSONFileBehaviorContextRepository
    from apate.assets import Asset, JSONFileAssetRepository
    data, operation, ledger, service = setup
    service.contexts = JSONFileBehaviorContextRepository(data / "behavior_context")
    service.assets = JSONFileAssetRepository(data / "assets")
    source = BehaviorContextSource(name="Contexto", data={"secreto": "contexto-original"}, provenance="synthetic")
    service.contexts.save(source)
    operation.behavior_context_source_ids = [source.id]
    operation.adversary_profile.target_assets = ["asset-1"]
    service.assets.save(Asset("asset-1", "Inicial", "server", "high"))
    service.operations.save(operation)
    service.adopt(operation.id, actor="admin")
    plan = service.propose(operation.id, parent_id=None, reason="Inicial", actor="autor")
    source.data["secreto"] = "contenido-alterado"
    service.contexts.save(source)
    service.assets.save(Asset("asset-1", "Actualizado", "server", "high"))
    assert ledger.operation(operation.id)["baseline"]["assets"][0]["snapshot"]["name"] == "Inicial"
    assert ledger.record(operation.id, plan["id"])["payload"]["content"]["context_sources"][0]["snapshot"]["data"] == {"secreto": "contexto-original"}
    assert b"contexto-original" not in ledger.path.read_bytes()
    with pytest.raises(LedgerError, match="context_integrity_mismatch"):
        service.propose(operation.id, parent_id=None, reason="Alterada", actor="autor")


def test_yaml_invalido_impide_congelar_un_plan(setup):
    operation_id, ledger, service = adopted(setup)
    service.rules_path.write_text("rules: [invalid]", encoding="utf-8")
    with pytest.raises(LedgerError, match="invalid_rules_snapshot"):
        service.propose(operation_id, parent_id=None, reason="Inválido", actor="autor")
    assert len(ledger.history(operation_id)) == 1


def test_mutar_entrada_despues_de_validar_no_cambia_lo_persistido(setup, monkeypatch):
    operation_id, ledger, _, plan = activated(setup)
    draft = decision(plan)
    original = ledger._validate_fact
    def mutate(*args, **kwargs):
        original(*args, **kwargs)
        draft.payload["outcome"] = "rejected"
    monkeypatch.setattr(ledger, "_validate_fact", mutate)
    ledger.append(operation_id, [draft], actor="adaptador")
    assert ledger.record(operation_id, draft.id)["payload"]["outcome"] == "accepted"


def test_mutar_contenido_mientras_se_valida_no_cambia_plan(setup, monkeypatch):
    operation_id, ledger, service = adopted(setup)
    content = service.capture_design(operation_id)
    original = ledger._validate_plan_content
    def mutate(*args, **kwargs):
        original(*args, **kwargs)
        content["operation"]["name"] = "alterado"
    monkeypatch.setattr(ledger, "_validate_plan_content", mutate)
    plan = ledger.propose(operation_id, content, parent_id=None, reason="Inicial", actor="autor")
    assert ledger.record(operation_id, plan["id"])["payload"]["content"]["operation"]["name"] == "Prueba"


@pytest.mark.parametrize("collection,item", [("scenarios", {"description": "Sin ID"}), ("telemetry_bridges", {"name": "Sin ID", "elastic_url": "http://example", "index": "events"})])
def test_importacion_no_fabrica_ids_de_entidades_anidadas(setup, collection, item):
    data, operation, ledger, service = setup
    path = data / "operations" / f"{operation.id}.json"
    original = json.loads(path.read_bytes())
    original[collection] = [item]
    path.write_text(json.dumps(original), encoding="utf-8")
    report = service.migrate(actor="admin")
    assert report["imported"] == []
    assert report["rejected"][0]["code"] == "ambiguous_entity_identity"
    with pytest.raises(LedgerError, match="operation_not_found"):
        ledger.operation(operation.id)


def test_documento_con_entidad_ambigua_no_se_convierte_en_propuesta(setup):
    operation_id, ledger, service = adopted(setup)
    path = service.operations._path_for(operation_id)
    original = json.loads(path.read_bytes())
    original["scenarios"] = [{"description": "Sin ID"}]
    path.write_text(json.dumps(original), encoding="utf-8")
    with pytest.raises(LedgerError, match="ambiguous_entity_identity"):
        service.propose(operation_id, parent_id=None, reason="Ambigua", actor="autor")
    assert len(ledger.history(operation_id)) == 1


def test_propuesta_directa_exige_ids_estables(setup):
    operation_id, ledger, service = adopted(setup)
    content = service.capture_design(operation_id)
    content["operation"]["scenarios"] = [{"description": "Sin ID"}]
    with pytest.raises(LedgerError, match="ambiguous_entity_identity"):
        ledger.propose(operation_id, content, parent_id=None, reason="Ambigua", actor="autor")
