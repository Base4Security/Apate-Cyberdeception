"""Registro común de versiones y hechos; no invoca capacidades externas.

El servicio de ejecución comparte estas transacciones para K1/K2. Los
actores locales son referencias; el transporte autentica antes de usarlas.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ..i18n import gettext as _
from ..secrets import SecretCipher

SCHEMA_VERSION = 1
APPLICATION_ID = 0x41504C31
STATES = {"preparation", "active", "paused", "closing", "closed"}
FACT_KINDS = {"decision", "command", "attempt", "receipt", "evidence", "result", "disposition"}


class LedgerError(ValueError):
    """Error con código estable, sin incluir contenido posiblemente secreto."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(_("Registro de operación: %(reason)s.", reason=code))


def canonical(value: Any) -> str:
    """Serialización estable de valores JSON, sin NaN ni conversiones implícitas."""
    try:
        # El recorrido evita que JSON convierta silenciosamente claves enteras.
        def check(item):
            if isinstance(item, dict):
                if any(not isinstance(key, str) for key in item):
                    raise LedgerError("invalid_json_key")
                for child in item.values():
                    check(child)
            elif isinstance(item, list):
                for child in item:
                    check(child)
            elif item is not None and type(item) not in {str, int, float, bool}:
                raise LedgerError("invalid_json_value")
        check(value)
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        if isinstance(error, LedgerError):
            raise
        raise LedgerError("invalid_json") from error


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def text_required(value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise LedgerError("required_text")


def json_snapshot(value: Any) -> Any:
    """Copia el contenido al entrar; validar y escribir usan la misma foto."""
    return json.loads(canonical(value))


def validate_entity_ids(definition: dict) -> None:
    """Rechaza entidades ambiguas antes de los defaults del dominio heredado."""
    if not isinstance(definition, dict):
        raise LedgerError("invalid_plan_definition")
    for collection, identifier in (("scenarios", "id"), ("telemetry_bridges", "id"), ("plugins", "plugin_id")):
        values = definition.get(collection, [])
        if not isinstance(values, list):
            raise LedgerError("ambiguous_entity_identity")
        identities = []
        for value in values:
            if not isinstance(value, dict) or not isinstance(value.get(identifier), str) or not value[identifier].strip():
                raise LedgerError("ambiguous_entity_identity")
            identities.append(value[identifier])
        if len(set(identities)) != len(identities):
            raise LedgerError("ambiguous_entity_identity")


@dataclass(frozen=True)
class RecordReference:
    operation_id: str
    kind: str
    record_id: str


@dataclass(frozen=True)
class RecordDraft:
    kind: str
    payload: dict[str, Any]
    plan_id: str | None = None
    references: dict[str, RecordReference] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


def freeze_draft(draft: RecordDraft) -> RecordDraft:
    if not isinstance(draft, RecordDraft) or not isinstance(draft.references, dict):
        raise LedgerError("invalid_record_draft")
    references = dict(draft.references)
    if any(not isinstance(ref, RecordReference) for ref in references.values()):
        raise LedgerError("invalid_reference")
    return RecordDraft(draft.kind, json_snapshot(draft.payload), draft.plan_id, references, draft.id)


_SCHEMA = """
CREATE TABLE operations (
 id TEXT PRIMARY KEY, baseline TEXT NOT NULL, baseline_digest TEXT NOT NULL,
 origin TEXT NOT NULL, created_at TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('preparation','active','paused','closing','closed')),
 revision INTEGER NOT NULL DEFAULT 0, sequence INTEGER NOT NULL DEFAULT 0,
 active_plan_id TEXT,
 FOREIGN KEY(id,active_plan_id) REFERENCES records(operation_id,id)
);
CREATE TABLE records (
 operation_id TEXT NOT NULL REFERENCES operations(id), id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('adoption','plan','approval','activation','state',
   'decision','command','attempt','receipt','evidence','result','disposition')),
 sequence INTEGER NOT NULL, schema_version INTEGER NOT NULL CHECK(schema_version=1),
 actor TEXT NOT NULL, created_at TEXT NOT NULL, plan_id TEXT,
 payload TEXT NOT NULL, digest TEXT NOT NULL,
 idempotency_key TEXT, command_id TEXT, attempt_number INTEGER,
 PRIMARY KEY(operation_id,id), UNIQUE(operation_id,id,kind), UNIQUE(operation_id,sequence),
 UNIQUE(operation_id,idempotency_key), UNIQUE(operation_id,command_id,attempt_number),
 FOREIGN KEY(operation_id,plan_id) REFERENCES records(operation_id,id)
);
CREATE INDEX records_by_kind ON records(operation_id,kind,sequence);
CREATE TABLE record_refs (
 operation_id TEXT NOT NULL, record_id TEXT NOT NULL, role TEXT NOT NULL,
 target_id TEXT NOT NULL, target_kind TEXT NOT NULL,
 PRIMARY KEY(operation_id,record_id,role),
 FOREIGN KEY(operation_id,record_id) REFERENCES records(operation_id,id),
 FOREIGN KEY(operation_id,target_id,target_kind) REFERENCES records(operation_id,id,kind)
);
CREATE TRIGGER immutable_records_update BEFORE UPDATE ON records
 BEGIN SELECT RAISE(ABORT,'immutable_record'); END;
CREATE TRIGGER immutable_records_delete BEFORE DELETE ON records
 BEGIN SELECT RAISE(ABORT,'immutable_record'); END;
CREATE TRIGGER immutable_refs_update BEFORE UPDATE ON record_refs
 BEGIN SELECT RAISE(ABORT,'immutable_reference'); END;
CREATE TRIGGER immutable_refs_delete BEFORE DELETE ON record_refs
 BEGIN SELECT RAISE(ABORT,'immutable_reference'); END;
CREATE TRIGGER immutable_baseline BEFORE UPDATE OF id,baseline,baseline_digest,origin,created_at ON operations
 BEGIN SELECT RAISE(ABORT,'immutable_baseline'); END;
CREATE TRIGGER immutable_operation_delete BEFORE DELETE ON operations
 BEGIN SELECT RAISE(ABORT,'immutable_operation'); END;
"""


class SQLiteOperationLedger:
    """Historial cifrado con enlaces tipados y activación serializada de planes."""

    def __init__(self, path: str | Path, cipher: SecretCipher):
        self.path = Path(path)
        self.cipher = cipher
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection(write=True) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            application = connection.execute("PRAGMA application_id").fetchone()[0]
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if version > SCHEMA_VERSION:
                raise LedgerError("schema_too_new")
            if version == 0 and not tables and application == 0:
                # DDL y sello se confirman juntos, bajo el mismo lock que
                # protege la comprobación frente a otro arranque concurrente.
                for statement in _SCHEMA.split(";\n"):
                    if statement.strip():
                        connection.execute(statement)
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            elif version != SCHEMA_VERSION or application != APPLICATION_ID or tables != {"operations", "records", "record_refs"}:
                raise LedgerError("unknown_schema")

    @contextmanager
    def _connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        try:
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _decode(self, encrypted: str, expected: str) -> dict:
        if not SecretCipher.is_encrypted(encrypted):
            raise LedgerError("unencrypted_payload")
        value = json.loads(self.cipher.decrypt(encrypted))
        if digest(value) != expected:
            raise LedgerError("digest_mismatch")
        return value

    def _operation(self, connection, operation_id: str) -> dict:
        row = connection.execute("SELECT * FROM operations WHERE id=?", (operation_id,)).fetchone()
        if row is None:
            raise LedgerError("operation_not_found")
        result = dict(row)
        result["baseline"] = self._decode(row["baseline"], row["baseline_digest"])
        return result

    def operation(self, operation_id: str) -> dict:
        with self._connection() as connection:
            return self._operation(connection, operation_id)

    def _record(self, connection, operation_id: str, record_id: str, kind: str | None = None) -> dict:
        row = connection.execute("SELECT * FROM records WHERE operation_id=? AND id=?", (operation_id, record_id)).fetchone()
        if row is None or (kind is not None and row["kind"] != kind):
            raise LedgerError("invalid_reference")
        result = dict(row)
        envelope = self._decode(row["payload"], row["digest"])
        result["payload"] = envelope["body"]
        result["references"] = {ref["role"]: {"operation_id": operation_id, "kind": ref["target_kind"], "record_id": ref["target_id"]}
            for ref in connection.execute("SELECT * FROM record_refs WHERE operation_id=? AND record_id=? ORDER BY role", (operation_id, record_id))}
        if result["references"] != envelope["references"]:
            raise LedgerError("reference_digest_mismatch")
        return result

    def record(self, operation_id: str, record_id: str) -> dict:
        with self._connection() as connection:
            return self._record(connection, operation_id, record_id)

    def history(self, operation_id: str) -> list[dict]:
        with self._connection() as connection:
            connection.execute("BEGIN")
            self._operation(connection, operation_id)
            return [self._record(connection, operation_id, row[0]) for row in
                    connection.execute("SELECT id FROM records WHERE operation_id=? ORDER BY sequence", (operation_id,)).fetchall()]

    def _insert(self, connection, operation_id: str, draft: RecordDraft, actor: str) -> dict:
        draft = freeze_draft(draft)
        text_required(actor)
        text_required(draft.id)
        if not isinstance(draft.payload, dict):
            raise LedgerError("invalid_payload")
        payload = canonical({"body": draft.payload, "references": {
            role: {"operation_id": ref.operation_id, "kind": ref.kind, "record_id": ref.record_id}
            for role, ref in draft.references.items()}})
        if draft.plan_id is not None:
            self._record(connection, operation_id, draft.plan_id, "plan")
        for role, reference in draft.references.items():
            text_required(role)
            if reference.operation_id != operation_id:
                raise LedgerError("cross_operation_reference")
            self._record(connection, operation_id, reference.record_id, reference.kind)
        connection.execute("UPDATE operations SET sequence=sequence+1 WHERE id=?", (operation_id,))
        sequence = connection.execute("SELECT sequence FROM operations WHERE id=?", (operation_id,)).fetchone()[0]
        command = draft.references.get("command") if draft.kind == "attempt" else None
        try:
            connection.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                operation_id, draft.id, draft.kind, sequence, SCHEMA_VERSION, actor, now(), draft.plan_id,
                self.cipher.encrypt(payload), hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                draft.payload.get("idempotency_key") if draft.kind == "command" else None,
                command.record_id if command else None, draft.payload.get("number") if command else None,
            ))
            for role, reference in draft.references.items():
                connection.execute("INSERT INTO record_refs VALUES (?,?,?,?,?)", (operation_id, draft.id, role, reference.record_id, reference.kind))
        except sqlite3.IntegrityError as error:
            raise LedgerError("duplicate_or_invalid_record") from error
        return self._record(connection, operation_id, draft.id)

    def adopt(self, operation_id: str, baseline: dict, *, state: str, origin: str, actor: str) -> dict:
        """Fija H en el presente; no genera aprobación ni historia anterior."""
        text_required(operation_id)
        text_required(actor)
        text_required(origin)
        if state not in STATES or not isinstance(baseline, dict):
            raise LedgerError("invalid_adoption")
        baseline = json_snapshot(baseline)
        encoded = canonical(baseline)
        with self._connection(write=True) as connection:
            try:
                connection.execute("INSERT INTO operations (id,baseline,baseline_digest,origin,created_at,state) VALUES (?,?,?,?,?,?)",
                    (operation_id, self.cipher.encrypt(encoded), digest(baseline), origin, now(), state))
            except sqlite3.IntegrityError as error:
                raise LedgerError("already_adopted") from error
            self._insert(connection, operation_id, RecordDraft("adoption", {"origin": origin, "baseline_digest": digest(baseline), "initial_state": state}), actor)
            return self._operation(connection, operation_id)

    def propose(self, operation_id: str, content: dict, *, parent_id: str | None, reason: str,
                actor: str, findings: list[RecordReference] | None = None,
                dispositions: dict[str, str] | None = None) -> dict:
        """Congela una propuesta; cualquier edición requiere otra propuesta."""
        text_required(reason)
        if not isinstance(content, dict):
            raise LedgerError("invalid_plan")
        content = json_snapshot(content)
        findings = list(findings or [])
        dispositions = json_snapshot(dispositions or {})
        if not isinstance(dispositions, dict) or any(not isinstance(ref, RecordReference) for ref in findings):
            raise LedgerError("invalid_plan_references")
        self._validate_plan_content(operation_id, content)
        with self._connection(write=True) as connection:
            operation = self._operation(connection, operation_id)
            if operation["state"] in {"closed", "closing"}:
                raise LedgerError("operation_stopped")
            if parent_id != operation["active_plan_id"]:
                raise LedgerError("stale_parent")
            references = {f"finding:{index}": ref for index, ref in enumerate(findings or [])}
            if parent_id:
                references["parent"] = RecordReference(operation_id, "plan", parent_id)
            for ref in findings or []:
                if ref.kind not in {"evidence", "receipt", "result"}:
                    raise LedgerError("invalid_finding")
            disposition = dict(dispositions or {})
            for command_id, choice in disposition.items():
                if choice not in {"cancel", "reconcile", "wait"}:
                    raise LedgerError("invalid_disposition")
                references[f"disposition:{command_id}"] = RecordReference(operation_id, "command", command_id)
            draft = RecordDraft("plan", {"content": content, "parent_id": parent_id,
                "baseline_digest": operation["baseline_digest"], "base_revision": operation["revision"],
                "reason": reason, "dispositions": disposition}, references=references)
            return self._insert(connection, operation_id, draft, actor)

    @staticmethod
    def _validate_plan_content(operation_id: str, content: dict) -> None:
        """Valida lo congelado; no resuelve configuraciones remotas mutables."""
        from ..core import ApateError, Operation
        from ..rules import parse_rules

        canonical(content)
        definition = content.get("operation")
        if content.get("schema_version") != 1 or not isinstance(definition, dict) or definition.get("id") != operation_id:
            raise LedgerError("invalid_plan_identity")
        validate_entity_ids(definition)
        try:
            operation = Operation.from_dict(definition)
        except (ApateError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise LedgerError("invalid_plan_definition") from error
        controlled = [binding.plugin_id for binding in operation.plugins]
        observed = [source.id for source in operation.telemetry_bridges]
        scenarios = [scenario.id for scenario in operation.scenarios]
        if len(set(controlled)) != len(controlled) or len(set(observed)) != len(observed) or len(set(scenarios)) != len(scenarios) or set(controlled) & set(observed):
            raise LedgerError("ambiguous_capability_or_scenario")
        for binding in operation.plugins:
            if binding.scenario_id is not None and binding.scenario_id not in scenarios:
                raise LedgerError("invalid_scenario_reference")
            if binding.leads_to_plugin_id is not None and binding.leads_to_plugin_id not in controlled:
                raise LedgerError("invalid_capability_reference")
        rules = content.get("rules")
        catalogs = content.get("catalogs")
        if not isinstance(rules, dict) or not isinstance(catalogs, list):
            raise LedgerError("rules_and_catalog_snapshots_required")
        for snapshot in [rules, *catalogs]:
            if not isinstance(snapshot, dict) or not isinstance(snapshot.get("content"), str):
                raise LedgerError("invalid_source_snapshot")
            if hashlib.sha256(snapshot["content"].encode("utf-8")).hexdigest() != snapshot.get("sha256"):
                raise LedgerError("source_digest_mismatch")
        try:
            parse_rules(rules["content"])
        except (ApateError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise LedgerError("invalid_rules_snapshot") from error
        if "execution_policy" in content:
            from .execution import validate_policy
            validate_policy(content["execution_policy"], operation_id)
            resources = content.get("external_resource_versions", {})
            items = resources.get("items")
            if not isinstance(items, list):
                raise LedgerError("resource_snapshots_required")
            identities = []
            for item in items:
                if not isinstance(item, dict) or item.get("kind") not in {"deployment_plan", "deployment_record", "target_credential", "plugin_descriptor"}:
                    raise LedgerError("invalid_resource_snapshot")
                text_required(item.get("id"))
                if digest(item.get("snapshot")) != item.get("sha256"):
                    raise LedgerError("resource_digest_mismatch")
                identities.append((item["kind"], item["id"]))
                if item["kind"] == "plugin_descriptor":
                    from .descriptors import validate_descriptor
                    validate_descriptor(item["snapshot"])
                    binding = operation.find_plugin_binding(item["id"])
                    from ..plugins.registry import PluginRegistry
                    if binding is None or PluginRegistry.resolve_binding_kind(binding) != item["snapshot"]["kind"]:
                        raise LedgerError("invalid_descriptor_binding")
                    if item["snapshot"].get("binding_digest") != digest(binding.to_dict()):
                        raise LedgerError("descriptor_binding_mismatch")
                if item["kind"] in {"deployment_plan", "deployment_record"} and item["snapshot"].get("operation_id") != operation_id:
                    raise LedgerError("cross_operation_resource")
            if len(identities) != len(set(identities)):
                raise LedgerError("ambiguous_resource_snapshot")

    def _check_current(self, operation: dict, plan: dict) -> None:
        if operation["state"] in {"closing", "closed"}:
            raise LedgerError("operation_stopped")
        payload = plan["payload"]
        if payload["parent_id"] != operation["active_plan_id"] or payload["base_revision"] != operation["revision"]:
            raise LedgerError("stale_parent")
        if payload["baseline_digest"] != operation["baseline_digest"]:
            raise LedgerError("baseline_mismatch")

    def approve(self, operation_id: str, plan_id: str, *, expected_digest: str, actor: str,
                require_distinct_actor: bool = False) -> dict:
        """Aprueba solo la huella que el operador revisó, con padre vigente."""
        with self._connection(write=True) as connection:
            operation = self._operation(connection, operation_id)
            plan = self._record(connection, operation_id, plan_id, "plan")
            self._check_current(operation, plan)
            if expected_digest != plan["digest"]:
                raise LedgerError("approval_digest_mismatch")
            if require_distinct_actor and actor == plan["actor"]:
                raise LedgerError("distinct_actor_required")
            if self._approval(connection, operation_id, plan_id) is not None:
                raise LedgerError("already_approved")
            from ..extensions import check_ledger_policy
            policy_metadata = check_ledger_policy(self, "approve", operation=operation, plan=plan, actor=actor)
            approval_body = {"plan_digest": expected_digest}
            if policy_metadata is not None:
                approval_body["authorization"] = json_snapshot(policy_metadata)
            return self._insert(connection, operation_id, RecordDraft("approval", approval_body, plan_id,
                {"plan": RecordReference(operation_id, "plan", plan_id)}), actor)

    def _approval(self, connection, operation_id: str, plan_id: str) -> dict | None:
        row = connection.execute("SELECT id FROM records WHERE operation_id=? AND kind='approval' AND plan_id=?", (operation_id, plan_id)).fetchone()
        return self._record(connection, operation_id, row[0], "approval") if row else None

    def _pending(self, connection, operation_id: str) -> list[str]:
        return [row[0] for row in connection.execute("""SELECT c.id FROM records c
            WHERE c.operation_id=? AND c.kind='command' AND NOT EXISTS (
                SELECT 1 FROM record_refs r JOIN records d
                ON d.operation_id=r.operation_id AND d.id=r.record_id
                WHERE r.operation_id=c.operation_id AND r.target_id=c.id
                AND r.role='command' AND d.kind='disposition') ORDER BY c.sequence""", (operation_id,))]

    def pending_commands(self, operation_id: str) -> list[str]:
        with self._connection() as connection:
            self._operation(connection, operation_id)
            return self._pending(connection, operation_id)

    def activate(self, operation_id: str, plan_id: str, *, expected_digest: str, actor: str) -> dict:
        """Activa un único plan, sin ejecutar ni cancelar recursos externos."""
        with self._connection(write=True) as connection:
            operation = self._operation(connection, operation_id)
            plan = self._record(connection, operation_id, plan_id, "plan")
            self._check_current(operation, plan)
            approval = self._approval(connection, operation_id, plan_id)
            if approval is None or approval["payload"]["plan_digest"] != plan["digest"] or expected_digest != plan["digest"]:
                raise LedgerError("exact_approval_required")
            from ..extensions import check_ledger_policy
            check_ledger_policy(self, "activate", operation=operation, plan=plan, approval=approval, actor=actor)
            if set(plan["payload"]["dispositions"]) != set(self._pending(connection, operation_id)):
                raise LedgerError("pending_dispositions_required")
            policy = plan["payload"]["content"].get("execution_policy")
            if policy:
                # Una revisión no crea una ventana nueva ni amplía la original.
                for row in connection.execute("SELECT plan_id FROM records WHERE operation_id=? AND kind='activation' ORDER BY sequence", (operation_id,)).fetchall():
                    previous = self._record(connection, operation_id, row[0], "plan")["payload"]["content"].get("execution_policy")
                    if previous and previous["modification_limit"] != policy["modification_limit"]:
                        raise LedgerError("budget_window_immutable")
                    if previous and "query_limit" in previous and previous["query_limit"] != policy.get("query_limit"):
                        raise LedgerError("query_budget_window_immutable")
            for command_id, choice in plan["payload"]["dispositions"].items():
                command = self._record(connection, operation_id, command_id, "command")
                if command["payload"].get("execution_contract") != 1:
                    continue
                claimed = connection.execute("SELECT 1 FROM records WHERE operation_id=? AND command_id=? AND kind='attempt'", (operation_id, command_id)).fetchone()
                if choice == "cancel" and claimed:
                    raise LedgerError("claimed_command_requires_reconciliation")
                if choice == "cancel":
                    self._insert(connection, operation_id, RecordDraft("disposition", {
                        "outcome": "cancelled", "reason": "plan_revision", "execution_contract": 1},
                        command["plan_id"], {"command": RecordReference(operation_id, "command", command_id)}), actor)
            activation = self._insert(connection, operation_id, RecordDraft("activation", {
                "previous_plan_id": operation["active_plan_id"], "previous_state": operation["state"],
                "state": "active", "revision": operation["revision"] + 1,
                "dispositions": plan["payload"]["dispositions"]}, plan_id,
                {"plan": RecordReference(operation_id, "plan", plan_id), "approval": RecordReference(operation_id, "approval", approval["id"])}), actor)
            connection.execute("UPDATE operations SET active_plan_id=?,state='active',revision=revision+1 WHERE id=?", (plan_id, operation_id))
            return activation

    def stop(self, operation_id: str, *, target: str, expected_revision: int, reason: str, actor: str) -> dict:
        """Suspende/cierra admisión y cancela órdenes B aún no reclamadas."""
        text_required(reason)
        if type(expected_revision) is not int or expected_revision < 0 or not isinstance(target, str):
            raise LedgerError("invalid_control_revision_or_state")
        with self._connection(write=True) as connection:
            operation = self._operation(connection, operation_id)
            if operation["revision"] != expected_revision:
                raise LedgerError("stale_revision")
            allowed = {"preparation": {"closing"}, "active": {"paused", "closing"}, "paused": {"closing"}, "closing": set(), "closed": set()}
            if target not in allowed[operation["state"]]:
                raise LedgerError("invalid_transition")
            return self._stop_in_transaction(connection, operation_id, operation, target, reason, actor)

    def _stop_in_transaction(self, connection, operation_id, operation, target, reason, actor):
        record = self._insert(connection, operation_id, RecordDraft("state", {
            "previous_state": operation["state"], "state": target,
            "reason": reason, "revision": operation["revision"] + 1}, operation["active_plan_id"]), actor)
        connection.execute("UPDATE operations SET state=?,revision=revision+1 WHERE id=?", (target, operation_id))
        for command_id in self._pending(connection, operation_id):
            command = self._record(connection, operation_id, command_id, "command")
            claimed = connection.execute("SELECT 1 FROM records WHERE operation_id=? AND command_id=? AND kind='attempt'", (operation_id, command_id)).fetchone()
            if command["payload"].get("execution_contract") == 1 and command["payload"].get("purpose") == "ordinary" and not claimed:
                self._insert(connection, operation_id, RecordDraft("disposition", {
                    "outcome": "cancelled", "reason": "operation_stop", "execution_contract": 1},
                    command["plan_id"], {"command": RecordReference(operation_id, "command", command_id)}), actor)
        return record

    def append(self, operation_id: str, drafts: list[RecordDraft], *, actor: str) -> list[dict]:
        """Persiste hechos relacionados en un único compromiso, sin despachar acciones.

        No usar como autorización: los hechos ejecutables de planes B solo
        los puede escribir OperationExecutor. Los lotes solo apuntan a registros
        anteriores o a elementos anteriores del mismo lote.
        """
        drafts = [freeze_draft(draft) for draft in drafts]
        with self._connection(write=True) as connection:
            self._operation(connection, operation_id)
            result = []
            for draft in drafts:
                if not isinstance(draft, RecordDraft):
                    raise LedgerError("invalid_record_draft")
                if draft.kind not in FACT_KINDS:
                    raise LedgerError("reserved_record_kind")
                if any(key in draft.payload for key in ("query_contract", "evidence_contract", "closure_contract")):
                    raise LedgerError("managed_fact_service_required")
                if draft.plan_id is not None and draft.kind in {"decision", "command", "attempt", "receipt", "disposition"}:
                    plan = self._record(connection, operation_id, draft.plan_id, "plan")
                    if plan["payload"]["content"].get("execution_policy"):
                        raise LedgerError("execution_service_required")
                self._validate_fact(connection, operation_id, draft)
                result.append(self._insert(connection, operation_id, draft, actor))
            return result

    def _validate_fact(self, connection, operation_id: str, draft: RecordDraft) -> None:
        if not isinstance(draft.payload, dict):
            raise LedgerError("invalid_payload")
        canonical(draft.payload)
        # Validar las referencias antes de usar contenido ajeno en una guarda.
        referenced = {}
        for role, ref in draft.references.items():
            if ref.operation_id != operation_id:
                raise LedgerError("cross_operation_reference")
            referenced[role] = self._record(connection, operation_id, ref.record_id, ref.kind)
        payload = draft.payload
        if draft.plan_id is not None:
            self._record(connection, operation_id, draft.plan_id, "plan")
        if draft.kind in {"decision", "command", "attempt"} and draft.plan_id is None:
            raise LedgerError("plan_required")
        if draft.kind == "decision":
            if payload.get("outcome") not in {"accepted", "rejected"} or payload.get("purpose") not in {"ordinary", "cleanup", "reconciliation"}:
                raise LedgerError("invalid_decision")
            text_required(payload.get("action"))
            if not isinstance(payload.get("guards"), dict) or not isinstance(payload.get("scope"), dict):
                raise LedgerError("invalid_decision")
        required_ref = {"command": ("decision", "decision"), "attempt": ("command", "command"),
                        "receipt": ("attempt", "attempt"), "disposition": ("command", "command")}.get(draft.kind)
        if required_ref:
            role, kind = required_ref
            linked = referenced.get(role)
            if linked is None or linked["kind"] != kind or linked["plan_id"] != draft.plan_id:
                raise LedgerError("invalid_lineage")
        if draft.kind == "command":
            decision = referenced["decision"]
            if decision["payload"]["outcome"] != "accepted" or decision["payload"]["action"] != payload.get("action"):
                raise LedgerError("rejected_or_different_decision")
            plan = self._record(connection, operation_id, draft.plan_id, "plan")
            if self._approval(connection, operation_id, draft.plan_id) is None:
                raise LedgerError("exact_approval_required")
            controlled = {item["plugin_id"] for item in plan["payload"]["content"].get("operation", {}).get("plugins", [])}
            if payload.get("capability_id") not in controlled:
                raise LedgerError("controlled_capability_required")
            if type(payload.get("max_attempts")) is not int or payload["max_attempts"] < 1 or not isinstance(payload.get("parameters"), dict):
                raise LedgerError("invalid_command")
            text_required(payload.get("idempotency_key"))
        elif draft.kind == "attempt":
            command = referenced["command"]
            if command["id"] not in self._pending(connection, operation_id):
                raise LedgerError("already_disposed")
            number = payload.get("number")
            previous = connection.execute("SELECT COALESCE(MAX(attempt_number),0) FROM records WHERE operation_id=? AND command_id=? AND kind='attempt'", (operation_id, command["id"])).fetchone()[0]
            if type(number) is not int or number != previous + 1 or number > command["payload"]["max_attempts"]:
                raise LedgerError("attempt_limit_or_sequence")
        elif draft.kind == "receipt":
            if payload.get("outcome") not in {"accepted", "confirmed", "failed", "unknown"}:
                raise LedgerError("invalid_receipt")
        elif draft.kind == "disposition":
            if payload.get("outcome") not in {"completed", "cancelled", "abandoned"}:
                raise LedgerError("invalid_disposition")
            command_id = referenced["command"]["id"]
            if command_id not in self._pending(connection, operation_id):
                raise LedgerError("already_disposed")
        elif draft.kind == "evidence":
            for name in ("source", "generation", "transformation"):
                text_required(payload.get(name))
            for name in ("external_id", "origin_time", "ingested_at", "raw_sha256"):
                if name not in payload:
                    raise LedgerError("evidence_unknowns_required")
            raw_digest = payload["raw_sha256"]
            if raw_digest is not None and (not isinstance(raw_digest, str) or len(raw_digest) != 64 or any(c not in "0123456789abcdef" for c in raw_digest)):
                raise LedgerError("invalid_raw_digest")
        elif draft.kind == "result":
            text_required(payload.get("criterion"))
            text_required(payload.get("judgment"))
