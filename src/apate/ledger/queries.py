"""Consultas lógicas con cupo durable separado de las modificaciones."""

from .repository import LedgerError, RecordDraft, RecordReference, now, text_required


def query_fact(category, source, **values):
    return {"category": category, "source": source, "generation": "local",
        "external_id": None, "origin_time": None, "ingested_at": now(),
        "raw_sha256": None, "transformation": "apate-query-v1", "query_contract": 1, **values}


class OperationQueries:
    def __init__(self, executor):
        self.executor = executor
        self.ledger = executor.ledger

    def run(self, operation_id, source_id, callback, *, purpose="observe", window=None):
        """Una admisión es una invocación: no hay reembolso ni replay automático.

        El callback pertenece al adaptador de lectura. El presupuesto limita
        lotes lógicos, no cada llamada del SDK, bytes o duración de red.
        """
        failure = None
        text_required(source_id)
        with self.ledger._connection(write=True) as connection:
            state, plan, definition = self.executor._context(connection, operation_id)
            policy = plan["payload"]["content"]["execution_policy"]
            read_policy = dict(policy, autonomous=policy.get("query_autonomous", False))
            authorize = getattr(self.executor, "authorize_query", self.executor.authorize)
            from .execution import OperationExecutor
            principal = OperationExecutor(self.ledger, authorize)._principal(operation_id, definition, read_policy)
            from ..extensions import check_ledger_policy
            check_ledger_policy(self.ledger, "query", operation=definition, plan=plan,
                principal=principal, capability_id=source_id, action="query", purpose=purpose)
            allowed = {b.plugin_id for b in definition.plugins} | {s.id for s in definition.telemetry_bridges}
            used = 0
            for row in connection.execute("SELECT id FROM records WHERE operation_id=? AND kind='evidence'", (operation_id,)).fetchall():
                body = self.ledger._record(connection, operation_id, row[0])["payload"]
                used += body.get("category") == "query_reservation" and body.get("outcome") == "accepted"
            limit = policy.get("query_limit")
            guards = {"approved_query_policy": type(limit) is int, "source": source_id in allowed,
                "purpose": purpose in {"observe", "status", "reconcile"},
                "budget": type(limit) is int and used < limit}
            failure = next((key for key, value in guards.items() if not value), None)
            draft = RecordDraft("evidence", query_fact(
                "query_reservation", source_id, outcome="rejected" if failure else "accepted",
                guards=guards, reason=failure, purpose=purpose, window=window,
                budget_window=operation_id, reserved_units=0 if failure else 1), plan["id"])
            self.ledger._validate_fact(connection, operation_id, draft)
            ticket = self.ledger._insert(connection, operation_id, draft, principal.actor)
        if failure:
            raise LedgerError("query_" + failure)
        try:
            result = callback()
        except Exception as error:
            self._receipt(operation_id, ticket, outcome="unknown", error_code=type(error).__name__)
            raise
        self._receipt(operation_id, ticket, outcome="returned", error_code=None)
        return result

    def _receipt(self, operation_id, ticket, *, outcome, error_code):
        with self.ledger._connection(write=True) as connection:
            draft = RecordDraft("evidence", query_fact(
                "query_receipt", ticket["payload"]["source"], outcome=outcome, error_code=error_code,
                window=ticket["payload"]["window"], coverage="unknown",
                meaning="adapter_returned_not_complete_source_coverage"), ticket["plan_id"],
                {"query": RecordReference(operation_id, "evidence", ticket["id"])})
            self.ledger._validate_fact(connection, operation_id, draft)
            record = self.ledger._insert(connection, operation_id, draft, "system:query")
            if self.ledger._operation(connection, operation_id)["state"] == "closed":
                from .evidence import OperationEvidence
                OperationEvidence(self.ledger)._addendum(connection, operation_id, record)
            return record

    def status(self, operation_id):
        reservations = [r for r in self.ledger.history(operation_id) if r["payload"].get("category") == "query_reservation"]
        receipts = {r["references"]["query"]["record_id"]: r["payload"]["outcome"] for r in self.ledger.history(operation_id)
            if r["payload"].get("category") == "query_receipt"}
        return {"reserved_queries": sum(r["payload"]["outcome"] == "accepted" for r in reservations),
            "unknown_queries": [r["id"] for r in reservations if r["payload"]["outcome"] == "accepted" and receipts.get(r["id"]) != "returned"]}
