"""Procedencia admitida, corte de cierre y adendas sin sobrescribir resultados."""

from .repository import LedgerError, RecordDraft, RecordReference, digest, now, text_required


class OperationEvidence:
    def __init__(self, ledger):
        self.ledger = ledger

    def ingest(self, operation_id, event):
        """El ID de operación procede del integrador, nunca de un campo externo."""
        if event.operation_id != operation_id:
            raise LedgerError("cross_operation_event")
        metadata = getattr(event, "provenance", None) or {}
        with self.ledger._connection(write=True) as connection:
            state = self.ledger._operation(connection, operation_id)
            plan_id = state["active_plan_id"]
            plan = self.ledger._record(connection, operation_id, plan_id, "plan") if plan_id else None
            definition = plan["payload"]["content"]["operation"] if plan else {}
            sources = {b["plugin_id"] for b in definition.get("plugins", [])} | {s["id"] for s in definition.get("telemetry_bridges", [])}
            accepted = event.plugin_id in sources
            raw = metadata.get("raw")
            normalized = event.to_dict()
            normalized.pop("provenance", None)
            raw = normalized if raw is None else raw
            raw_hash = digest(raw)
            generation = metadata.get("generation")
            external_id = metadata.get("external_id")
            if generation is not None and (not isinstance(generation, str) or not generation.strip()):
                raise LedgerError("invalid_source_generation")
            if external_id is not None and (not isinstance(external_id, str) or not external_id.strip()):
                raise LedgerError("invalid_external_event_id")
            previous = None
            for row in connection.execute("SELECT id FROM records WHERE operation_id=? AND kind='evidence' ORDER BY sequence", (operation_id,)).fetchall():
                candidate = self.ledger._record(connection, operation_id, row[0])
                body = candidate["payload"]
                if body.get("category") not in {"observation", "lifecycle"}:
                    continue
                if body.get("event", {}).get("id") == event.id:
                    previous = candidate
                    break
                if generation is not None and external_id is not None and body["source"] == event.plugin_id and body.get("source_generation") == generation and body["external_id"] == external_id:
                    previous = candidate
                    break
            if previous and previous["payload"]["raw_sha256"] == raw_hash:
                return previous, False
            reason = "source_not_approved" if not accepted else "external_identity_conflict" if previous else None
            exposure = metadata.get("exposure_plan")
            refs = {}
            if exposure is not None:
                self.ledger._record(connection, operation_id, exposure, "plan")
                refs["exposure_plan"] = RecordReference(operation_id, "plan", exposure)
            from ..plugins.base import is_lifecycle_event
            body = {"category": "quarantine" if reason else "lifecycle" if is_lifecycle_event(event) else "observation",
                "evidence_contract": 1, "source": event.plugin_id, "generation": generation or "unknown",
                "source_generation": generation, "external_id": external_id,
                "origin_time": metadata.get("origin_time"), "ingested_at": now(),
                "raw_sha256": raw_hash, "raw": raw, "event": normalized,
                "transformation": metadata.get("transformation", "apate-plugin-event-v1"),
                "mapping_sha256": metadata.get("mapping_sha256"), "plan_at_ingest": plan_id,
                "exposure_plan": exposure, "exposure_basis": "declared_by_adapter" if exposure else "unknown",
                "deduplication": "stable_identity" if generation is not None and external_id is not None else "event_id_only",
                "origin_authenticity": "not_established", "coverage": "unknown", "reason": reason}
            draft = RecordDraft("evidence", body, plan_id, refs)
            self.ledger._validate_fact(connection, operation_id, draft)
            record = self.ledger._insert(connection, operation_id, draft, "system:ingest")
            if state["state"] == "closed":
                self._addendum(connection, operation_id, record)
            return record, not reason

    def coverage(self, operation_id, source_id, *, window, status, reason, actor, query_id=None):
        """Conserva una declaración de cobertura; no la deduce de un HTTP 200."""
        if status not in {"complete", "partial", "gap", "unknown"}:
            raise LedgerError("invalid_source_coverage")
        text_required(reason)
        with self.ledger._connection(write=True) as connection:
            state = self.ledger._operation(connection, operation_id)
            plan = self.ledger._record(connection, operation_id, state["active_plan_id"], "plan")
            definition = plan["payload"]["content"]["operation"]
            sources = {b["plugin_id"] for b in definition["plugins"]} | {s["id"] for s in definition["telemetry_bridges"]}
            if source_id not in sources:
                raise LedgerError("source_not_approved")
            refs = {}
            if query_id:
                query = self.ledger._record(connection, operation_id, query_id, "evidence")
                if query["payload"].get("category") != "query_reservation" or query["payload"]["source"] != source_id:
                    raise LedgerError("source_query_mismatch")
                refs["query"] = RecordReference(operation_id, "evidence", query_id)
            body = {"category": "source_coverage", "evidence_contract": 1, "source": source_id,
                "generation": "unknown", "external_id": None, "origin_time": None, "ingested_at": now(),
                "raw_sha256": None, "transformation": "coverage-declaration-v1", "window": window,
                "coverage": status, "reason": reason, "basis": "adapter_or_operator_declaration"}
            draft = RecordDraft("evidence", body, plan["id"], refs)
            self.ledger._validate_fact(connection, operation_id, draft)
            record = self.ledger._insert(connection, operation_id, draft, actor)
            if state["state"] == "closed":
                self._addendum(connection, operation_id, record)
            return record

    def find_event(self, operation_id, event_id):
        return next((r for r in self.ledger.history(operation_id) if r["kind"] == "evidence"
            and r["payload"].get("category") in {"observation", "lifecycle"}
            and r["payload"].get("event", {}).get("id") == event_id), None)

    def _addendum(self, connection, operation_id, record):
        rows = connection.execute("SELECT id FROM records WHERE operation_id=? AND kind='result' ORDER BY sequence", (operation_id,)).fetchall()
        for row in rows:
            result = self.ledger._record(connection, operation_id, row[0])
            if result["payload"].get("category") == "closure":
                return self.ledger._insert(connection, operation_id, RecordDraft("result", {
                    "category": "addendum", "closure_contract": 1, "criterion": "post_cut_record",
                    "judgment": "Registro posterior al corte; no modifica el juicio de cierre.",
                    "previous_cut": result["payload"]["cut_sequence"]}, record["plan_id"],
                    {"closure": RecordReference(operation_id, "result", result["id"]),
                     "late_record": RecordReference(operation_id, record["kind"], record["id"])}), "system:addendum")

    def close(self, operation_id, *, expected_revision, criterion, judgment, actor):
        text_required(criterion)
        text_required(judgment)
        with self.ledger._connection(write=True) as connection:
            state = self.ledger._operation(connection, operation_id)
            if state["state"] != "closing" or type(expected_revision) is not int or state["revision"] != expected_revision:
                raise LedgerError("closing_revision_required")
            if state["active_plan_id"] is None:
                raise LedgerError("active_approved_plan_required")
            cut = state["sequence"]
            facts = [self.ledger._record(connection, operation_id, row[0]) for row in connection.execute("SELECT id FROM records WHERE operation_id=? ORDER BY sequence", (operation_id,)).fetchall()]
            observations = [r for r in facts if r["payload"].get("category") == "observation"]
            resources = {}
            for fact in facts:
                if fact["kind"] != "receipt" or not fact["payload"].get("adapter_state"):
                    continue
                attempt = self.ledger._record(connection, operation_id, fact["references"]["attempt"]["record_id"])
                command = self.ledger._record(connection, operation_id, attempt["references"]["command"]["record_id"])
                resources[command["payload"]["capability_id"]] = fact["payload"]["adapter_state"]
            plan = self.ledger._record(connection, operation_id, state["active_plan_id"], "plan") if state["active_plan_id"] else None
            definition = plan["payload"]["content"]["operation"] if plan else {}
            pending_resources = []
            for binding in definition.get("plugins", []):
                identifier = binding["plugin_id"]
                receipt = resources.get(identifier)
                config = (receipt or {}).get("config", {})
                retained = [r for r in config.get("_managed_resources", []) if not r.get("removed")]
                deployment = (receipt or {}).get("deployment_record")
                retired = (receipt or {}).get("state") == "retired" or (deployment or {}).get("status") == "retired"
                if receipt is None or not retired or retained:
                    pending_resources.append({"capability_id": identifier, "status": "unknown" if receipt is None else "pending",
                        "retained_resources": retained})
            expected = set(state["baseline"].get("adversary_profile", {}).get("expected_ttps", []))
            observed = {r["payload"]["event"]["payload"]["ttp_id"] for r in observations if isinstance(r["payload"]["event"]["payload"].get("ttp_id"), str)
                and r["payload"]["event"]["payload"].get("source") != "defender_simulation"}
            supporting = [r for r in facts if r["kind"] == "evidence" and r["payload"].get("category") in {"observation", "query_receipt", "source_coverage"}]
            refs = {"evidence:" + str(i): RecordReference(operation_id, "evidence", r["id"]) for i, r in enumerate(supporting)}
            body = {"category": "closure", "closure_contract": 1, "criterion": criterion, "judgment": judgment,
                "cut_sequence": cut, "cut_at": now(), "baseline_digest": state["baseline_digest"],
                "plan_ids": [r["id"] for r in facts if r["kind"] == "plan"],
                "evidence_ids": [r["id"] for r in observations], "coverage": "unknown",
                "source_windows": [r["payload"] for r in facts if r["payload"].get("category") in {"query_receipt", "source_coverage"}],
                "pending_commands": self.ledger._pending(connection, operation_id),
                "pending_resources": pending_resources, "resource_states": resources,
                "ttp_contrast": {"expected_observed": sorted(expected & observed), "expected_not_observed": sorted(expected - observed), "unexpected_observed": sorted(observed - expected)},
                "limits": ["No observada no significa ausente.", "Retirar BUDA no revierte efectos PowerShell.", "Un recibo local no demuestra retirada física."]}
            result = self.ledger._insert(connection, operation_id, RecordDraft("result", body, state["active_plan_id"], refs), actor)
            self.ledger._stop_in_transaction(connection, operation_id, state, "closed", "result_recorded", actor)
            return result


class EvidenceBus:
    """La persistencia precede a colector y reglas; las proyecciones son separadas."""
    def __init__(self, ledger, operation_id, bus):
        self.service = OperationEvidence(ledger)
        self.operation_id = operation_id
        self.bus = bus

    def subscribe(self, event_type, handler):
        return self.bus.subscribe(event_type, handler)

    def publish(self, event):
        record, admitted = self.service.ingest(self.operation_id, event)
        if admitted:
            event.provenance = dict(getattr(event, "provenance", None) or {}, ledger_evidence_id=record["id"])
            return self.bus.publish(event)
