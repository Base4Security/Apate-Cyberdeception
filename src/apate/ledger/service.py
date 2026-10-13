"""Adopción explícita del documento heredado y congelación del diseño revisable."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ..assets import JSONFileAssetRepository
from ..core import ApateError, JSONFileBehaviorContextRepository, Operation
from ..rules import parse_rules
from ..secrets import EncryptedJSONFileOperationRepository, SecretCipher
from .repository import LedgerError, SQLiteOperationLedger, now, validate_entity_ids


class OperationPlanService:
    """Puente local al editor; la ejecución adoptada usa su plan aprobado.

    Los archivos JSON/YAML son documentos de trabajo, no una proyección de la
    historia aprobada. Cambiarlos nunca reescribe H ni una propuesta congelada.
    """

    def __init__(self, ledger, operations, rules_path, *, contexts=None, assets=None, deployments=None, credentials=None, buda_snapshotter=None):
        self.ledger = ledger
        self.operations = operations
        self.rules_path = Path(rules_path)
        self.contexts = contexts
        self.assets = assets
        self.deployments = deployments
        self.credentials = credentials
        self.buda_snapshotter = buda_snapshotter
        from .adoption import AdoptionGate
        self.adoption_gate = AdoptionGate(ledger.path.parent / "operation_admission.db")

    @classmethod
    def from_data_dir(cls, data_dir: str | Path, rules_path: str | Path):
        directory = Path(data_dir)
        from ..deployment.repository import JSONFileDeploymentRepository
        from ..deployment.credentials import EncryptedJSONCredentialStore
        from ..deployment.vault_credentials import VaultCredentialStore
        import os
        cipher = SecretCipher.from_environment_or_data_dir(directory)
        return cls(SQLiteOperationLedger(directory / "operation_ledger.db", cipher),
            EncryptedJSONFileOperationRepository(directory / "operations", cipher), rules_path,
            contexts=JSONFileBehaviorContextRepository(directory / "behavior_context"),
            assets=JSONFileAssetRepository(directory / "assets"),
            deployments=JSONFileDeploymentRepository(directory / "deployments"),
            credentials=VaultCredentialStore.from_environment() if os.environ.get("APATE_VAULT_ADDR") else EncryptedJSONCredentialStore(directory / "deployment_credentials", cipher))

    @staticmethod
    def _safe_id(operation_id: str):
        if not isinstance(operation_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", operation_id):
            raise LedgerError("invalid_operation_id")

    def _context_snapshots(self, operation: Operation) -> list[dict]:
        result = []
        for source_id in operation.behavior_context_source_ids:
            self._safe_id(source_id)
            if self.contexts is None:
                result.append({"id": source_id, "availability": "unknown", "snapshot": None})
                continue
            try:
                source = self.contexts.get(source_id)
            except KeyError:
                result.append({"id": source_id, "availability": "missing", "snapshot": None})
            else:
                if not source.integrity_ok:
                    raise LedgerError("context_integrity_mismatch")
                result.append({"id": source_id, "availability": "captured", "snapshot": source.to_dict()})
        return result

    def _asset_snapshots(self, operation: Operation) -> list[dict]:
        identifiers = sorted(set(operation.adversary_profile.target_assets) |
            {identifier for binding in operation.plugins for identifier in binding.protected_asset_ids})
        result = []
        for identifier in identifiers:
            try:
                asset = self.assets.get(identifier) if self.assets else None
            except KeyError:
                asset = None
            result.append({"identifier": identifier, "availability": "captured" if asset else "unknown",
                           "snapshot": asset.to_dict() if asset else None})
        return result

    def prepare_adoption(self, operation_id):
        self._safe_id(operation_id)
        operation = self.operations.get(operation_id)
        from ..plugins.registry import PluginRegistry
        executors = [{"capability_id": b.plugin_id, "kind": PluginRegistry.resolve_binding_kind(b)}
            for b in operation.plugins if PluginRegistry.resolve_binding_kind(b) in {"buda", "dolost", "opencanary", "playground"}]
        records = self.deployments.list_records_for_operation(operation_id) if self.deployments else []
        inventory = {"external_executors": executors, "legacy_document_sha256": hashlib.sha256(self.operations._path_for(operation_id).read_bytes()).hexdigest(),
            "deployment_resources": [{"record_id": r.id, "status": r.status.value} for r in records],
            "remote_worker_state": "unknown" if executors else "not_registered"}
        return self.adoption_gate.fence(operation_id, inventory)

    def adopt(self, operation_id: str, *, actor: str, quiescence=None) -> dict:
        """Importa la foto actual una vez, sin inferir su pasado."""
        self._safe_id(operation_id)
        report = self.prepare_adoption(operation_id)
        adoption = self.adoption_gate.complete(operation_id, report, quiescence, actor)
        # Leer el documento original permite distinguir fechas/IDs ausentes de
        # los valores por defecto que añade Operation.from_dict por compatibilidad.
        path = self.operations._path_for(operation_id)
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != report["inventory"]["legacy_document_sha256"]:
            raise LedgerError("stale_adoption_document")
        original = json.loads(raw)
        validate_entity_ids(original)
        if original.get("id") != operation_id or original.get("status") not in {"planning", "active", "compromised", "closed"}:
            raise LedgerError("ambiguous_legacy_identity_or_state")
        operation = self.operations.get(operation_id)
        state = {"planning": "preparation", "active": "active", "compromised": "active", "closed": "closed"}[original["status"]]
        baseline = {
            "schema_version": 1, "captured_at": now(), "historical_provenance": "unknown",
            "adversary_profile": operation.adversary_profile.to_dict(),
            "context_sources": self._context_snapshots(operation),
            "assets": self._asset_snapshots(operation),
            "legacy_status": original["status"], "legacy_compromised_signal": original["status"] == "compromised",
            "legacy_created_at": original.get("created_at"), "legacy_updated_at": original.get("updated_at"),
            "legacy_document_sha256": hashlib.sha256(raw).hexdigest(),
            "legacy_snapshot": operation.to_dict(),
            "adoption_protocol": adoption,
        }
        # Las fechas normalizadas del snapshot no se presentan como originales:
        # las claves legacy_* anteriores conservan los desconocidos explícitos.
        for key in ("created_at", "updated_at", "closed_at"):
            baseline["legacy_snapshot"][key] = original.get(key)
        if path.read_bytes() != raw:
            raise LedgerError("stale_adoption_document")
        result = self.ledger.adopt(operation_id, baseline, state=state, origin="legacy_import", actor=actor)
        self.adoption_gate.adopted(operation_id)
        return result

    def migrate(self, *, actor: str) -> dict:
        """Importación repetible, con errores aislados por archivo y sin borrados."""
        report = {"schema_version": 1, "imported": [], "already_present": [], "changed_since_import": [], "rejected": []}
        for path in sorted(self.operations._dir.glob("*.json")):
            try:
                self._safe_id(path.stem)
                try:
                    existing = self.ledger.operation(path.stem)
                except LedgerError as error:
                    if error.code != "operation_not_found":
                        raise
                else:
                    report["already_present"].append(path.stem)
                    if existing["baseline"].get("legacy_document_sha256") != hashlib.sha256(path.read_bytes()).hexdigest():
                        report["changed_since_import"].append(path.stem)
                    continue
                self.adopt(path.stem, actor=actor)
                report["imported"].append(path.stem)
            except (ApateError, OSError, ValueError, KeyError, TypeError) as error:
                if isinstance(error, LedgerError) and error.code == "already_adopted":
                    report["already_present"].append(path.stem)
                    continue
                report["rejected"].append({"file": path.name,
                    "code": error.code if isinstance(error, LedgerError) else type(error).__name__})
        return report

    def capture_design(self, operation_id: str) -> dict:
        """Separa intención de resultados/cursor y guarda reglas y catálogos exactos."""
        self._safe_id(operation_id)
        original = json.loads(self.operations._path_for(operation_id).read_bytes())
        validate_entity_ids(original)
        if original.get("id") != operation_id:
            raise LedgerError("invalid_plan_identity")
        operation = self.operations.get(operation_id)
        definition = operation.to_dict()
        for key in ("status", "created_at", "updated_at", "closed_at"):
            definition.pop(key)
        for binding in definition["plugins"]:
            for key in ("measured_outcome", "measured_at", "measured_by", "evidence_event_ids"):
                binding["effect"].pop(key)
        for source in definition["telemetry_bridges"]:
            source.pop("last_fetch_at")
        rules_raw = self.rules_path.read_bytes()
        rules_text = rules_raw.decode("utf-8")
        try:
            parse_rules(rules_text)
        except (ApateError, ValueError, KeyError, TypeError, AttributeError) as error:
            raise LedgerError("invalid_rules_snapshot") from error
        catalogs = []
        for filename in ("mitre_attack_groups.json", "mitre_engage_matrix.json", "engage_ttp_suggestions.json", "engage_objective_suggestions.json"):
            raw = (Path(__file__).resolve().parent.parent / "data" / filename).read_bytes()
            catalogs.append({"name": filename, "sha256": hashlib.sha256(raw).hexdigest(), "content": raw.decode("utf-8")})
        return {"schema_version": 1, "operation": definition,
            "rules": {"sha256": hashlib.sha256(rules_raw).hexdigest(), "content": rules_text},
            "catalogs": catalogs, "context_sources": self._context_snapshots(operation),
            "assets": self._asset_snapshots(operation),
            "external_resource_versions": {"status": "not_captured", "items": []}}

    def propose(self, operation_id: str, *, parent_id: str | None, reason: str, actor: str,
                findings=None, dispositions=None, execution_policy=None) -> dict:
        content = self.capture_design(operation_id)
        if execution_policy is not None:
            from .execution import validate_policy
            from .repository import digest, json_snapshot
            validate_policy(execution_policy, operation_id)
            content["execution_policy"] = json_snapshot(execution_policy)
            snapshots = [plan.to_dict() for plan in self.deployments.list_plans_for_operation(operation_id)] if self.deployments else []
            records = [record.to_dict() for record in self.deployments.list_records_for_operation(operation_id)] if self.deployments else []
            items = [{"kind": "deployment_plan", "id": item["id"], "sha256": digest(item), "snapshot": item} for item in snapshots]
            items.extend({"kind": "deployment_record", "id": item["id"], "sha256": digest(item), "snapshot": item} for item in records)
            for reference in sorted({item["target"]["credential_ref"] for item in snapshots if item["target"].get("credential_ref")}):
                if self.credentials is None:
                    raise LedgerError("credential_snapshot_required")
                values = self.credentials.get(reference)
                items.append({"kind": "target_credential", "id": reference, "sha256": digest(values), "snapshot": values})
            from .descriptors import capture_descriptor
            for binding in Operation.from_dict(content["operation"]).plugins:
                snapshot = capture_descriptor(binding, buda_snapshotter=self.buda_snapshotter)
                if snapshot is not None:
                    items.append({"kind": "plugin_descriptor", "id": binding.plugin_id,
                        "sha256": digest(snapshot), "snapshot": snapshot})
            content["external_resource_versions"] = {"status": "captured_execution_resources", "items": items,
                "unsupported_adapters": []}
        return self.ledger.propose(operation_id, content, parent_id=parent_id,
            reason=reason, actor=actor, findings=findings, dispositions=dispositions)
