"""Vistas aisladas para que un conector no relea un plan editable."""

from ..deployment.models import DeploymentPlan, DeploymentRecord
from .repository import LedgerError, json_snapshot


class FrozenDeploymentRepository:
    def __init__(self, repository, plan, record):
        self.repository = repository
        self.plan = plan.to_dict()
        self.record = record.to_dict() if record else None

    def get_plan(self, identifier):
        if identifier != self.plan["id"]:
            raise LedgerError("resource_plan_mismatch")
        return DeploymentPlan.from_dict(json_snapshot(self.plan))

    def get_record(self, identifier):
        if self.record is None or identifier != self.record["id"]:
            raise LedgerError("approved_resource_required")
        return DeploymentRecord.from_dict(json_snapshot(self.record))

    def find_record_for_plan(self, identifier):
        self.get_plan(identifier)
        return DeploymentRecord.from_dict(json_snapshot(self.record)) if self.record else None

    def save_record(self, record):
        if record.plan_id != self.plan["id"] or record.operation_id != self.plan["operation_id"]:
            raise LedgerError("resource_plan_mismatch")
        self.repository.save_record(record)
        self.record = record.to_dict()


class FrozenCredentialStore:
    def __init__(self, reference, values, operational_store):
        self.reference = reference
        self.values = json_snapshot(values)
        self.operational_store = operational_store

    def get(self, reference):
        return dict(self.values) if reference == self.reference else self.operational_store.get(reference)

    def exists(self, reference):
        return reference == self.reference or self.operational_store.exists(reference)

    def save(self, reference, values):
        if reference == self.reference:
            raise LedgerError("immutable_target_credential")
        self.operational_store.save(reference, values)
