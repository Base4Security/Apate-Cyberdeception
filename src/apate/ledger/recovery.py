"""Reconstrucción idempotente de telemetría admitida, sin replay del motor."""
from ..plugins.base import PluginEvent
from ..telemetry.models import TelemetryRecord


def recover_telemetry(ledger, repository, operation_id):
    created = existing = 0
    for record in ledger.history(operation_id):
        if record["kind"] != "evidence" or record["payload"].get("category") != "observation":
            continue
        event = PluginEvent.from_dict(record["payload"]["event"])
        event.provenance = {"ledger_evidence_id": record["id"]}
        normalized = TelemetryRecord.from_event(event)
        if repository.append_recovered(normalized):
            created += 1
        else:
            existing += 1
    return {"created": created, "existing": existing, "actions_replayed": 0}
