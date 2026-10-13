"""Evaluación determinista y transiciones humanas de atención."""

from __future__ import annotations

from datetime import datetime, timezone

from ..telemetry.models import TelemetryRecord
from .models import Case, Signal, SignalEvidence, SignalRule
from .repository import SQLiteAttentionRepository

DEFAULT_RULES = (
    SignalRule(
        id="honeyuser-authentication-success", version="1", field="payload.kind",
        equals="honeyuser_authentication_success", severity="high",
        title="Autenticación de honeyuser observada",
        description="Una identidad señuelo fue utilizada; revisar la autenticación y su origen.",
        dedupe_fields=("plugin_id", "resource_id"),
    ),
)


class AttentionService:
    def __init__(self, repository: SQLiteAttentionRepository, telemetry_repository, *, rules=DEFAULT_RULES) -> None:
        self.repository = repository
        self.telemetry_repository = telemetry_repository
        self.rules = tuple(rules)

    @staticmethod
    def _field(record: TelemetryRecord, field: str) -> str:
        value = record.payload.get("kind") if field == "payload.kind" else getattr(record, field)
        return value.value if hasattr(value, "value") else str(value or "")

    def on_record(self, record: TelemetryRecord) -> list[Signal]:
        """Se llama solo después de persistir un evento; nunca despliega."""

        result = []
        for rule in self.rules:
            if not rule.enabled or self._field(record, rule.field) != rule.equals:
                continue
            key = "|".join([rule.id, *[self._field(record, field) for field in rule.dedupe_fields]]) if rule.dedupe_fields else ""
            signal = Signal(
                operation_id=record.operation_id, title=rule.title, description=rule.description,
                severity=rule.severity, origin="rule", rule_id=rule.id, rule_version=rule.version,
                dedupe_key=key, evidence=[SignalEvidence("telemetry_event", record.id)],
            )
            result.append(self.repository.create_or_append(signal)[0])
        return result

    def create_manual(self, operation_id: str, *, title: str, description: str, severity: str,
                      event_ids: list[str], note: str, operator: str) -> Signal:
        known = {record.id for record in self.telemetry_repository.list_for_operation(operation_id)}
        selected = list(dict.fromkeys(event_ids))
        if any(event_id not in known for event_id in selected):
            raise ValueError("La evidencia no pertenece a esta operación.")
        evidence = [SignalEvidence("telemetry_event", event_id) for event_id in selected]
        if note.strip():
            evidence.append(SignalEvidence("manual_note", note.strip(), operator))
        signal = Signal(operation_id=operation_id, title=title.strip(), description=description.strip(),
                        severity=severity, origin="manual", evidence=evidence)
        self.repository.save_signal(signal)
        return signal

    def transition_signal(self, operation_id: str, signal_id: str, action: str, *, note: str = "") -> Signal:
        signal = self.repository.get_signal(operation_id, signal_id)
        allowed = {"open": {"acknowledge": "acknowledged", "resolve": "resolved"},
                   "acknowledged": {"resolve": "resolved"}, "resolved": {"reopen": "open"}}
        if action not in allowed[signal.status]:
            raise ValueError("Transición de señal no permitida.")
        if action in {"resolve", "reopen"} and not note.strip():
            raise ValueError("Resolver o reabrir exige una nota.")
        signal.status = allowed[signal.status][action]
        signal.updated_at = datetime.now(timezone.utc)
        signal.resolved_at = signal.updated_at if action == "resolve" else None
        signal.resolution_note = note.strip() if action == "resolve" else ""
        if action == "reopen":
            signal.evidence.append(SignalEvidence("manual_note", note.strip()))
        self.repository.save_signal(signal)
        return signal

    def assign_signal(self, operation_id: str, signal_id: str, responsible: str) -> Signal:
        signal = self.repository.get_signal(operation_id, signal_id)
        signal.responsible = responsible.strip()
        signal.updated_at = datetime.now(timezone.utc)
        self.repository.save_signal(signal)
        return signal

    def create_case(self, operation_id: str, *, title: str, description: str, signal_ids: list[str]) -> Case:
        case = Case(operation_id=operation_id, title=title.strip(), description=description.strip(),
                    signal_ids=list(dict.fromkeys(signal_ids)))
        self.repository.save_case(case)
        return case

    def update_case_signals(self, operation_id: str, case_id: str, *, add: list[str] = (), remove: list[str] = ()) -> Case:
        case = self.repository.get_case(operation_id, case_id)
        case.signal_ids = [signal_id for signal_id in case.signal_ids if signal_id not in remove]
        case.signal_ids.extend(signal_id for signal_id in add if signal_id not in case.signal_ids)
        if not case.signal_ids:
            raise ValueError("Un caso no puede quedar sin señales.")
        case.updated_at = datetime.now(timezone.utc)
        self.repository.save_case(case)
        return case

    def transition_case(self, operation_id: str, case_id: str, action: str, *, note: str) -> Case:
        case = self.repository.get_case(operation_id, case_id)
        if (case.status, action) not in {("open", "resolve"), ("resolved", "reopen")} or not note.strip():
            raise ValueError("Transición de caso inválida o sin nota.")
        case.status = "resolved" if action == "resolve" else "open"
        case.updated_at = datetime.now(timezone.utc)
        case.resolved_at = case.updated_at if action == "resolve" else None
        case.resolution_note = note.strip() if action == "resolve" else ""
        self.repository.save_case(case)
        return case

    def assign_case(self, operation_id: str, case_id: str, responsible: str) -> Case:
        case = self.repository.get_case(operation_id, case_id)
        case.responsible = responsible.strip()
        case.updated_at = datetime.now(timezone.utc)
        self.repository.save_case(case)
        return case
