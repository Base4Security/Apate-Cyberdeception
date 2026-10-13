"""Modelos persistentes de atención sin inferir causalidad ni respuestas."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4

SEVERITIES = ("informational", "low", "medium", "high", "critical")
SIGNAL_STATUSES = ("open", "acknowledged", "resolved")
CASE_STATUSES = ("open", "resolved")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SignalEvidence:
    kind: str
    value: str
    operator: str = ""

    def __post_init__(self) -> None:
        if self.kind not in {"telemetry_event", "manual_note"} or not self.value.strip():
            raise ValueError("La evidencia debe ser un evento o una nota no vacía.")

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "operator": self.operator}

    @classmethod
    def from_dict(cls, data: dict) -> "SignalEvidence":
        return cls(**data)


@dataclass
class Signal:
    operation_id: str
    title: str
    description: str
    severity: str
    origin: str
    evidence: list[SignalEvidence]
    id: str = field(default_factory=lambda: str(uuid4()))
    status: str = "open"
    responsible: str = ""
    rule_id: str = ""
    rule_version: str = ""
    dedupe_key: str = ""
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)
    resolved_at: datetime | None = None
    resolution_note: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES or self.status not in SIGNAL_STATUSES:
            raise ValueError("Severidad o estado de señal inválido.")
        if self.origin not in {"rule", "manual"} or not self.evidence or not self.title.strip():
            raise ValueError("La señal requiere título, origen y evidencia.")
        if self.origin == "rule" and (not self.rule_id or not self.rule_version):
            raise ValueError("Una señal automática requiere regla y versión.")

    def to_dict(self) -> dict:
        return {**self.__dict__, "evidence": [item.to_dict() for item in self.evidence],
                "created_at": self.created_at.isoformat(), "updated_at": self.updated_at.isoformat(),
                "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None}

    @classmethod
    def from_dict(cls, data: dict) -> "Signal":
        return cls(**{**data, "evidence": [SignalEvidence.from_dict(item) for item in data["evidence"]],
                      "created_at": datetime.fromisoformat(data["created_at"]),
                      "updated_at": datetime.fromisoformat(data["updated_at"]),
                      "resolved_at": datetime.fromisoformat(data["resolved_at"]) if data.get("resolved_at") else None})


@dataclass
class Case:
    operation_id: str
    title: str
    signal_ids: list[str]
    id: str = field(default_factory=lambda: str(uuid4()))
    description: str = ""
    status: str = "open"
    responsible: str = ""
    resolution_note: str = ""
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)
    resolved_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.title.strip() or not self.signal_ids or self.status not in CASE_STATUSES:
            raise ValueError("El caso requiere título, señales y estado válido.")

    def to_dict(self) -> dict:
        return {**self.__dict__, "created_at": self.created_at.isoformat(),
                "updated_at": self.updated_at.isoformat(),
                "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None}

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        return cls(**{**data, "created_at": datetime.fromisoformat(data["created_at"]),
                      "updated_at": datetime.fromisoformat(data["updated_at"]),
                      "resolved_at": datetime.fromisoformat(data["resolved_at"]) if data.get("resolved_at") else None})


@dataclass(frozen=True)
class SignalRule:
    """Solo evalúa campos persistidos y crea atención; no ejecuta plugins."""

    id: str
    version: str
    field: str
    equals: str
    severity: str
    title: str
    description: str
    dedupe_fields: tuple[str, ...] = ()
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES or self.field not in {"event_type", "plugin_id", "surface", "ttp_id", "resource_id", "payload.kind"}:
            raise ValueError("Regla de señal con campo o severidad inválidos.")
        if any(field not in {"plugin_id", "surface", "ttp_id", "resource_id"} for field in self.dedupe_fields):
            raise ValueError("La deduplicación solo admite campos estructurados.")
