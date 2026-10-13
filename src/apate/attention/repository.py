"""Persistencia SQLite transaccional de señales, evidencias y casos."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ..schema_version import apply_sqlite_version
from .models import Case, Signal


class SQLiteAttentionRepository:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS signals (
                    id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
                    status TEXT NOT NULL, severity TEXT NOT NULL,
                    responsible TEXT NOT NULL, dedupe_key TEXT NOT NULL,
                    created_at TEXT NOT NULL, document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS signals_operation_status ON signals(operation_id, status, severity);
                CREATE INDEX IF NOT EXISTS signals_dedupe ON signals(operation_id, dedupe_key, status);
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, document TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS cases_operation_status ON cases(operation_id, status);
                """
            )
            apply_sqlite_version(db)

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _write_signal(db, signal: Signal) -> None:
        db.execute(
            """INSERT INTO signals(id, operation_id, status, severity, responsible, dedupe_key, created_at, document)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET status=excluded.status, severity=excluded.severity,
               responsible=excluded.responsible, dedupe_key=excluded.dedupe_key, document=excluded.document""",
            (signal.id, signal.operation_id, signal.status, signal.severity, signal.responsible,
             signal.dedupe_key, signal.created_at.isoformat(), json.dumps(signal.to_dict(), ensure_ascii=False)),
        )

    def save_signal(self, signal: Signal) -> None:
        with self._connect() as db:
            self._write_signal(db, signal)

    def create_or_append(self, signal: Signal) -> tuple[Signal, bool]:
        """Una sola transacción decide deduplicación y agrega evidencia."""

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = None
            if signal.dedupe_key:
                row = db.execute(
                    """SELECT document FROM signals WHERE operation_id=? AND dedupe_key=?
                       AND status IN ('open','acknowledged') ORDER BY created_at LIMIT 1""",
                    (signal.operation_id, signal.dedupe_key),
                ).fetchone()
            if row:
                existing = Signal.from_dict(json.loads(row["document"]))
                seen = {(item.kind, item.value) for item in existing.evidence}
                existing.evidence.extend(item for item in signal.evidence if (item.kind, item.value) not in seen)
                existing.updated_at = signal.updated_at
                self._write_signal(db, existing)
                return existing, False
            self._write_signal(db, signal)
            return signal, True

    def get_signal(self, operation_id: str, signal_id: str) -> Signal:
        with self._connect() as db:
            row = db.execute("SELECT document FROM signals WHERE id=? AND operation_id=?", (signal_id, operation_id)).fetchone()
        if not row:
            raise KeyError("Señal no encontrada en esta operación.")
        return Signal.from_dict(json.loads(row["document"]))

    def list_signals(self, operation_id: str) -> list[Signal]:
        with self._connect() as db:
            rows = db.execute("SELECT document FROM signals WHERE operation_id=? ORDER BY created_at DESC", (operation_id,)).fetchall()
        return [Signal.from_dict(json.loads(row["document"])) for row in rows]

    def save_case(self, case: Case) -> None:
        """Rechaza agrupaciones cruzadas y dos casos abiertos para una señal."""

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for signal_id in case.signal_ids:
                row = db.execute("SELECT operation_id FROM signals WHERE id=?", (signal_id,)).fetchone()
                if not row or row["operation_id"] != case.operation_id:
                    raise ValueError("Una señal del caso no pertenece a esta operación.")
            if case.status == "open":
                rows = db.execute("SELECT document FROM cases WHERE operation_id=? AND status='open' AND id<>?", (case.operation_id, case.id)).fetchall()
                claimed = {signal_id for row in rows for signal_id in json.loads(row["document"])["signal_ids"]}
                if claimed.intersection(case.signal_ids):
                    raise ValueError("Una señal ya pertenece a otro caso abierto.")
            db.execute(
                """INSERT INTO cases(id, operation_id, status, created_at, document) VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET status=excluded.status, document=excluded.document""",
                (case.id, case.operation_id, case.status, case.created_at.isoformat(), json.dumps(case.to_dict(), ensure_ascii=False)),
            )

    def get_case(self, operation_id: str, case_id: str) -> Case:
        with self._connect() as db:
            row = db.execute("SELECT document FROM cases WHERE id=? AND operation_id=?", (case_id, operation_id)).fetchone()
        if not row:
            raise KeyError("Caso no encontrado en esta operación.")
        return Case.from_dict(json.loads(row["document"]))

    def list_cases(self, operation_id: str) -> list[Case]:
        with self._connect() as db:
            rows = db.execute("SELECT document FROM cases WHERE operation_id=? ORDER BY created_at DESC", (operation_id,)).fetchall()
        return [Case.from_dict(json.loads(row["document"])) for row in rows]
