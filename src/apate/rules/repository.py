"""Persistencia SQLite de decisiones del motor de reglas.

El bus de eventos sigue siendo síncrono: cada decisión se confirma en
SQLite antes de devolver el control al publicador del evento. El volumen
esperado es bajo (una operación de ciberengaño, no telemetría cruda), por
lo que una conexión breve por escritura mantiene el diseño simple y evita
un hilo o cola asíncrona adicional.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .models import Action, RejectedAction, RejectionKind, RuleFiring
from ..schema_version import apply_sqlite_version


def _action_to_dict(action: Action) -> dict[str, str | None]:
    """Serializa sin ampliar el contrato de ``apate.rules.models``."""

    data: dict[str, str | None] = {"action": action.kind.value, "plugin_id": action.plugin_id}
    if action.to is not None:
        data["to"] = action.to.value
    return data


class SQLiteRuleDecisionRepository:
    """Guarda disparos y rechazos del motor por operación en SQLite."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS rule_firings (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    operation_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    actions_json TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    triggering_event_id TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_rule_firings_operation
                    ON rule_firings(operation_id, sequence);
                CREATE TABLE IF NOT EXISTS rejected_rule_actions (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT NOT NULL UNIQUE,
                    operation_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    action_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    rejection_kind TEXT,
                    triggering_event_id TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_rejected_rule_actions_operation
                    ON rejected_rule_actions(operation_id, sequence);
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(rejected_rule_actions)")
            }
            if "rejection_kind" not in columns:
                connection.execute("ALTER TABLE rejected_rule_actions ADD COLUMN rejection_kind TEXT")
            if "triggering_event_id" not in columns:
                connection.execute("ALTER TABLE rejected_rule_actions ADD COLUMN triggering_event_id TEXT")
            # Sello de version del esquema. Los `ALTER TABLE` de arriba resuelven
            # una columna que falta, pero no pueden ver un cambio de significado
            # -- un enum renombrado, una unidad distinta -- ni decir con que
            # version se escribio esta base. Ver `apate.schema_version`.
            apply_sqlite_version(connection)
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def append_firing(self, operation_id: str, firing: RuleFiring) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """INSERT INTO rule_firings
                (id, operation_id, rule_name, actions_json, timestamp, triggering_event_id)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    firing.id,
                    operation_id,
                    firing.rule_name,
                    json.dumps([_action_to_dict(action) for action in firing.actions]),
                    firing.timestamp.isoformat(),
                    firing.triggering_event_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def append_rejection(self, operation_id: str, rejection: RejectedAction) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """INSERT INTO rejected_rule_actions
                (id, operation_id, rule_name, action_json, reason, timestamp, rejection_kind, triggering_event_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    rejection.id,
                    operation_id,
                    rejection.rule_name,
                    json.dumps(_action_to_dict(rejection.action)),
                    rejection.reason,
                    rejection.timestamp.isoformat(),
                    rejection.kind.value,
                    rejection.triggering_event_id,
                ),
            )
            connection.commit()
        finally:
            connection.close()

    def list_firings_for_operation(self, operation_id: str) -> list[RuleFiring]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT id, rule_name, actions_json, timestamp, triggering_event_id
                FROM rule_firings WHERE operation_id = ? ORDER BY sequence""",
                (operation_id,),
            ).fetchall()
        finally:
            connection.close()
        return [self._firing_from_row(row) for row in rows]

    def list_rejections_for_operation(self, operation_id: str) -> list[RejectedAction]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT id, rule_name, action_json, reason, timestamp, rejection_kind, triggering_event_id
                FROM rejected_rule_actions WHERE operation_id = ? ORDER BY sequence""",
                (operation_id,),
            ).fetchall()
        finally:
            connection.close()
        return [self._rejection_from_row(row) for row in rows]

    def list_recent_firings(self, limit: int = 5) -> list[tuple[str, RuleFiring]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT operation_id, id, rule_name, actions_json, timestamp, triggering_event_id
                FROM rule_firings ORDER BY sequence DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        finally:
            connection.close()
        return [(row["operation_id"], self._firing_from_row(row)) for row in rows]

    def list_firings_for_operations(self, operation_ids: list[str]) -> list[tuple[str, RuleFiring]]:
        """Devuelve disparos de varias operaciones con una sola consulta.

        El centro de impacto necesita el total agregado, no una consulta
        por tarjeta. Una lista vacía se resuelve sin tocar SQLite para que
        una instalación nueva pueda cargar la vista sin datos previos.
        """

        if not operation_ids:
            return []
        placeholders = ", ".join("?" for _ in operation_ids)
        connection = self._connect()
        try:
            rows = connection.execute(
                f"""SELECT operation_id, id, rule_name, actions_json, timestamp, triggering_event_id
                FROM rule_firings WHERE operation_id IN ({placeholders}) ORDER BY sequence""",
                operation_ids,
            ).fetchall()
        finally:
            connection.close()
        return [(row["operation_id"], self._firing_from_row(row)) for row in rows]

    @staticmethod
    def _firing_from_row(row: sqlite3.Row) -> RuleFiring:
        return RuleFiring(
            id=row["id"],
            rule_name=row["rule_name"],
            actions=[Action.from_dict(action) for action in json.loads(row["actions_json"])],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            triggering_event_id=row["triggering_event_id"],
        )

    @staticmethod
    def _rejection_from_row(row: sqlite3.Row) -> RejectedAction:
        raw_kind = row["rejection_kind"] if "rejection_kind" in row.keys() else None
        try:
            kind = RejectionKind(raw_kind) if raw_kind else RejectionKind.from_legacy_reason(row["reason"])
        except ValueError:
            kind = RejectionKind.from_legacy_reason(row["reason"])
        return RejectedAction(
            id=row["id"],
            rule_name=row["rule_name"],
            action=Action.from_dict(json.loads(row["action_json"])),
            reason=row["reason"],
            kind=kind,
            timestamp=datetime.fromisoformat(row["timestamp"]),
            triggering_event_id=(row["triggering_event_id"] if "triggering_event_id" in row.keys() else None),
        )
