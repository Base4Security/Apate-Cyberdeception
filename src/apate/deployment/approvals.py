"""Aprobación de planes por una segunda identidad humana autenticada."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

from ..schema_version import apply_sqlite_version
from .models import DeploymentPlan


def plan_digest(plan: DeploymentPlan) -> str:
    """Vincula la aprobación a todos los cambios y parámetros del plan."""
    payload = json.dumps(plan.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class PlanApprovalRepository:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS plan_approvals (
                plan_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL, digest TEXT NOT NULL,
                maker_id TEXT NOT NULL, approver_id TEXT NOT NULL DEFAULT '',
                approved_at TEXT NOT NULL DEFAULT ''
            )""")
            apply_sqlite_version(db)

    def _connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def register(self, plan: DeploymentPlan, maker_id: str) -> None:
        if not maker_id:
            raise ValueError("El plan requiere un operador autenticado.")
        with self._connect() as db:
            db.execute(
                "INSERT INTO plan_approvals (plan_id, operation_id, digest, maker_id) VALUES (?, ?, ?, ?)",
                (plan.id, plan.operation_id, plan_digest(plan), maker_id),
            )

    def status(self, plan: DeploymentPlan) -> dict | None:
        with self._connect() as db:
            row = db.execute(
                "SELECT digest, maker_id, approver_id, approved_at FROM plan_approvals WHERE plan_id=? AND operation_id=?",
                (plan.id, plan.operation_id),
            ).fetchone()
        if not row:
            return None
        if row[0] != plan_digest(plan):
            raise ValueError("El plan cambió desde su registro de aprobación.")
        return {"maker_id": row[1], "approver_id": row[2], "approved_at": row[3]}

    def approve(self, plan: DeploymentPlan, approver_id: str, *, now=None) -> None:
        if plan.is_expired(now=now):
            raise ValueError("El plan ya expiró.")
        if not approver_id:
            raise ValueError("La aprobación exige sesión autenticada.")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT digest, maker_id, approver_id FROM plan_approvals WHERE plan_id=? AND operation_id=?",
                (plan.id, plan.operation_id),
            ).fetchone()
            if not row or row[0] != plan_digest(plan):
                raise ValueError("No existe una solicitud válida para este plan.")
            if row[1] == approver_id:
                raise ValueError("El autor del plan no puede aprobarlo.")
            if row[2]:
                raise ValueError("Este plan ya fue aprobado.")
            db.execute(
                "UPDATE plan_approvals SET approver_id=?, approved_at=datetime('now') WHERE plan_id=?",
                (approver_id, plan.id),
            )

    def require_approved(self, plan: DeploymentPlan) -> None:
        if plan.is_expired():
            raise ValueError("El plan ya expiró.")
        status = self.status(plan)
        if not status or not status["approver_id"]:
            raise ValueError("El plan requiere aprobación de una segunda persona.")
