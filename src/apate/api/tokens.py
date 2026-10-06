"""Tokens de máquina con scopes, vencimiento, cuota y auditoría SQLite."""

from __future__ import annotations

import hashlib
import argparse
import hmac
import json
import secrets
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from ..schema_version import apply_sqlite_version

SCOPES = frozenset({"operations:read", "telemetry:read", "honeyuser:read", "honeyuser:prepare",
                    "honeyuser:execute", "honeyuser:refresh", "honeyuser:rotate", "honeyuser:retire", "honeyuser:poll",
                    "plans:propose", "plans:activate", "operations:stop", "capabilities:execute"})


@dataclass(frozen=True)
class MachineToken:
    id: str
    name: str
    scopes: frozenset[str]
    operation_ids: frozenset[str]
    expires_at: datetime

    def permits(self, scope: str, operation_id: str | None = None) -> bool:
        return scope in self.scopes and (operation_id is None or operation_id in self.operation_ids)


class MachineTokenRepository:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL,
                    scopes TEXT NOT NULL, operation_ids TEXT NOT NULL,
                    expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS requests (
                    token_id TEXT NOT NULL, period INTEGER NOT NULL, count INTEGER NOT NULL,
                    PRIMARY KEY(token_id, period)
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    token_id TEXT NOT NULL, key TEXT NOT NULL, path TEXT NOT NULL,
                    body_hash TEXT NOT NULL, status INTEGER, response TEXT,
                    PRIMARY KEY(token_id, key)
                );
                CREATE TABLE IF NOT EXISTS api_audit (
                    id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, token_id TEXT,
                    method TEXT NOT NULL, path TEXT NOT NULL, outcome TEXT NOT NULL,
                    status INTEGER NOT NULL, detail TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS api_audit_token ON api_audit(token_id, timestamp);
            """)
            apply_sqlite_version(db)

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def create(self, *, name: str, scopes: set[str], operation_ids: set[str], expires_at: datetime) -> str:
        if not name.strip() or not scopes or not scopes <= SCOPES or not operation_ids:
            raise ValueError("Nombre, scopes válidos y operaciones permitidas son obligatorios.")
        if expires_at.tzinfo is None or expires_at <= datetime.now(timezone.utc):
            raise ValueError("El token debe tener un vencimiento futuro con zona horaria.")
        token_id = uuid4().hex
        secret = secrets.token_urlsafe(32)
        with self._connect() as db:
            db.execute("INSERT INTO tokens VALUES (?, ?, ?, ?, ?, ?, 0)",
                       (token_id, name.strip(), hashlib.sha256(secret.encode()).hexdigest(),
                        json.dumps(sorted(scopes)), json.dumps(sorted(operation_ids)), expires_at.isoformat()))
        return f"apate_{token_id}_{secret}"

    def authenticate(self, bearer: str) -> MachineToken | None:
        if not bearer.startswith("apate_"):
            return None
        pieces = bearer.split("_", 2)
        if len(pieces) != 3:
            return None
        _, token_id, secret = pieces
        with self._connect() as db:
            row = db.execute("SELECT * FROM tokens WHERE id=?", (token_id,)).fetchone()
        if not row or row["revoked"] or not hmac.compare_digest(row["secret_hash"], hashlib.sha256(secret.encode()).hexdigest()):
            return None
        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at <= datetime.now(timezone.utc):
            return None
        return MachineToken(token_id, row["name"], frozenset(json.loads(row["scopes"])),
                            frozenset(json.loads(row["operation_ids"])), expires_at)

    def revoke(self, token_id: str) -> None:
        with self._connect() as db:
            if db.execute("UPDATE tokens SET revoked=1 WHERE id=?", (token_id,)).rowcount == 0:
                raise KeyError("Token no encontrado.")

    def allow_request(self, token_id: str, *, limit_per_minute: int = 60) -> bool:
        period = int(time.time() // 60)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO requests VALUES (?, ?, 0) ON CONFLICT DO NOTHING", (token_id, period))
            count = db.execute("SELECT count FROM requests WHERE token_id=? AND period=?", (token_id, period)).fetchone()[0]
            if count >= limit_per_minute:
                return False
            db.execute("UPDATE requests SET count=count+1 WHERE token_id=? AND period=?", (token_id, period))
            db.execute("DELETE FROM requests WHERE period<?", (period - 120,))
        return True

    def idempotency_lookup(self, token_id: str, key: str, path: str, body: bytes):
        digest = hashlib.sha256(body).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM idempotency WHERE token_id=? AND key=?", (token_id, key)).fetchone()
            if row:
                if row["path"] != path or row["body_hash"] != digest:
                    raise ValueError("La clave de idempotencia ya se usó para otra petición.")
                if row["status"] is None:
                    raise RuntimeError("La petición original aún está pendiente de conciliación.")
                return row["status"], json.loads(row["response"])
            db.execute("INSERT INTO idempotency VALUES (?, ?, ?, ?, NULL, NULL)", (token_id, key, path, digest))
        return None

    def idempotency_finish(self, token_id: str, key: str, status: int, response: dict) -> None:
        with self._connect() as db:
            db.execute("UPDATE idempotency SET status=?, response=? WHERE token_id=? AND key=?",
                       (status, json.dumps(response, ensure_ascii=False), token_id, key))

    def audit(self, *, token_id: str | None, method: str, path: str, outcome: str, status: int, detail: str) -> None:
        with self._connect() as db:
            db.execute("INSERT INTO api_audit VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                       (str(uuid4()), datetime.now(timezone.utc).isoformat(), token_id,
                        method, path, outcome, status, detail))

    def list_audit(self, token_id: str | None = None) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT * FROM api_audit WHERE (? IS NULL OR token_id=?) ORDER BY timestamp DESC", (token_id, token_id)).fetchall()
        return [dict(row) for row in rows]

    def list_tokens(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT id, name, scopes, operation_ids, expires_at, revoked FROM tokens ORDER BY name").fetchall()
        return [dict(row) for row in rows]


def main() -> None:
    parser = argparse.ArgumentParser(description="Administrar tokens de máquina APATE desde el host.")
    parser.add_argument("--data-dir", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument("--scope", action="append", required=True)
    create.add_argument("--operation", action="append", required=True)
    create.add_argument("--expires-at", required=True, help="Fecha ISO 8601 con zona, por ejemplo 2026-10-15T00:00:00+00:00")
    commands.add_parser("list")
    revoke = commands.add_parser("revoke")
    revoke.add_argument("token_id")
    args = parser.parse_args()
    repository = MachineTokenRepository(Path(args.data_dir) / "machine_tokens.db")
    if args.command == "create":
        value = repository.create(name=args.name, scopes=set(args.scope), operation_ids=set(args.operation),
                                  expires_at=datetime.fromisoformat(args.expires_at))
        print(value)
    elif args.command == "revoke":
        repository.revoke(args.token_id)
        print("Token revocado.")
    else:
        for token in repository.list_tokens():
            print(f"{token['id']} {token['name']} {token['expires_at']} revoked={bool(token['revoked'])}")


if __name__ == "__main__":
    main()
