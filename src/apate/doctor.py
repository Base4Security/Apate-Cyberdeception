"""Diagnóstico de solo lectura y paquete de soporte sin datos operativos.

No abre sockets, descifra secretos ni incluye rutas, nombres de recursos,
identificadores de operación o cargas persistidas en la salida.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3

from .backup import verify_backup
from .ops import evaluate_alerts
from .provenance import build_info
from .schema_version import ARCHIVO, SCHEMA_VERSION, SQLITE_SCHEMA_VERSION


_APATE_DATABASES = {
    "attention.db", "machine_tokens.db", "operation_admission.db",
    "operation_ledger.db", "plan_approvals.db", "rule_decisions.db", "telemetry.db",
}


def diagnose(data_dir: Path | str, *, backup: Path | str | None = None,
             status: Path | str | None = None) -> dict:
    """Devuelve solo códigos estables, conteos y versiones no sensibles."""
    root = Path(data_dir).resolve()
    checks: dict[str, dict] = {}

    def check(name: str, state: str, code: str, **details) -> None:
        checks[name] = {"state": state, "code": code, **details}

    if not root.is_dir():
        check("data_dir", "critical", "data_dir_missing")
    else:
        check("data_dir", "ok" if os.access(root, os.R_OK) else "critical",
              "data_dir_readable" if os.access(root, os.R_OK) else "data_dir_unreadable")
        stamp = root / ARCHIVO
        if not stamp.exists():
            check("schema", "warning", "schema_unstamped")
        else:
            try:
                value = json.loads(stamp.read_text(encoding="utf-8"))["schema_version"]
                if type(value) is not int or value < 0:
                    raise ValueError("invalid_schema")
            except (OSError, ValueError, KeyError, TypeError):
                check("schema", "critical", "schema_invalid")
            else:
                if value > SCHEMA_VERSION:
                    check("schema", "critical", "schema_future", version=value)
                elif value < SCHEMA_VERSION:
                    check("schema", "warning", "schema_legacy", version=value)
                else:
                    check("schema", "ok", "schema_current", version=value)

        databases = sorted(root.rglob("*.db"))
        if len(databases) > 1000:
            check("sqlite", "critical", "sqlite_inventory_limit")
        elif not databases:
            check("sqlite", "warning", "sqlite_absent", count=0)
        else:
            failures = 0
            future = 0
            legacy = 0
            for path in databases:
                if path.is_symlink():
                    failures += 1
                    continue
                try:
                    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
                        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                            failures += 1
                        if path.name in _APATE_DATABASES:
                            version = connection.execute("PRAGMA user_version").fetchone()[0]
                            if version > SQLITE_SCHEMA_VERSION:
                                future += 1
                            elif version < SQLITE_SCHEMA_VERSION:
                                legacy += 1
                except (OSError, sqlite3.DatabaseError):
                    failures += 1
            if failures:
                check("sqlite", "critical", "sqlite_integrity_failed", count=len(databases), failed=failures)
            elif future:
                check("sqlite", "critical", "sqlite_future_schema", count=len(databases), future=future)
            elif legacy:
                check("sqlite", "warning", "sqlite_legacy_schema", count=len(databases), legacy=legacy)
            else:
                check("sqlite", "ok", "sqlite_integrity_ok", count=len(databases))

        key_present = bool(os.environ.get("APATE_SECRET_ENCRYPTION_KEY")) or (root / "secret_encryption.key").is_file()
        check("secret_key", "ok" if key_present else "warning",
              "secret_key_present" if key_present else "secret_key_not_detected")

    if backup is not None:
        try:
            manifest = verify_backup(backup)
        except (OSError, ValueError, KeyError, TypeError, sqlite3.DatabaseError):
            check("backup", "critical", "backup_invalid")
        else:
            check("backup", "ok", "backup_verified", count=len(manifest["files"]))
    if status is not None:
        try:
            snapshot = json.loads(Path(status).read_text(encoding="utf-8"))
            alerts = evaluate_alerts(snapshot)
        except (OSError, ValueError, KeyError, TypeError):
            check("status", "critical", "status_invalid")
        else:
            check("status", alerts["state"], "status_evaluated",
                  alerts=alerts["alerts"], coverage=alerts["coverage"])

    overall = ("critical" if any(item["state"] == "critical" for item in checks.values()) else
               "warning" if any(item["state"] == "warning" for item in checks.values()) else "ok")
    build = build_info()
    return {"format": 1, "version": build.version, "commit": build.commit,
            "schema_supported": {"json": SCHEMA_VERSION, "sqlite": SQLITE_SCHEMA_VERSION},
            "state": overall, "checks": checks, "network_used": False, "raw_data_included": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--status", type=Path)
    parser.add_argument("--output", type=Path, help="Crea un JSON sanitizado sin sobrescribir otro archivo")
    args = parser.parse_args()
    report = diagnose(args.data_dir, backup=args.backup, status=args.status)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(rendered)
    else:
        print(rendered, end="")
    if report["state"] == "critical":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
