"""Diagnóstico local de capacidad y alertas sobre estados ya exportados.

No abre conexiones externas ni envía datos operativos. Los umbrales son
configurables y solo orientativos hasta medir un piloto representativo.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
import gc
import json
import math
from pathlib import Path
import sqlite3
import tempfile
from time import perf_counter


def _nonnegative(value, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or not math.isfinite(value):
        raise ValueError(f"invalid_{label}")
    return float(value)


def evaluate_alerts(status: dict, *, connectors: list[dict] | None = None,
                    outbox_age_seconds: int = 900, connector_age_seconds: int = 900,
                    now: datetime | None = None) -> dict:
    """Evalúa señales sin exponer cargas, tokens o nombres de operaciones."""
    if not isinstance(status, dict) or not isinstance(status.get("outbox"), dict):
        raise ValueError("invalid_status_snapshot")
    if outbox_age_seconds <= 0 or connector_age_seconds <= 0:
        raise ValueError("invalid_alert_threshold")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("naive_alert_clock")
    current = current.astimezone(timezone.utc)
    outbox = status["outbox"]
    states = outbox.get("states")
    expected_states = {"pending", "sending", "retry", "unknown", "awaiting_ack", "delivered", "dead"}
    if not isinstance(states, dict) or set(states) != expected_states:
        raise ValueError("invalid_outbox_states")
    for key in expected_states:
        if type(states[key]) is not int or states[key] < 0:
            raise ValueError("invalid_outbox_states")
    if type(status.get("unknown_receipts")) is not int:
        raise ValueError("invalid_unknown_receipts")
    unknown = _nonnegative(status["unknown_receipts"], "unknown_receipts")
    age = _nonnegative(outbox.get("oldest_undelivered_seconds"), "outbox_age")
    alerts: list[dict[str, str]] = []

    def add(code: str, severity: str) -> None:
        alerts.append({"code": code, "severity": severity})

    if unknown:
        add("external_effect_unknown", "critical")
    if states["dead"]:
        add("outbox_dead_letters", "critical")
    if states["unknown"]:
        add("outbox_remote_outcome_unknown", "warning")
    if age >= outbox_age_seconds and sum(states[key] for key in expected_states if key != "delivered"):
        add("outbox_delivery_stale", "critical" if age >= 4 * outbox_age_seconds else "warning")

    if connectors is not None:
        if not isinstance(connectors, list):
            raise ValueError("invalid_connectors_snapshot")
        for connector in connectors:
            if not isinstance(connector, dict) or connector.get("status") not in {"active", "degraded", "failed", "unknown"}:
                raise ValueError("invalid_connector_status")
            if connector["status"] == "failed":
                add("connector_failed", "critical")
            elif connector["status"] in {"degraded", "unknown"}:
                add("connector_degraded", "warning")
            observed = connector.get("last_success_at")
            if observed is not None:
                moment = datetime.fromisoformat(observed)
                if moment.tzinfo is None:
                    raise ValueError("naive_connector_timestamp")
                elapsed = max(0, (current - moment.astimezone(timezone.utc)).total_seconds())
                if elapsed >= connector_age_seconds:
                    add("connector_observation_stale", "warning")
    severity = ("critical" if any(item["severity"] == "critical" for item in alerts) else
                "warning" if alerts else "ok")
    return {"state": severity, "alerts": alerts,
            "coverage": {"outbox": True, "unknown_receipts": True, "connectors": connectors is not None}}


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(percentile * len(ordered)) - 1)], 3)


def inspect_storage(data_dir: Path | str) -> dict:
    """Mide proyecciones en una transacción de lectura por base SQLite.

    Una conexión de solo lectura ve las filas confirmadas en WAL. Cada base
    tiene su propia instantánea; los archivos JSON y los tamaños no forman
    parte de una transacción global entre repositorios.
    """
    root = Path(data_dir)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("invalid_data_dir")
    databases = list(root.rglob("*.db"))
    if len(databases) > 1000 or any(path.is_symlink() for path in databases):
        raise ValueError("invalid_database_inventory")
    sizes = {"database_file_bytes": sum(path.stat().st_size for path in databases),
             "wal_file_bytes": sum(Path(str(path) + "-wal").stat().st_size
                                   for path in databases if Path(str(path) + "-wal").is_file())}
    result = {"format": 1, "database_count": len(databases), **sizes,
              "telemetry_records": 0, "ledger_operations": 0, "ledger_records": 0,
              "operation_states": {state: 0 for state in ("preparation", "active", "paused", "closing", "closed")},
              "network_used": False, "raw_data_included": False,
              "snapshot_consistency": "per_database_read_transaction",
              "cross_database_consistency": "not_atomic"}
    for path in databases:
        if path.name not in {"telemetry.db", "operation_ledger.db"}:
            continue
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            if path.name == "telemetry.db":
                result["telemetry_records"] += connection.execute(
                    "SELECT count(*) FROM telemetry_records").fetchone()[0]
            else:
                result["ledger_operations"] += connection.execute("SELECT count(*) FROM operations").fetchone()[0]
                result["ledger_records"] += connection.execute("SELECT count(*) FROM records").fetchone()[0]
                for state, count in connection.execute("SELECT state, count(*) FROM operations GROUP BY state"):
                    if state not in result["operation_states"]:
                        raise ValueError("invalid_operation_state")
                    result["operation_states"][state] += count
    return result


def benchmark_local(*, scratch: Path | None = None, operations: int = 40, events: int = 100,
                    requests: int = 40, workers: int = 4) -> dict:
    """Mide rutas de lectura con datos sintéticos y sin servidor HTTP."""
    if not 1 <= operations <= 500 or not 1 <= events <= 5000 or not 2 <= requests <= 50 or not 1 <= workers <= 8:
        raise ValueError("invalid_benchmark_size")
    from .core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
    from .plugins.base import EventType
    from .provenance import build_info
    from .telemetry.models import TelemetryRecord
    from .web import create_app

    if scratch is not None:
        scratch = scratch.resolve()
        scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="apate-benchmark-", dir=scratch) as temporary:
        data = Path(temporary) / "data"
        app = create_app({"TESTING": True, "APATE_DATA_DIR": data,
                          "APATE_RULES_PATH": data / "rules.yaml", "APATE_MOUNT_EXTERNAL_TOOLS": False,
                          "APATE_HONEYUSER_MONITORING_ENABLED": False})
        identifiers = []
        for index in range(operations):
            operation = Operation(name=f"Sintética {index}", adversary_profile=AdversaryProfile("Hipótesis"),
                                  roe=RulesOfEngagement(), narrative=Narrative("Prueba"))
            app.config["OPERATION_REPOSITORY"].save(operation)
            identifiers.append(operation.id)
        target = identifiers[0]
        telemetry = app.config["TELEMETRY_COLLECTOR"].repository
        for index in range(events):
            telemetry.append(TelemetryRecord(event_type=EventType.INTERACTION, operation_id=target,
                             plugin_id="benchmark", surface="synthetic", timestamp=datetime.now(timezone.utc),
                             source_event_id=f"synthetic-{index}"))
        bearer = app.config["MACHINE_TOKEN_REPOSITORY"].create(
            name="benchmark", scopes={"operations:read", "telemetry:read"}, operation_ids=set(identifiers),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
        headers = {"Authorization": f"Bearer {bearer}"}
        paths = {"operations": "/api/v1/operations",
                 "telemetry": f"/api/v1/operations/{target}/telemetry?limit=100"}

        def measure(kind: str) -> tuple[str, float]:
            client = app.test_client()
            started = perf_counter()
            response = client.get(paths[kind], headers=headers)
            elapsed = (perf_counter() - started) * 1000
            if response.status_code != 200:
                raise ValueError(f"benchmark_http_{response.status_code}")
            return kind, elapsed

        measure("operations")
        measure("telemetry")
        kinds = ["operations" if index % 2 == 0 else "telemetry" for index in range(requests)]
        started = perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            samples = list(pool.map(measure, kinds))
        wall_seconds = perf_counter() - started
        latency = {kind: [duration for sample_kind, duration in samples if sample_kind == kind] for kind in paths}
        result = {"commit": build_info().commit, "synthetic": True, "operations": operations, "events": events,
                  "requests": requests, "workers": workers, "wall_seconds": round(wall_seconds, 3),
                  "requests_per_second": round(requests / wall_seconds, 3),
                  "latency_ms": {kind: {"p50": _percentile(values, .50), "p95": _percentile(values, .95),
                                        "max": round(max(values), 3)} for kind, values in latency.items()},
                  "external_services": "not_used"}
        del app, telemetry
        gc.collect()
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    alerts = commands.add_parser("alerts")
    alerts.add_argument("status", type=Path)
    alerts.add_argument("--connectors", type=Path)
    alerts.add_argument("--outbox-age-seconds", type=int, default=900)
    alerts.add_argument("--connector-age-seconds", type=int, default=900)
    benchmark = commands.add_parser("benchmark")
    benchmark.add_argument("--scratch", type=Path)
    benchmark.add_argument("--operations", type=int, default=40)
    benchmark.add_argument("--events", type=int, default=100)
    benchmark.add_argument("--requests", type=int, default=40)
    benchmark.add_argument("--workers", type=int, default=4)
    inventory = commands.add_parser("inventory")
    inventory.add_argument("--data-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "alerts":
        result = evaluate_alerts(json.loads(args.status.read_text(encoding="utf-8")),
                                 connectors=json.loads(args.connectors.read_text(encoding="utf-8")) if args.connectors else None,
                                 outbox_age_seconds=args.outbox_age_seconds,
                                 connector_age_seconds=args.connector_age_seconds)
    elif args.command == "benchmark":
        result = benchmark_local(scratch=args.scratch, operations=args.operations, events=args.events,
                                 requests=args.requests, workers=args.workers)
    else:
        result = inspect_storage(args.data_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == "alerts" and result["state"] == "critical":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
