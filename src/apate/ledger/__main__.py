"""Herramienta local de administración; no autentica ni modifica señuelos."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ..i18n import gettext as _
from .repository import LedgerError
from .service import OperationPlanService


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=_("Historia de operación y planes congelados; administración local."))
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--rules", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    migration = commands.add_parser("migrate")
    migration.add_argument("--actor", required=True)
    proposal = commands.add_parser("propose")
    proposal.add_argument("operation_id")
    proposal.add_argument("--parent")
    proposal.add_argument("--reason", required=True)
    proposal.add_argument("--actor", required=True)
    proposal.add_argument("--dispositions", type=Path)
    proposal.add_argument("--execution-policy", type=Path)
    stop = commands.add_parser("stop")
    stop.add_argument("operation_id")
    stop.add_argument("--target", choices=("paused", "closing"), required=True)
    stop.add_argument("--revision", type=int, required=True)
    stop.add_argument("--reason", required=True)
    stop.add_argument("--actor", required=True)
    for name in ("approve", "activate"):
        command = commands.add_parser(name)
        command.add_argument("operation_id")
        command.add_argument("plan_id")
        command.add_argument("--digest", required=True)
        command.add_argument("--actor", required=True)
        if name == "approve":
            command.add_argument("--distinct-actor", action="store_true")
    status = commands.add_parser("status")
    status.add_argument("operation_id")
    review = commands.add_parser("review")
    review.add_argument("operation_id")
    review.add_argument("plan_id")
    review.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if not Path(args.data_dir).is_dir():
            raise LedgerError("data_directory_required")
        # No reemplazar una clave perdida al abrir una historia ya existente.
        if (Path(args.data_dir) / "operation_ledger.db").exists() and not (
                os.environ.get("APATE_SECRET_ENCRYPTION_KEY") or (Path(args.data_dir) / "secret_encryption.key").exists()):
            raise LedgerError("existing_key_required")
        service = OperationPlanService.from_data_dir(args.data_dir, args.rules)
        ledger = service.ledger
        if args.command == "migrate":
            result = service.migrate(actor=args.actor)
        elif args.command == "propose":
            dispositions = json.loads(args.dispositions.read_text(encoding="utf-8")) if args.dispositions else None
            record = service.propose(args.operation_id, parent_id=args.parent, reason=args.reason,
                actor=args.actor, dispositions=dispositions,
                execution_policy=json.loads(args.execution_policy.read_text(encoding="utf-8")) if args.execution_policy else None)
            result = {key: record[key] for key in ("id", "operation_id", "digest", "sequence")}
        elif args.command == "approve":
            record = ledger.approve(args.operation_id, args.plan_id, expected_digest=args.digest,
                actor=args.actor, require_distinct_actor=args.distinct_actor)
            result = {"approval_id": record["id"]}
        elif args.command == "activate":
            ledger.activate(args.operation_id, args.plan_id, expected_digest=args.digest, actor=args.actor)
            result = {"active_plan_id": args.plan_id}
        elif args.command == "stop":
            ledger.stop(args.operation_id, target=args.target, expected_revision=args.revision, reason=args.reason, actor=args.actor)
            result = {"state": args.target}
        elif args.command == "review":
            record = ledger.record(args.operation_id, args.plan_id)
            if record["kind"] != "plan":
                raise LedgerError("plan_required")
            # La salida contiene el diseño descifrado y puede contener secretos.
            # Nunca sobrescribir un archivo del llamador o la propia base.
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(record, stream, ensure_ascii=False, indent=2)
            result = {"plan_id": record["id"], "digest": record["digest"], "output": str(args.output)}
        else:
            operation = ledger.operation(args.operation_id)
            result = {key: operation[key] for key in ("id", "state", "revision", "sequence", "active_plan_id", "baseline_digest")}
            result["pending_commands"] = ledger.pending_commands(args.operation_id)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1 if args.command == "migrate" and result["rejected"] else 0
    except (LedgerError, OSError, ValueError, KeyError, TypeError) as error:
        # Un error de parsing no imprime el documento potencialmente secreto.
        print(json.dumps({"error": error.code if isinstance(error, LedgerError) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
