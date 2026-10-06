"""Fases de un ensayo entre dos wheels instaladas, con datos ficticios."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import apate
from apate.core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
from apate.plugins.base import EventType
from apate.telemetry.models import TelemetryRecord
from apate.web import create_app


def _app(data_dir: Path):
    return create_app({"TESTING": True, "APATE_DATA_DIR": data_dir,
                       "APATE_RULES_PATH": data_dir / "rules.yaml",
                       "APATE_MOUNT_EXTERNAL_TOOLS": False,
                       "APATE_HONEYUSER_MONITORING_ENABLED": False})


def _event(operation_id: str, source_id: str) -> TelemetryRecord:
    return TelemetryRecord(event_type=EventType.INTERACTION, operation_id=operation_id,
        plugin_id="upgrade-probe", surface="synthetic", timestamp=datetime.now(timezone.utc),
        source_event_id=source_id)


def run(phase: str, data_dir: Path, fixture: Path) -> dict:
    """Comprueba que importa desde la wheel y preserva hechos entre versiones."""

    if not Path(apate.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()):
        raise RuntimeError("upgrade_probe_not_installed_wheel")
    app = _app(data_dir)
    operations = app.config["OPERATION_REPOSITORY"]
    telemetry = app.config["TELEMETRY_COLLECTOR"].repository
    if phase == "prepare":
        if fixture.exists():
            raise ValueError("upgrade_fixture_exists")
        operation = Operation(name="Ensayo de actualización", adversary_profile=AdversaryProfile("Ficticio"),
            roe=RulesOfEngagement(), narrative=Narrative("Sin efectos externos"))
        operations.save(operation)
        telemetry.append(_event(operation.id, "before-upgrade"))
        fixture.write_text(json.dumps({"operation_id": operation.id}), encoding="utf-8")
        expected = ["before-upgrade"]
    else:
        operation_id = json.loads(fixture.read_text(encoding="utf-8"))["operation_id"]
        operation = operations.get(operation_id)
        if operation is None or operation.name != "Ensayo de actualización":
            raise RuntimeError("upgrade_operation_missing")
        if phase == "mutate":
            telemetry.append(_event(operation_id, "after-upgrade"))
        expected = ["before-upgrade", "after-upgrade"] if phase in {"mutate", "verify-mutated"} else ["before-upgrade"]
    actual = [record.source_event_id for record in telemetry.list_for_operation(operation.id)]
    if actual != expected:
        raise RuntimeError("upgrade_telemetry_mismatch")
    if app.test_client().get("/about").status_code != 200:
        raise RuntimeError("upgrade_web_failed")
    return {"phase": phase, "operations": 1, "events": len(actual), "external_services": "not_used"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "verify", "mutate", "verify-mutated"))
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.phase, args.data_dir, args.fixture), sort_keys=True))


if __name__ == "__main__":
    main()
