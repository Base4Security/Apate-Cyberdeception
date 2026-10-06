"""Prepara y valida un expediente local de gates sin contactar infraestructura."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

from review_release_artifact import review


GATES = {
    "AD-WEF": ("AD-01", "AD-02", "AD-03", "AD-04", "AD-05"),
    "SMB": ("SMB-01", "SMB-02", "SMB-03"),
    "VAULT": ("VAULT-01", "VAULT-02", "VAULT-03"),
    "IDP": ("OIDC-01", "SCIM-01", "LDAP-01"),
    "SOC": ("HEC-01", "HEC-02", "HEC-03", "OTLP-01", "OTLP-02"),
    "RESTORE": ("BKP-01", "BKP-02"),
    "OPERADORES": ("OPS-01", "OPS-02", "OPS-03", "OPS-04", "OPS-05"),
    "RENDIMIENTO": ("PERF-01", "PERF-02"),
}

ARTIFACT_FILES = ("release-evidence.json", "upgrade-smoke.json", "apate-image.cdx.json",
                  "apate-image-id.txt")


def _write(path: Path, data: dict) -> None:
    with path.open("x", encoding="utf-8") as target:
        target.write(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n")


def prepare(artifact_dir: Path, project: Path, output: Path, *, commit: str, version: str) -> dict:
    """Congela artefactos y crea informes vacíos, siempre NOT_RUN."""

    result = review(artifact_dir, project, commit=commit, version=version)
    output.mkdir(parents=True, exist_ok=False)
    artifact_target = output / "artifact"
    artifact_target.mkdir()
    for name in ARTIFACT_FILES:
        shutil.copy2(artifact_dir / name, artifact_target / name)
    wheels = list(artifact_dir.glob("apate-*.whl"))
    shutil.copy2(wheels[0], artifact_target / wheels[0].name)
    source = output / "source"
    (source / "requirements").mkdir(parents=True)
    for old, new in ((project / "NOTICE", source / "NOTICE"),
                     (project / "requirements" / "release.txt", source / "requirements" / "release.txt"),
                     (project / "requirements" / "build.txt", source / "requirements" / "build.txt")):
        shutil.copy2(old, new)
    reports = output / "reports"
    reports.mkdir()
    (output / "evidence").mkdir()
    for gate, cases in GATES.items():
        _write(reports / f"{gate}.json", {
            "gate": gate, "status": "NOT_RUN", "physical_verification": False,
            "environment": None, "operator": None, "reviewer": None,
            "started_at": None, "finished_at": None, "limitations": [],
            "cases": [{"id": case, "status": "NOT_RUN", "expected": None,
                       "observed": None, "evidence": []} for case in cases],
        })
    manifest = {"format": 1, "created_at": datetime.now(timezone.utc).isoformat(),
                "commit": commit, "version": version, "wheel_sha256": result["wheel_sha256"],
                "release_review": "PASSED", "initial_external_gates": "NOT_RUN",
                "gate_ids": list(GATES)}
    _write(output / "manifest.json", manifest)
    return {"pack": "PREPARED", "commit": commit, "version": version,
            "gate_count": len(GATES), "case_count": sum(map(len, GATES.values())),
            "passed_external_gates": 0}


def validate(pack: Path) -> dict:
    """Rechaza PASS sin revisión física y evidencia local con SHA-256."""

    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("format") != 1 or manifest.get("gate_ids") != list(GATES):
        raise ValueError("pilot_manifest_invalid")
    release = review(pack / "artifact", pack / "source", commit=manifest["commit"], version=manifest["version"])
    if release["wheel_sha256"] != manifest.get("wheel_sha256"):
        raise ValueError("pilot_wheel_mismatch")
    passed = 0
    for gate, expected_cases in GATES.items():
        report = json.loads((pack / "reports" / f"{gate}.json").read_text(encoding="utf-8"))
        cases = report.get("cases")
        if (report.get("gate") != gate or not isinstance(cases, list)
                or [item.get("id") for item in cases] != list(expected_cases)):
            raise ValueError(f"pilot_cases_invalid:{gate}")
        status = report.get("status")
        if status not in {"NOT_RUN", "IN_PROGRESS", "BLOCKED", "FAILED", "PASSED"}:
            raise ValueError(f"pilot_status_invalid:{gate}")
        if status == "NOT_RUN" and (report.get("physical_verification") is not False
                                    or any(item.get("status") != "NOT_RUN" for item in cases)):
            raise ValueError(f"pilot_not_run_inconsistent:{gate}")
        if status == "PASSED":
            if (report.get("physical_verification") is not True or not report.get("reviewer")
                    or not report.get("operator") or not report.get("environment")
                    or not report.get("started_at") or not report.get("finished_at")):
                raise ValueError(f"pilot_review_missing:{gate}")
            for item in cases:
                if item.get("status") != "PASSED" or not item.get("expected") or not item.get("observed"):
                    raise ValueError(f"pilot_case_not_passed:{item['id']}")
                evidence = item.get("evidence")
                if not isinstance(evidence, list) or not evidence:
                    raise ValueError(f"pilot_evidence_missing:{item['id']}")
                for entry in evidence:
                    path = Path(entry.get("path", ""))
                    target = (pack / path).resolve()
                    if (path.is_absolute() or not target.is_relative_to((pack / "evidence").resolve())
                            or not target.is_file()
                            or hashlib.sha256(target.read_bytes()).hexdigest() != entry.get("sha256")):
                        raise ValueError(f"pilot_evidence_invalid:{item['id']}")
            passed += 1
    return {"pack": "VALID", "commit": manifest["commit"], "version": manifest["version"],
            "gate_count": len(GATES), "passed_external_gates": passed,
            "not_passed_external_gates": len(GATES) - passed}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "validate"))
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--project", type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--version")
    parser.add_argument("--pack", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        if not all((args.artifact_dir, args.project, args.commit, args.version)):
            parser.error("prepare requiere --artifact-dir, --project, --commit y --version")
        result = prepare(args.artifact_dir, args.project, args.pack,
                         commit=args.commit, version=args.version)
    else:
        result = validate(args.pack)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
