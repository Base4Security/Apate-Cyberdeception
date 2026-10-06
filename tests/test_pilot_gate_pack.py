"""El expediente no puede convertir evidencia ausente en gates aprobados."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from zipfile import ZipFile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from pilot_gate_pack import prepare, validate  # noqa: E402
from review_release_artifact import review  # noqa: E402


COMMIT = "a" * 40
VERSION = "0.1.0rc1"


def _json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _artifact(artifact: Path, project: Path) -> Path:
    artifact.mkdir()
    (project / "requirements").mkdir(parents=True)
    (project / "NOTICE").write_text("APATE", encoding="utf-8")
    (project / "requirements" / "release.txt").write_text("dep==1\n", encoding="utf-8")
    (project / "requirements" / "build.txt").write_text("wheel==1\n", encoding="utf-8")
    wheel = artifact / f"apate-{VERSION}-py3-none-any.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr(f"apate-{VERSION}.dist-info/METADATA", f"Name: apate\nVersion: {VERSION}\n")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    source_url = f"https://example.test/apate/tree/{COMMIT}"
    _json(artifact / "upgrade-smoke.json", {
        "format": 1, "baseline_wheel_sha256": "b" * 64,
        "candidate_wheel_sha256": digest, "upgrade": "ok", "candidate_restore": "ok",
        "rollback": "ok", "original_unchanged": True, "external_services": "not_used"})
    _json(artifact / "apate-image.cdx.json", {"bomFormat": "CycloneDX", "metadata": {"component": {
        "name": "apate", "version": VERSION,
        "properties": [{"name": "apate:build:commit", "value": COMMIT}],
        "externalReferences": [{"type": "distribution-source", "url": source_url}]}}})
    (artifact / "apate-image-id.txt").write_text("sha256:" + "c" * 64, encoding="utf-8")
    paths = {"wheel": wheel, "image_sbom": artifact / "apate-image.cdx.json",
             "upgrade_smoke": artifact / "upgrade-smoke.json", "notice": project / "NOTICE",
             "runtime_lock": project / "requirements" / "release.txt",
             "build_lock": project / "requirements" / "build.txt"}
    _json(artifact / "release-evidence.json", {
        "format": 1, "commit": COMMIT, "version": VERSION, "source_url": source_url,
        "image_id": "sha256:" + "c" * 64,
        "artifacts": {name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                             "bytes": path.stat().st_size} for name, path in paths.items()}})
    return wheel


def test_preparacion_deja_todos_los_gates_sin_ejecutar_y_rechaza_pass_vacio(tmp_path):
    artifact, project, pack = (tmp_path / name for name in ("artifact", "project", "pack"))
    project.mkdir()
    _artifact(artifact, project)
    assert review(artifact, project, commit=COMMIT, version=VERSION)["review"] == "PASSED"
    result = prepare(artifact, project, pack, commit=COMMIT, version=VERSION)
    assert result["passed_external_gates"] == 0
    assert validate(pack)["not_passed_external_gates"] == result["gate_count"]
    report_path = pack / "reports" / "AD-WEF.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["status"] = "PASSED"
    _json(report_path, report)
    with pytest.raises(ValueError, match="pilot_review_missing"):
        validate(pack)


def test_revision_detecta_wheel_alterada_en_paquete(tmp_path):
    artifact, project, pack = (tmp_path / name for name in ("artifact", "project", "pack"))
    project.mkdir()
    wheel = _artifact(artifact, project)
    prepare(artifact, project, pack, commit=COMMIT, version=VERSION)
    (pack / "artifact" / wheel.name).write_bytes(b"cambio")
    with pytest.raises(ValueError, match="artifact_digest_mismatch:wheel"):
        validate(pack)


def test_gate_aprobado_exige_archivo_y_detecta_alteracion(tmp_path):
    artifact, project, pack = (tmp_path / name for name in ("artifact", "project", "pack"))
    project.mkdir()
    _artifact(artifact, project)
    prepare(artifact, project, pack, commit=COMMIT, version=VERSION)
    proof = pack / "evidence" / "observacion-sanitizada.txt"
    proof.write_text("Resultado observado por otra persona", encoding="utf-8")
    report_path = pack / "reports" / "AD-WEF.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report.update({"status": "PASSED", "physical_verification": True,
                   "environment": {"lab": "sintético"}, "operator": "operador",
                   "reviewer": "revisor", "started_at": "2026-10-02T12:00:00Z",
                   "finished_at": "2026-10-02T12:05:00Z"})
    for case in report["cases"]:
        case.update({"status": "PASSED", "expected": "efecto definido",
                     "observed": "efecto registrado", "evidence": [{
                         "path": "evidence/observacion-sanitizada.txt",
                         "sha256": hashlib.sha256(proof.read_bytes()).hexdigest()}]})
    _json(report_path, report)
    assert validate(pack)["passed_external_gates"] == 1
    proof.write_text("contenido cambiado", encoding="utf-8")
    with pytest.raises(ValueError, match="pilot_evidence_invalid"):
        validate(pack)
