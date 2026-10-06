"""Revisa offline un artefacto de CI antes de identificar una candidata."""

from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import re
from zipfile import ZipFile


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _document(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"artifact_invalid_json_object:{path.name}")
    return value


def review(artifact_dir: Path, project: Path, *, commit: str, version: str) -> dict:
    """Contrasta el manifiesto con bytes, procedencia y smoke reales de CI."""

    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("artifact_commit_invalid")
    wheels = list(artifact_dir.glob("apate-*.whl"))
    if len(wheels) != 1:
        raise ValueError("artifact_wheel_count_invalid")
    wheel = wheels[0]
    evidence = _document(artifact_dir / "release-evidence.json")
    smoke = _document(artifact_dir / "upgrade-smoke.json")
    sbom = _document(artifact_dir / "apate-image.cdx.json")
    if (evidence.get("format") != 1 or evidence.get("commit") != commit
            or evidence.get("version") != version or commit not in evidence.get("source_url", "")):
        raise ValueError("artifact_identity_mismatch")
    paths = {
        "wheel": wheel,
        "image_sbom": artifact_dir / "apate-image.cdx.json",
        "upgrade_smoke": artifact_dir / "upgrade-smoke.json",
        "notice": project / "NOTICE",
        "runtime_lock": project / "requirements" / "release.txt",
        "build_lock": project / "requirements" / "build.txt",
    }
    declared = evidence.get("artifacts")
    if not isinstance(declared, dict) or set(paths) != set(declared):
        raise ValueError("artifact_manifest_incomplete")
    for name, path in paths.items():
        expected = declared[name]
        if not isinstance(expected, dict) or expected.get("sha256") != _digest(path) or expected.get("bytes") != path.stat().st_size:
            raise ValueError(f"artifact_digest_mismatch:{name}")
    if (artifact_dir / "apate-image-id.txt").read_text(encoding="utf-8").strip() != evidence.get("image_id"):
        raise ValueError("artifact_image_id_mismatch")
    with ZipFile(wheel) as archive:
        metadata_paths = [name for name in archive.namelist() if re.fullmatch(r"apate-[^/]+\.dist-info/METADATA", name)]
        if len(metadata_paths) != 1:
            raise ValueError("artifact_wheel_metadata_invalid")
        metadata = BytesParser().parsebytes(archive.read(metadata_paths[0]))
        if metadata.get("Name", "").lower() != "apate" or metadata.get("Version") != version:
            raise ValueError("artifact_wheel_version_mismatch")
    component = sbom.get("metadata", {}).get("component", {})
    if (sbom.get("bomFormat") != "CycloneDX" or component.get("name") != "apate"
            or component.get("version") != version
            or commit not in {item.get("value") for item in component.get("properties", [])
                              if item.get("name") == "apate:build:commit"}
            or evidence["source_url"] not in {item.get("url") for item in component.get("externalReferences", [])
                                               if item.get("type") == "distribution-source"}):
        raise ValueError("artifact_sbom_mismatch")
    if (smoke.get("format") != 1 or smoke.get("candidate_wheel_sha256") != _digest(wheel)
            or smoke.get("baseline_wheel_sha256") == _digest(wheel)
            or any(smoke.get(key) != "ok" for key in ("upgrade", "candidate_restore", "rollback"))
            or smoke.get("original_unchanged") is not True or smoke.get("external_services") != "not_used"):
        raise ValueError("artifact_upgrade_smoke_mismatch")
    return {"review": "PASSED", "commit": commit, "version": version,
            "wheel_sha256": _digest(wheel), "upgrade_smoke_sha256": _digest(paths["upgrade_smoke"]),
            "external_gates": "NOT_RUN", "signature_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = review(args.artifact_dir, args.project, commit=args.commit, version=args.version)
    with args.output.open("x", encoding="utf-8") as target:
        target.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
