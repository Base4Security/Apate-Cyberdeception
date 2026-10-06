"""Verificación local de artefactos sin Docker ni servicios remotos.

El manifiesto identifica bytes, no promete una etiqueta estable ni un árbol limpio.
"""
from __future__ import annotations

import argparse
from email.parser import Parser
import hashlib
import importlib.metadata as metadata
import json
from pathlib import Path
import re
import tempfile
import zipfile


def verify_wheel(path: Path, expected_plugins=None) -> dict:
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        required = {
            "apate/ledger/repository.py", "apate/plugins/playground_plugin.py",
            "apate/release.py", "apate/ops.py", "apate/doctor.py", "apate/sbom.py",
            "apate/schema_version.py", "apate/deployment/connector.py",
            "apate/web/_readiness.py", "apate/web/_request_observability.py",
            "apate/playground/_stack/docker-compose.yml", "apate/playground/_stack/LICENSE",
            "apate/web/templates/base.html", "apate/web/static/theme.css",
            "apate/web/translations/en/LC_MESSAGES/messages.mo",
        }
        missing = sorted(required - names)
        if missing:
            raise ValueError("wheel_missing:" + ",".join(missing))
        if any(name.startswith("/") or ".." in Path(name).parts for name in names):
            raise ValueError("wheel_unsafe_path")
        points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(points) != 1:
            raise ValueError("wheel_metadata_ambiguous")
        import configparser
        config = configparser.ConfigParser()
        config.read_string(archive.read(points[0]).decode("utf-8"))
        plugins = dict(config["apate.plugins"])
        if expected_plugins is not None and plugins != expected_plugins:
            raise ValueError("wheel_entry_points_differ_from_source")
        for name, target in plugins.items():
            module = target.split(":", 1)[0].replace(".", "/") + ".py"
            if module not in names:
                raise ValueError("entry_point_missing_module:" + name)
        if "playground" not in plugins or "local" not in config["apate.identity_providers"]:
            raise ValueError("wheel_missing_capability")
        if not any(name.endswith("/LICENSE") and ".dist-info/" in name for name in names):
            raise ValueError("wheel_missing_license")
        if not any(name.endswith("/NOTICE") and ".dist-info/" in name for name in names):
            raise ValueError("wheel_missing_notice")
        metadata_files = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_files) != 1:
            raise ValueError("wheel_metadata_ambiguous")
        package = Parser().parsestr(archive.read(metadata_files[0]).decode("utf-8"))
        if package.get("Name", "").lower() != "apate" or not package.get("Version"):
            raise ValueError("wheel_package_metadata_invalid")
        return {"artifact": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "version": package["Version"], "files": len(names), "plugins": plugins}


def verify_installed() -> dict:
    from .playground.config import PlaygroundConfig
    distribution = metadata.distribution("apate")
    if not any(str(path).replace("\\", "/").endswith("/licenses/NOTICE")
               for path in distribution.files or ()):
        raise ValueError("installed_missing_notice")
    groups = {}
    for group in ("apate.plugins", "apate.identity_providers"):
        own = {point.name: point for point in distribution.entry_points if point.group == group}
        available = list(metadata.entry_points(group=group))
        for name, point in own.items():
            if sum(candidate.name == name for candidate in available) != 1:
                raise ValueError("entry_point_ambiguous:" + name)
            point.load()
        groups[group] = sorted(own)
    if "playground" not in groups["apate.plugins"] or "local" not in groups["apate.identity_providers"]:
        raise ValueError("installed_missing_capability")
    stack = PlaygroundConfig.from_env({}).path
    if not (stack / "LICENSE").is_file():
        raise ValueError("installed_missing_stack_license")
    return {"version": distribution.version, "entry_points": groups, "playground": str(stack)}


def source_plugins(path: Path) -> dict:
    """Lee la sección simple de entry points, también en Python 3.10."""
    import ast
    import re
    text = path.read_text(encoding="utf-8")
    match = re.search(r'\[project.entry-points\."apate.plugins"\]\s*\n(.*?)(?=\n\[|\Z)', text, re.S)
    if match is None:
        raise ValueError("source_entry_points_missing")
    result = {}
    for line in match[1].splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            name, value = line.split("=", 1)
            result[name.strip()] = ast.literal_eval(value.strip())
    return result


def smoke_distribution(*, scratch: Path | None = None, expected_commit: str | None = None,
                       notice: Path | None = None, sbom: Path | None = None) -> dict:
    """Ejercita una instalación y su restauración con datos sintéticos efímeros."""
    from datetime import datetime, timedelta, timezone
    import gc

    from .backup import create_backup, restore_backup, verify_backup
    from .core import AdversaryProfile, Narrative, Operation, RulesOfEngagement
    from .plugins.base import EventType
    from .provenance import build_info
    from .telemetry.models import TelemetryRecord
    from .web import create_app

    installed = verify_installed()
    build = build_info()
    if expected_commit and build.commit != expected_commit:
        raise ValueError("release_commit_mismatch")
    if notice is not None and "APATE" not in notice.read_text(encoding="utf-8"):
        raise ValueError("release_notice_missing")
    if sbom is not None:
        document = json.loads(sbom.read_text(encoding="utf-8"))
        component = document.get("metadata", {}).get("component", {})
        if (document.get("bomFormat") != "CycloneDX" or component.get("name") != "apate"
                or component.get("version") != installed["version"]):
            raise ValueError("release_sbom_mismatch")
        if expected_commit and {item.get("value") for item in component.get("properties", [])
                                if item.get("name") == "apate:build:commit"} != {expected_commit}:
            raise ValueError("release_sbom_commit_mismatch")
        if build.source_url and build.source_url not in {item.get("url") for item in component.get("externalReferences", [])
                                                          if item.get("type") == "distribution-source"}:
            raise ValueError("release_sbom_source_mismatch")

    if scratch is not None:
        scratch = scratch.resolve()
        scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="apate-release-", dir=scratch) as temporary:
        root = Path(temporary)
        data = root / "data"
        config = {"TESTING": True, "APATE_DATA_DIR": data, "APATE_RULES_PATH": data / "rules.yaml",
                  "APATE_MOUNT_EXTERNAL_TOOLS": False, "APATE_HONEYUSER_MONITORING_ENABLED": False}
        app = create_app(config)
        operation = Operation(name="Smoke sintético", adversary_profile=AdversaryProfile("Hipótesis"),
                              roe=RulesOfEngagement(), narrative=Narrative("Historia de prueba"))
        app.config["OPERATION_REPOSITORY"].save(operation)
        event = TelemetryRecord(event_type=EventType.INTERACTION, operation_id=operation.id,
                                plugin_id="smoke", surface="synthetic", timestamp=datetime.now(timezone.utc),
                                source_event_id="release-smoke-1")
        app.config["TELEMETRY_COLLECTOR"].repository.append(event)
        bearer = app.config["MACHINE_TOKEN_REPOSITORY"].create(
            name="release-smoke", scopes={"operations:read", "telemetry:read"},
            operation_ids={operation.id}, expires_at=datetime.now(timezone.utc) + timedelta(minutes=10))
        headers = {"Authorization": f"Bearer {bearer}"}
        client = app.test_client()
        for path in ("/about", "/operations/"):
            response = client.get(path)
            if response.status_code != 200:
                raise ValueError("release_web_smoke_failed")
            if path == "/about" and ((expected_commit and expected_commit not in response.get_data(as_text=True))
                                     or (build.source_url and build.source_url not in response.get_data(as_text=True))):
                raise ValueError("release_provenance_not_visible")
        detail = f"/api/v1/operations/{operation.id}"
        telemetry = detail + "/telemetry"
        if client.get(detail, headers=headers).json["operation"]["id"] != operation.id:
            raise ValueError("release_operation_read_failed")
        if [item["source_event_id"] for item in client.get(telemetry, headers=headers).json["events"]] != [event.source_event_id]:
            raise ValueError("release_telemetry_read_failed")
        if not app.config["MACHINE_TOKEN_REPOSITORY"].list_audit():
            raise ValueError("release_audit_missing")

        backup = root / "backup"
        manifest = create_backup(data, backup)
        verify_backup(backup)
        restored = root / "restored"
        restore_backup(backup, restored)
        restored_app = create_app({**config, "APATE_DATA_DIR": restored,
                                   "APATE_RULES_PATH": restored / "rules.yaml"})
        restored_client = restored_app.test_client()
        if restored_client.get("/about").status_code != 200:
            raise ValueError("release_restored_web_failed")
        if restored_client.get(detail, headers=headers).json["operation"]["id"] != operation.id:
            raise ValueError("release_restored_operation_missing")
        if [item["source_event_id"] for item in restored_client.get(telemetry, headers=headers).json["events"]] != [event.source_event_id]:
            raise ValueError("release_restored_telemetry_missing")
        if not restored_app.config["MACHINE_TOKEN_REPOSITORY"].list_audit():
            raise ValueError("release_restored_audit_missing")
        result = {"version": installed["version"], "commit": build.commit, "web": "ok",
                  "machine_api": "ok", "backup_restore": "ok", "backup_files": len(manifest["files"]),
                  "external_services": "not_used"}
        # sqlite3.Connection.__exit__ confirma la transacción pero no cierra el
        # descriptor: liberar clientes y recolectar antes de borrar en Windows.
        del client, restored_client, app, restored_app
        gc.collect()
        return result


def release_evidence(*, wheel: Path, sbom: Path, notice: Path, lock: Path,
                     build_lock: Path, base_image: str, image_id: Path,
                     expected_commit: str, source_url: str,
                     upgrade_smoke: Path | None = None) -> dict:
    """Vincula bytes de la candidata con fuente y build declarados.

    Es evidencia autocontenida, no una firma ni una atestación de un tercero.
    """
    if not re.fullmatch(r"python:[^@]+@sha256:[0-9a-f]{64}", base_image):
        raise ValueError("release_base_image_not_pinned")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ValueError("release_commit_invalid")
    if not source_url.startswith("https://") or expected_commit not in source_url:
        raise ValueError("release_source_url_invalid")
    identifier = image_id.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", identifier):
        raise ValueError("release_image_id_invalid")
    wheel_info = verify_wheel(wheel)
    document = json.loads(sbom.read_text(encoding="utf-8"))
    component = document.get("metadata", {}).get("component", {})
    if document.get("bomFormat") != "CycloneDX" or component.get("name") != "apate":
        raise ValueError("release_sbom_invalid")
    if component.get("version") != wheel_info["version"]:
        raise ValueError("release_sbom_version_mismatch")
    if {item.get("value") for item in component.get("properties", [])
            if item.get("name") == "apate:build:commit"} != {expected_commit}:
        raise ValueError("release_sbom_commit_mismatch")
    if source_url not in {item.get("url") for item in component.get("externalReferences", [])
                          if item.get("type") == "distribution-source"}:
        raise ValueError("release_sbom_source_mismatch")
    if "APATE" not in notice.read_text(encoding="utf-8"):
        raise ValueError("release_notice_missing")
    requirements = lock.read_text(encoding="utf-8")
    if not re.search(r"(?m)^\w[\w.-]*==[^\s]+\s*\\\s*\n\s*--hash=sha256:", requirements):
        raise ValueError("release_lock_invalid")
    if "--hash=sha256:" not in build_lock.read_text(encoding="utf-8"):
        raise ValueError("release_build_lock_invalid")

    def artifact(path: Path) -> dict:
        return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}

    artifacts = {"wheel": artifact(wheel), "image_sbom": artifact(sbom),
                 "notice": artifact(notice), "runtime_lock": artifact(lock),
                 "build_lock": artifact(build_lock)}
    if upgrade_smoke is not None:
        upgrade = json.loads(upgrade_smoke.read_text(encoding="utf-8"))
        if not isinstance(upgrade, dict):
            raise ValueError("release_upgrade_smoke_mismatch")
        baseline_hash = upgrade.get("baseline_wheel_sha256")
        if (upgrade.get("format") != 1 or upgrade.get("candidate_wheel_sha256") != artifacts["wheel"]["sha256"]
                or not isinstance(baseline_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", baseline_hash)
                or baseline_hash == artifacts["wheel"]["sha256"]
                or any(upgrade.get(key) != "ok" for key in ("upgrade", "candidate_restore", "rollback"))
                or upgrade.get("original_unchanged") is not True
                or upgrade.get("external_services") != "not_used"):
            raise ValueError("release_upgrade_smoke_mismatch")
        artifacts["upgrade_smoke"] = artifact(upgrade_smoke)
    return {"format": 1, "commit": expected_commit, "source_url": source_url,
            "version": component.get("version"), "base_image": base_image, "image_id": identifier,
            "wheel_files": wheel_info["files"], "runtime_packages_locked": len(re.findall(r"(?m)^\w[\w.-]*==", requirements)),
            "artifacts": artifacts,
            "signed_attestation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("wheel", "installed", "smoke", "evidence"))
    parser.add_argument("path", nargs="?", type=Path)
    parser.add_argument("--project", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--notice", type=Path)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--build-lock", type=Path)
    parser.add_argument("--base-image")
    parser.add_argument("--image-id", type=Path)
    parser.add_argument("--source-url")
    parser.add_argument("--upgrade-smoke", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "wheel" and args.path is None:
        parser.error("wheel requiere una ruta")
    expected = source_plugins(args.project / "pyproject.toml") if args.project else None
    if args.command == "wheel":
        result = verify_wheel(args.path, expected)
    elif args.command == "smoke":
        result = smoke_distribution(scratch=args.scratch, expected_commit=args.expected_commit,
                                    notice=args.notice, sbom=args.sbom)
    elif args.command == "evidence":
        if not all((args.wheel, args.sbom, args.notice, args.lock, args.build_lock,
                    args.base_image, args.image_id, args.expected_commit, args.source_url)):
            parser.error("evidence requiere wheel, SBOM, NOTICE, locks, imagen, commit y fuente")
        result = release_evidence(wheel=args.wheel, sbom=args.sbom, notice=args.notice,
                                  lock=args.lock, build_lock=args.build_lock,
                                  base_image=args.base_image, image_id=args.image_id,
                                  expected_commit=args.expected_commit, source_url=args.source_url,
                                  upgrade_smoke=args.upgrade_smoke)
    else:
        result = verify_installed()
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
