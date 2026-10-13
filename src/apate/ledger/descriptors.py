"""Fotos revisables de dependencias externas; capturarlas no despliega recursos."""

from __future__ import annotations

import ast
import base64
import json
from pathlib import Path
import re
import subprocess

from .repository import LedgerError, digest, json_snapshot

DOCKER_KINDS = frozenset({"opencanary", "dolost", "playground"})
MANAGED_KINDS = DOCKER_KINDS | {"buda"}


def docker_client():
    import docker
    try:
        return docker.from_env()
    except Exception as error:
        raise LedgerError("docker_snapshot_unavailable") from error


def image_id(client, reference):
    """Resolver solo imágenes locales: ni pull ni build durante una propuesta."""
    from docker.errors import NotFound
    try:
        image = client.images.get(reference)
    except NotFound as error:
        raise LedgerError("prepared_image_required") from error
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image.id):
        raise LedgerError("immutable_image_required")
    return image.id


def capture_buda(binding):
    from flask import has_app_context
    if not has_app_context():
        raise LedgerError("buda_application_context_required")
    from BUDA.app import db
    from BUDA.models import Narrative
    narrative = db.session.get(Narrative, binding.config.get("narrative_id"))
    if narrative is None or narrative.is_running:
        raise LedgerError("stopped_buda_narrative_required")
    steps = []
    for profile in sorted(narrative.user_profiles, key=lambda p: p.id):
        if not profile.credentials_recoverable:
            raise LedgerError("recoverable_buda_credentials_required")
        for activity in sorted(profile.activities, key=lambda a: a.id):
            commands = activity.approved_commands()
            if not commands:
                raise LedgerError("approved_buda_commands_required")
            for command in commands:
                steps.append({"profile_id": profile.id, "profile_name": profile.name, "profile_role": profile.role,
                    "activity_id": activity.id, "activity_type": activity.activity_type,
                    "server": profile.winrm_server, "username": profile.winrm_username,
                    "password": profile.winrm_password, "command": command})
    return {"kind": "buda", "narrative_id": narrative.id,
        "title": narrative.title, "end_date": narrative.end_date.isoformat(),
        "steps": steps, "cycles": binding.config.get("cycles", 1),
        "interval_seconds": binding.config.get("interval_seconds", 30)}


def _playground(binding, client):
    from ..playground.config import PlaygroundConfig
    config = PlaygroundConfig.from_path(binding.config["path"])
    level = binding.config.get("level", "basic")
    if level not in {"none", "basic", "complete", "impossible"}:
        raise LedgerError("invalid_playground_level")
    import os
    completed = subprocess.run(["docker", "compose", "--profile", level, "config", "--format", "json"],
        cwd=config.path, env={**os.environ, "DECEPTION_LEVEL": level},
        capture_output=True, text=True, check=True, timeout=60)
    document = json.loads(completed.stdout)
    services = {name: service for name, service in document["services"].items()
        if not service.get("profiles") or level in service["profiles"]}
    document["services"] = services
    for network in document.get("networks", {}).values():
        if set(network) - {"name", "driver"} or network.get("driver", "bridge") != "bridge":
            raise LedgerError("unsupported_playground_network")
    for volume in document.get("volumes", {}).values():
        if set(volume) - {"name", "driver"} or volume.get("driver", "local") != "local":
            raise LedgerError("unsupported_playground_volume")
    files = {}
    root = config.path.resolve()
    allowed = {"image", "build", "container_name", "environment", "command", "entrypoint", "ports",
        "volumes", "networks", "depends_on", "profiles", "restart", "healthcheck", "user",
        "stdin_open", "tty", "hostname", "labels", "working_dir"}
    for name, service in services.items():
        if set(service) - allowed:
            raise LedgerError("unsupported_playground_service_option")
        for network in service.get("networks", {}).values():
            if set(network or {}) - {"aliases"}:
                raise LedgerError("unsupported_playground_endpoint")
        reference = binding.config.get("images", {}).get(name) or service.get("image") or f"{document['name']}-{name}"
        service["image"] = image_id(client, reference)
        service.pop("build", None)
        for mount in service.get("volumes", []):
            if mount["type"] != "bind":
                if mount["type"] != "volume":
                    raise LedgerError("unsupported_playground_mount")
                continue
            source = Path(mount["source"]).resolve()
            if not source.is_relative_to(root):
                # Dos lecturas del host Docker ya presentes en Filebeat.
                if mount.get("read_only") and mount["source"] in {"/var/run/docker.sock", "/var/lib/docker/containers"}:
                    mount["host_source"] = mount.pop("source")
                    continue
                raise LedgerError("external_playground_bind_not_supported")
            relative = source.relative_to(root).as_posix()
            mount["source"] = relative
            if mount.get("read_only") or source.is_file():
                mount["read_only"] = True
                paths = [source] if source.is_file() else sorted(source.rglob("*"))
                for path in paths:
                    if path.is_symlink():
                        raise LedgerError("symlink_in_playground_snapshot")
                    if path.is_file():
                        files[path.relative_to(root).as_posix()] = base64.b64encode(path.read_bytes()).decode("ascii")
            # Los logs escribibles tienen una carpeta nueva por capacidad.
    if sum(len(value) for value in files.values()) > 32 * 1024 * 1024:
        raise LedgerError("playground_snapshot_too_large")
    return {"kind": "playground", "level": level, "compose": document, "files": files,
        "attacker_command": ["sh", "-c", "printf 'c\\nc\\nc\\nc\\nc\\nc\\nc\\nc\\nc\\nc\\n' | python3 attack_scripts/main_attacker.py"]}


def capture_descriptor(binding, *, buda_snapshotter=None):
    from ..plugins.registry import PluginRegistry
    kind = PluginRegistry.resolve_binding_kind(binding)
    if kind not in MANAGED_KINDS:
        return None
    if kind == "buda":
        snapshot = (buda_snapshotter or capture_buda)(binding)
    else:
        client = docker_client()
        daemon = client.info().get("ID")
        if not daemon:
            raise LedgerError("docker_daemon_identity_required")
        if kind == "opencanary":
            mode = binding.config.get("network_mode", "bridge")
            if mode not in {"bridge", "host"}:
                raise LedgerError("unsupported_network_mode")
            snapshot = {"kind": kind, "image": image_id(client, binding.config.get("image", "thinkst/opencanary"))}
        elif kind == "dolost":
            decoys = json_snapshot(binding.config.get("decoys", []))
            if len({d["Hostname"] for d in decoys}) != len(decoys):
                raise LedgerError("ambiguous_decoy_identity")
            images = binding.config.get("images", {})
            for decoy in decoys:
                reference = images.get(decoy["Hostname"], f"decoy_image_{decoy['DecoyFiles']}:dolost")
                decoy["image"] = image_id(client, reference)
                ports = decoy["ServicePorts"]
                decoy["ports"] = ast.literal_eval(ports) if isinstance(ports, str) else ports
                if not isinstance(decoy["ports"], dict):
                    raise LedgerError("invalid_decoy_ports")
            snapshot = {"kind": kind, "collector_image": image_id(client, images.get("collector", "collector_image:dolost")), "decoys": decoys}
        else:
            snapshot = _playground(binding, client)
        snapshot["daemon_id"] = daemon
    snapshot = json_snapshot(snapshot)
    snapshot["binding_digest"] = digest(binding.to_dict())
    validate_descriptor(snapshot)
    return snapshot


def validate_descriptor(snapshot):
    if not isinstance(snapshot, dict) or snapshot.get("kind") not in MANAGED_KINDS:
        raise LedgerError("invalid_adapter_descriptor")
    if snapshot["kind"] == "buda":
        from datetime import date
        try:
            date.fromisoformat(snapshot["end_date"])
        except (KeyError, TypeError, ValueError) as error:
            raise LedgerError("invalid_buda_deadline") from error
        if not snapshot.get("steps") or type(snapshot.get("cycles")) is not int or not 1 <= snapshot["cycles"] <= 100:
            raise LedgerError("finite_buda_batch_required")
        interval = snapshot.get("interval_seconds")
        if type(interval) not in {int, float} or not 0 <= interval <= 3600:
            raise LedgerError("invalid_buda_interval")
        for step in snapshot["steps"]:
            if any(not isinstance(step.get(key), str) or not step[key].strip() for key in ("server", "username", "password", "command")):
                raise LedgerError("invalid_buda_step")
    elif not isinstance(snapshot.get("daemon_id"), str) or not snapshot["daemon_id"]:
        raise LedgerError("docker_daemon_identity_required")
    else:
        kind = snapshot["kind"]
        images = [snapshot.get("image")] if kind == "opencanary" else [snapshot.get("collector_image"), *[d.get("image") for d in snapshot.get("decoys", [])]] if kind == "dolost" else [s.get("image") for s in snapshot.get("compose", {}).get("services", {}).values()]
        if not images or any(not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in images):
            raise LedgerError("immutable_image_required")
        if kind == "playground":
            for name, encoded in snapshot.get("files", {}).items():
                from pathlib import PurePosixPath
                path = PurePosixPath(name)
                if path.is_absolute() or ".." in path.parts or ":" in name or "\\" in name:
                    raise LedgerError("invalid_snapshot_path")
                base64.b64decode(encoded, validate=True)


def descriptor_for(plan, capability_id):
    for item in plan["payload"]["content"]["external_resource_versions"]["items"]:
        if item["kind"] == "plugin_descriptor" and item["id"] == capability_id:
            if digest(item["snapshot"]) != item["sha256"]:
                raise LedgerError("resource_digest_mismatch")
            validate_descriptor(item["snapshot"])
            return json_snapshot(item["snapshot"])
    raise LedgerError("adapter_not_frozen")
