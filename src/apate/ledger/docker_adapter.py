"""Recursos Docker por ID y pertenencia; sin limpieza global ni imágenes por tag."""

from __future__ import annotations

import base64
import json
import re
import time

from ..plugins.base import EventType, PluginLifecycleState, sanitize_payload_text
from . import descriptors
from .repository import LedgerError, digest


class DockerAdapter:
    def __init__(self, facade, descriptor):
        self.facade = facade
        self.plugin = facade.plugin
        self.descriptor = descriptor
        self.descriptor_digest = digest(descriptor)
        self.namespace = "apate-" + digest({"operation": self.plugin.operation_id,
            "capability": self.plugin.plugin_id, "descriptor": self.descriptor_digest})[:24]
        self.client = None

    @property
    def resources(self):
        return self.plugin.config.setdefault("_managed_resources", [])

    def connect(self):
        client = descriptors.docker_client()
        if client.info().get("ID") != self.descriptor["daemon_id"]:
            raise LedgerError("docker_daemon_mismatch")
        self.client = client

    def labels(self, role):
        return {"apate.operation": self.plugin.operation_id, "apate.capability": self.plugin.plugin_id,
            "apate.descriptor": self.descriptor_digest, "apate.resource": role}

    def find(self, role):
        return next((r for r in reversed(self.resources) if r["role"] == role and not r.get("removed")), None)

    def checked(self, resource, *, missing_ok=False):
        from docker.errors import NotFound
        collection = getattr(self.client, resource["kind"])
        try:
            obj = collection.get(resource["id"])
            obj.reload()
        except NotFound:
            if missing_ok:
                resource["removed"] = True
                return None
            raise LedgerError("recorded_resource_missing")
        if obj.id != resource["id"]:
            raise LedgerError("resource_identity_mismatch")
        labels = obj.attrs.get("Config", {}).get("Labels") if resource["kind"] == "containers" else obj.attrs.get("Labels")
        if any((labels or {}).get(key) != value for key, value in self.labels(resource["role"]).items()):
            raise LedgerError("resource_ownership_mismatch")
        if resource.get("image") and obj.attrs.get("Image") != resource["image"]:
            raise LedgerError("resource_image_mismatch")
        return obj

    def network(self, role, **kwargs):
        resource = self.find(role)
        if resource:
            return self.checked(resource)
        obj = self.client.networks.create(self.namespace + "-" + digest(role)[:10],
            labels=self.labels(role), driver="bridge", **kwargs)
        self.resources.append({"kind": "networks", "id": obj.id, "role": role})
        return obj

    def create(self, role, image, **kwargs):
        resource = self.find(role)
        if resource:
            return self.checked(resource)
        if descriptors.image_id(self.client, image) != image:
            raise LedgerError("resource_image_mismatch")
        obj = self.client.containers.create(image, name=self.namespace + "-" + digest(role)[:10],
            labels=self.labels(role), detach=True, **kwargs)
        # Registrar antes de put_archive/start para conservar fallos parciales.
        self.resources.append({"kind": "containers", "id": obj.id, "role": role, "image": image})
        return obj

    def call(self, action, parameters=None):
        self.connect()
        parameters = parameters or {}
        if self.descriptor["kind"] == "opencanary":
            self._opencanary(action)
        elif self.descriptor["kind"] == "dolost":
            self._dolost(action, parameters)
        else:
            self._playground(action, parameters)
        if not parameters:
            self.plugin.state = PluginLifecycleState.RETIRED if action == "retire" else PluginLifecycleState.DEPLOYED
        self.plugin._publish(EventType.INTERACTION,
            {"kind": action, "adapter": self.descriptor["kind"], "parameters": parameters,
                "meaning": "adapter_invocation_returned"})

    def _opencanary(self, action):
        from ..plugins.opencanary_client import build_config, _config_archive, _port_bindings, CONFIG_DIR_IN_CONTAINER
        if action == "deploy":
            config = self.plugin.config
            services = config.get("services", {})
            kwargs = {"network_mode": "host"} if config.get("network_mode") == "host" else {"ports": _port_bindings(services)}
            obj = self.create("opencanary", self.descriptor["image"], **kwargs)
            raw = json.dumps(build_config(node_id=config.get("node_id") or self.plugin.plugin_id, services=services)).encode()
            if obj.put_archive(CONFIG_DIR_IN_CONTAINER, _config_archive(raw)) is not True:
                raise LedgerError("configuration_upload_failed")
            obj.start()
        elif action == "rotate":
            self.checked(self._required("opencanary")).restart()
        else:
            self.remove_containers()

    def _required(self, role):
        resource = self.find(role)
        if resource is None:
            raise LedgerError("recorded_resource_required")
        return resource

    def remove_containers(self, roles=None):
        resources = [r for r in reversed(self.resources) if r["kind"] == "containers" and not r.get("removed") and (roles is None or r["role"] in roles)]
        # Verificar todo antes de tocar el primer recurso del lote.
        objects = [(r, self.checked(r, missing_ok=True)) for r in resources]
        for resource, obj in objects:
            if obj is not None:
                obj.stop()
                obj.remove()
                from docker.errors import NotFound
                try:
                    self.client.containers.get(resource["id"])
                except NotFound:
                    resource["removed"] = True
                else:
                    raise LedgerError("resource_removal_not_confirmed")

    def remove_networks(self):
        resources = [r for r in reversed(self.resources) if r["kind"] == "networks" and not r.get("removed")]
        objects = [(r, self.checked(r, missing_ok=True)) for r in resources]
        for resource, obj in objects:
            if obj is not None:
                obj.remove()
                from docker.errors import NotFound
                try:
                    self.client.networks.get(resource["id"])
                except NotFound:
                    resource["removed"] = True
                else:
                    raise LedgerError("resource_removal_not_confirmed")

    def _dolost(self, action, parameters):
        import docker
        decoys = self.descriptor["decoys"]
        hostname = parameters.get("hostname")
        if hostname is not None:
            decoys = [d for d in decoys if d["Hostname"] == hostname]
            if len(decoys) != 1:
                raise LedgerError("approved_decoy_required")
        subaction = parameters.get("subaction")
        if subaction in {"start", "stop", "undeploy"}:
            roles = ["decoy:" + d["Hostname"] for d in decoys]
            if subaction == "undeploy":
                self.remove_containers(roles)
            else:
                objects = [self.checked(self._required(role)) for role in roles]
                for obj in objects:
                    getattr(obj, subaction)()
            return
        if action == "deploy":
            collector_net = self.network("collector-network")
            collector = self.create("collector", self.descriptor["collector_image"],
                network=collector_net.id, ports={"514/udp": ("127.0.0.1", None)})
            collector.start()
            collector.reload()
            port = collector.attrs["NetworkSettings"]["Ports"]["514/udp"][0]["HostPort"]
            for decoy in decoys:
                role = "decoy-network:" + decoy["DeceptionNetwork"]
                net = self.network(role, ipam=docker.types.IPAMConfig(pool_configs=[
                    docker.types.IPAMPool(subnet=decoy["Subnet"], gateway=decoy["Gateway"])]))
                obj = self.create("decoy:" + decoy["Hostname"], decoy["image"],
                    hostname=decoy["Hostname"], ports=decoy["ports"], network=net.name,
                    networking_config={net.name: docker.types.EndpointConfig("1.35", ipv4_address=decoy["IP"])},
                    log_config=docker.types.LogConfig(type="syslog", config={
                        "syslog-address": f"udp://127.0.0.1:{port}", "tag": decoy["Hostname"]}))
                obj.start()
        elif action == "rotate":
            objects = [self.checked(self._required("decoy:" + d["Hostname"])) for d in decoys]
            for obj in objects:
                obj.restart()
        else:
            self.remove_containers()
            self.remove_networks()

    def _materialize(self):
        root = self.facade.executor.ledger.path.parent / "execution_resources" / self.namespace
        base = self.facade.executor.ledger.path.parent.resolve()
        if not root.resolve().is_relative_to(base):
            raise LedgerError("invalid_snapshot_path")
        root.mkdir(parents=True, exist_ok=True)
        for name, encoded in self.descriptor["files"].items():
            path = root / name
            if not path.resolve().is_relative_to(root.resolve()):
                raise LedgerError("invalid_snapshot_path")
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = base64.b64decode(encoded, validate=True)
            if path.exists():
                if path.read_bytes() != raw:
                    raise LedgerError("materialized_snapshot_changed")
            else:
                with path.open("xb") as target:
                    target.write(raw)
        return root

    def _playground(self, action, parameters):
        if action != "retire":
            self._materialize()
        if parameters.get("subaction") == "attacker":
            resource = self._required("service:attacker")
            container = self.checked(resource)
            from ..playground.events import PlaygroundEventBridge
            adapter = self
            class AttackerSource:
                raw_line = None
                def publish(self, event):
                    raw = {"line": self.raw_line, "parsed_event": event.to_dict()}
                    event.plugin_id = adapter.plugin.plugin_id
                    event.resource_id = container.id
                    event.provenance = {"raw": raw, "generation": container.id, "external_id": None,
                        "origin_time": None, "transformation": "playground-attacker-parser-v1"}
                    return adapter.plugin._bus.publish(event)
            source = AttackerSource()
            bridge = PlaygroundEventBridge(bus=source, operation_id=self.plugin.operation_id)
            exec_id = self.client.api.exec_create(container.id, self.descriptor["attacker_command"])["Id"]
            import codecs
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            buffer = ""
            for chunk in self.client.api.exec_start(exec_id, stream=True):
                buffer += decoder.decode(chunk)
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    source.raw_line = line
                    bridge.ingest_attacker_output_line(line)
            buffer += decoder.decode(b"", final=True)
            if buffer:
                source.raw_line = buffer
                bridge.ingest_attacker_output_line(buffer)
            bridge.finish_attacker_output_stream()
            if self.client.api.exec_inspect(exec_id)["ExitCode"] != 0:
                raise LedgerError("attacker_script_failed")
            return
        if action == "retire":
            self.remove_containers()
            self.remove_networks()
            return
        if action == "rotate":
            objects = [self.checked(r) for r in self.resources if r["kind"] == "containers" and not r.get("removed")]
            for obj in objects:
                obj.restart()
            return
        root = self._materialize()
        document = self.descriptor["compose"]
        networks = {name: self.network("network:" + name) for name in document.get("networks", {})}
        volumes = {}
        for name in document.get("volumes", {}):
            role = "volume:" + name
            resource = self.find(role)
            if resource:
                obj = self.checked(resource)
            else:
                obj = self.client.volumes.create(name=self.namespace + "-" + digest(role)[:10], labels=self.labels(role))
                self.resources.append({"kind": "volumes", "id": obj.name, "role": role, "retained_on_retire": True})
            volumes[name] = obj
        services = document["services"]
        pending = dict(services)
        started = set()
        while pending:
            ready = next((name for name, s in pending.items() if set(s.get("depends_on", {})) <= started), None)
            if ready is None:
                raise LedgerError("cyclic_playground_dependencies")
            service = pending.pop(ready)
            mounts = {}
            for mount in service.get("volumes", []):
                if mount["type"] == "volume":
                    source = volumes[mount["source"]].name
                elif "host_source" in mount:
                    source = mount["host_source"]
                else:
                    path = root / mount["source"]
                    if not path.resolve().is_relative_to(root.resolve()):
                        raise LedgerError("invalid_snapshot_path")
                    if not path.exists():
                        path.mkdir(parents=True)
                    source = str(path)
                mounts[source] = {"bind": mount["target"], "mode": "ro" if mount.get("read_only") else "rw"}
            kwargs = {key: service[key] for key in ("environment", "command", "entrypoint", "user", "stdin_open", "tty", "hostname", "working_dir") if key in service}
            kwargs["volumes"] = mounts
            kwargs["ports"] = {f"{p['target']}/{p.get('protocol', 'tcp')}": (p.get("host_ip", "0.0.0.0"), int(p["published"])) for p in service.get("ports", [])}
            if service.get("restart"):
                kwargs["restart_policy"] = {"Name": service["restart"]}
            net_names = list(service.get("networks", {}))
            # Conectar antes de arrancar; evita usar nombres globales.
            if net_names:
                import docker
                kwargs["network"] = networks[net_names[0]].name
                kwargs["networking_config"] = {networks[name].name:
                    docker.types.EndpointConfig("1.35", aliases=list(dict.fromkeys([ready, *([service["container_name"]] if service.get("container_name") else []),
                        *(service["networks"][name] or {}).get("aliases", [])]))) for name in net_names}
            if service.get("healthcheck"):
                health = service["healthcheck"]
                def duration(value):
                    if type(value) is int:
                        return value
                    matches = list(re.finditer(r"([0-9]+)(ns|us|ms|s|m|h)", value))
                    if not matches or "".join(match[0] for match in matches) != value:
                        raise LedgerError("invalid_healthcheck_duration")
                    return sum(int(match[1]) * {"ns": 1, "us": 1000, "ms": 1000000, "s": 1000000000, "m": 60000000000, "h": 3600000000000}[match[2]] for match in matches)
                kwargs["healthcheck"] = {"test": health["test"], "retries": health.get("retries", 3)}
                for key in ("interval", "timeout", "start_period"):
                    if key in health:
                        kwargs["healthcheck"][key] = duration(health[key])
            obj = self.create("service:" + ready, service["image"], **kwargs)
            obj.start()
            if any(s.get("depends_on", {}).get(ready, {}).get("condition") == "service_healthy" for s in services.values()):
                deadline = time.monotonic() + 180
                while True:
                    obj.reload()
                    status = obj.attrs.get("State", {}).get("Health", {}).get("Status")
                    if status == "healthy":
                        break
                    if status == "unhealthy" or time.monotonic() >= deadline:
                        raise LedgerError("playground_dependency_not_healthy")
                    time.sleep(1)
            started.add(ready)

    def observe(self, *, since=None):
        self.connect()
        if self.descriptor["kind"] == "opencanary":
            from ..plugins.opencanary_client import OpenCanaryHit
            obj = self.checked(self._required("opencanary"))
            kwargs = {"stdout": True, "stderr": False}
            if since is not None:
                kwargs["since"] = int(since)
            result = []
            for line in obj.logs(**kwargs).decode("utf-8", errors="replace").splitlines():
                try:
                    raw = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(raw, dict):
                    continue
                hit = OpenCanaryHit.from_raw(raw)
                payload = {"kind": "trigger", "source_ip": hit.src_host, "logtype": hit.logtype, "logdata": hit.logdata}
                ttp = self.plugin.config.get("ttp_id")
                if ttp:
                    payload["ttp_id"] = ttp
                result.append(self.plugin._publish(EventType.TTP_OBSERVED if ttp else EventType.INTERACTION,
                    payload, resource_id="container:" + obj.id))
            return result
        if self.descriptor["kind"] == "dolost":
            obj = self.checked(self._required("collector"))
            from DOLOST.services import events
            # Los parsers puros existentes conservan su formato, sin cambiar
            # el singleton global ni su función _read_log_file.
            result = []
            seen = getattr(self, "_seen", set())
            specs = [(events._IPS_LOG_PATH, 3, "network_connection"),
                (events._USAGE_LOG_PATH, 2, "decoy_usage"), (events._INTERESTING_LOG_PATH, 3, "interesting_observable")]
            for path, count, kind in specs:
                response = obj.exec_run(["cat", path])
                if response.exit_code != 0:
                    raise LedgerError("collector_read_failed")
                for line in response.output.decode("utf-8", errors="replace").splitlines():
                    fields = events._parse_csv_record(line, count)
                    if fields is None:
                        continue
                    hostname = fields[1]
                    resource = self.find("decoy:" + hostname)
                    signature = (kind, line)
                    if resource is None or signature in seen:
                        continue
                    seen.add(signature)
                    payload = {"kind": kind, "detail": sanitize_payload_text(line)}
                    if kind == "network_connection":
                        payload["source_ip"] = sanitize_payload_text(fields[2])
                    result.append(self.plugin._publish(EventType.INTERACTION, payload, resource_id="container:" + resource["id"]))
            self._seen = seen
            return result
        return []
