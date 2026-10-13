"""Adaptadores B1: aislamiento, versiones congeladas, fallos y vías HTTP."""

from datetime import date, timedelta
from types import SimpleNamespace
import copy
import json

from docker.errors import NotFound
import pytest

from tests.test_operation_execution import setup, activate, policy, web_operation
from tests.test_web_external import mounted_app
from apate.core import PluginBinding
from apate.ledger import LedgerError
from apate.ledger import descriptors
from apate.ledger.buda_adapter import BudaAdapter
from apate.ledger.plugins import approved_plugins
from apate.plugins import EventBus

IMAGE = "sha256:" + "a" * 64
OTHER_IMAGE = "sha256:" + "b" * 64


class DockerObject:
    def __init__(self, collection, identifier, role, labels, *, image=None, kwargs=None):
        self.collection = collection
        self.id = identifier
        self.name = role
        self.calls = []
        self.status = "created"
        self.kwargs = kwargs or {}
        self.attrs = {"Labels": labels, "Config": {"Labels": labels}, "Image": image,
            "NetworkSettings": {"Ports": {"514/udp": [{"HostPort": "10514"}]}},
            "State": {"Health": {"Status": "healthy"}}}

    def reload(self):
        pass

    def start(self):
        self.calls.append("start")
        self.status = "running"
        if self.collection.client.fail_start:
            raise TimeoutError("Efecto incierto")

    def restart(self):
        self.calls.append("restart")
        self.status = "running"

    def stop(self):
        self.calls.append("stop")
        self.status = "stopped"

    def remove(self):
        self.calls.append("remove")
        del self.collection.objects[self.id]

    def put_archive(self, path, data):
        self.archive = data
        return True

    def logs(self, **kwargs):
        return b'{"logtype": 1000, "src_host": "192.0.2.3", "logdata": {}}\n'

    def connect(self, obj, **kwargs):
        self.calls.append(("connect", obj.id, kwargs))

    def exec_run(self, command):
        return SimpleNamespace(exit_code=0, output=b"2026-09-26,server,192.0.2.3\n")


class DockerCollection:
    def __init__(self, client, kind):
        self.client, self.kind = client, kind
        self.objects = {}

    def get(self, identifier):
        if identifier not in self.objects:
            raise NotFound("No existe")
        return self.objects[identifier]

    def create(self, *args, **kwargs):
        name = kwargs.get("name") or args[0]
        if any(obj.name == name for obj in self.objects.values()):
            raise RuntimeError("Nombre ocupado")
        identifier = name if self.kind == "volumes" else f"{self.kind}-{self.client.counter}"
        self.client.counter += 1
        image = args[0] if self.kind == "containers" else None
        obj = DockerObject(self, identifier, name, copy.deepcopy(kwargs["labels"]), image=image, kwargs=kwargs)
        if self.kind == "containers":
            from docker.models.containers import _create_container_args
            obj.engine_config = _create_container_args({**copy.deepcopy(kwargs), "image": image, "version": "1.44"})
        self.objects[identifier] = obj
        return obj


class DockerDouble:
    def __init__(self):
        self.daemon = "daemon-A"
        self.counter = 1
        self.fail_start = False
        self.references = {"thinkst/opencanary": IMAGE, "collector_image:dolost": IMAGE,
            "decoy_image_ssh:dolost": IMAGE, "lab-attacker": IMAGE, "lab-frontend": IMAGE}
        self.images = SimpleNamespace(get=self.image)
        self.containers = DockerCollection(self, "containers")
        self.networks = DockerCollection(self, "networks")
        self.volumes = DockerCollection(self, "volumes")
        self.executions = []
        self.api = SimpleNamespace(exec_create=self.exec_create,
            exec_start=lambda *a, **k: iter([b"Fase terminada\n"]), exec_inspect=lambda *a: {"ExitCode": 0})

    def image(self, reference):
        if reference in {IMAGE, OTHER_IMAGE}:
            return SimpleNamespace(id=reference)
        return SimpleNamespace(id=self.references[reference])

    def info(self):
        return {"ID": self.daemon}

    def exec_create(self, identifier, command):
        self.executions.append((identifier, copy.deepcopy(command)))
        return {"Id": "exec-1"}


@pytest.fixture
def docker(monkeypatch):
    client = DockerDouble()
    monkeypatch.setattr(descriptors, "docker_client", lambda: client)
    return client


def configure(setup, kind, config=None, *, limit=30):
    operation, service, executor = setup
    operation.plugins = [PluginBinding("cap", "network", plugin_kind=kind, config=config or {})]
    service.operations.save(operation)
    plan = activate(service, operation.id, execution_policy=policy(operation.id, limit=limit))
    return operation, service, executor, plan


def proxy(executor, operation):
    return approved_plugins(executor, operation.id, EventBus())["cap"]


def decoy_config():
    return {"decoys": [{"Hostname": "server", "Description": "Señuelo", "IP": "192.0.2.10",
        "Subnet": "192.0.2.0/24", "Gateway": "192.0.2.1", "DeceptionNetwork": "lab",
        "ServicePorts": "{'22/tcp': 2222}", "Service": "ssh", "DecoyFiles": "ssh"}]}


def buda_snapshot():
    return {"kind": "buda", "narrative_id": 1, "title": "Lote aprobado",
        "end_date": (date.today() + timedelta(days=1)).isoformat(), "cycles": 1, "interval_seconds": 0,
        "steps": [{"profile_id": 1, "activity_id": 1, "server": "https://host-A:5986",
            "username": "usuario-A", "password": "secreto-A", "command": command} for command in ("Get-Date", "Get-Process")]}


def playground_document(root):
    return {"name": "lab", "networks": {"lab": {}}, "volumes": {"db": {}},
        "services": {"frontend": {"image": "lab-frontend", "networks": {"lab": {}},
            "environment": {"DECEPTION_LEVEL": "basic"}, "volumes": [
                {"type": "bind", "source": str(root / "config.json"), "target": "/config.json", "read_only": True}]},
            "attacker": {"image": "lab-attacker", "networks": {"lab": {}}, "depends_on": {"frontend": {"condition": "service_started"}},
                "volumes": [{"type": "volume", "source": "db", "target": "/data"}]}}}


def playground(setup, docker, monkeypatch, tmp_path):
    root = tmp_path / "stack"
    root.mkdir()
    (root / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    (root / "config.json").write_text("APROBADO", encoding="utf-8")
    document = playground_document(root)
    monkeypatch.setattr(descriptors.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(document)))
    configured = configure(setup, "playground", {"path": str(root), "level": "basic"})
    return (*configured, root)


def test_opencanary_no_usa_tag_ni_borrador_editado(setup, docker):
    operation, service, executor, plan = configure(setup, "opencanary", {"services": {"ssh": {"enabled": True, "port": 2222}}})
    original_digest = plan["digest"]
    docker.references["thinkst/opencanary"] = OTHER_IMAGE
    operation.plugins[0].config["services"] = {"http": {"enabled": True, "port": 8000}}
    service.operations.save(operation)
    proxy(executor, operation).deploy()
    container = next(iter(docker.containers.objects.values()))
    assert container.attrs["Image"] == IMAGE
    assert container.kwargs["ports"] == {"2222/tcp": 2222}
    assert service.ledger.record(operation.id, plan["id"])["digest"] == original_digest


def test_opencanary_reinicio_y_retiro_por_id_de_recibo(setup, docker):
    operation, service, executor, _ = configure(setup, "opencanary")
    proxy(executor, operation).deploy()
    container = next(iter(docker.containers.objects.values()))
    proxy(executor, operation).rotate()
    assert container.calls == ["start", "restart"]
    state = service.ledger.operation(operation.id)
    service.ledger.stop(operation.id, target="paused", expected_revision=state["revision"], reason="Freno", actor="admin")
    proxy(executor, operation).retire()
    assert not docker.containers.objects
    assert executor.status(operation.id)["reserved_modifications"] == 3


@pytest.mark.parametrize("mismatch", ["daemon", "owner", "image"])
def test_docker_cambio_de_identidad_no_modifica_recurso(setup, docker, mismatch):
    operation, _, executor, _ = configure(setup, "opencanary")
    proxy(executor, operation).deploy()
    container = next(iter(docker.containers.objects.values()))
    if mismatch == "daemon":
        docker.daemon = "daemon-B"
    elif mismatch == "owner":
        container.attrs["Config"]["Labels"]["apate.operation"] = "otra"
    else:
        container.attrs["Image"] = OTHER_IMAGE
    with pytest.raises(LedgerError, match="mismatch"):
        proxy(executor, operation).retire()
    assert container.calls == ["start"]
    assert executor.status(operation.id)["pending"]


def test_contenedor_reemplazado_con_mismo_nombre_permanece_intacto(setup, docker):
    operation, _, executor, _ = configure(setup, "opencanary")
    proxy(executor, operation).deploy()
    old = next(iter(docker.containers.objects.values()))
    old.remove()
    replacement = docker.containers.create(IMAGE, name=old.name, labels={})
    proxy(executor, operation).retire()
    assert replacement.id in docker.containers.objects and replacement.calls == []


def test_fallo_parcial_conserva_recurso_y_cleanup_no_repite_deploy(setup, docker):
    operation, _, executor, _ = configure(setup, "opencanary")
    docker.fail_start = True
    with pytest.raises(TimeoutError):
        proxy(executor, operation).deploy()
    pending = executor.status(operation.id)["pending"][0]
    receipts = [r for r in executor.ledger.history(operation.id) if r["kind"] == "receipt"]
    assert receipts[-1]["payload"]["outcome"] == "unknown"
    assert receipts[-1]["payload"]["adapter_state"]["config"]["_managed_resources"]
    executor.abandon(operation.id, pending["command_id"], reason="Conciliación y retiro explícito")
    docker.fail_start = False
    proxy(executor, operation).retire()
    assert not docker.containers.objects


def test_error_de_consulta_docker_no_es_ausencia(setup, docker, monkeypatch):
    operation, _, executor, _ = configure(setup, "opencanary")
    proxy(executor, operation).deploy()
    monkeypatch.setattr(docker.containers, "get", lambda _: (_ for _ in ()).throw(ConnectionError("No responde")))
    with pytest.raises(ConnectionError):
        proxy(executor, operation).retire()
    assert len(docker.containers.objects) == 1


def test_dolost_aislamiento_sin_limpieza_global(setup, docker):
    operation, service, executor, _ = configure(setup, "dolost", decoy_config())
    proxy(executor, operation).deploy()
    original = set(docker.containers.objects)
    other = copy.deepcopy(operation)
    other.id = "otra-operacion"
    service.operations.save(other)
    inventory = service.prepare_adoption(other.id)
    service.adopt(other.id, actor="admin", quiescence={"inventory_digest": inventory["digest"],
        "workers_quiescent": True, "legacy_authority_disabled": True, "reason": "Sin ejecutores externos en este ensayo con dobles."})
    activate(service, other.id, execution_policy=policy(other.id, limit=30))
    proxy(executor, other).deploy()
    second = set(docker.containers.objects) - original
    second_networks = {identifier for identifier, n in docker.networks.objects.items() if n.attrs["Labels"]["apate.operation"] == other.id}
    proxy(executor, operation).retire()
    assert set(docker.containers.objects) == second
    assert set(docker.networks.objects) == second_networks


def test_dolost_subacciones_solo_sobre_decoy_aprobado(setup, docker):
    operation, _, executor, _ = configure(setup, "dolost", decoy_config())
    proxy(executor, operation).deploy()
    plugin = proxy(executor, operation)
    plugin.execute_managed("retire", parameters={"hostname": "server", "subaction": "stop"})
    decoy = next(c for c in docker.containers.objects.values() if c.attrs["Config"]["Labels"]["apate.resource"] == "decoy:server")
    assert decoy.status == "stopped"
    proxy(executor, operation).execute_managed("rotate", parameters={"hostname": "server", "subaction": "start"})
    assert decoy.status == "running"
    with pytest.raises(LedgerError, match="admission_adapter_parameters"):
        proxy(executor, operation).execute_managed("retire", parameters={"hostname": "otro", "subaction": "stop"})
    assert decoy.status == "running"


def test_buda_lote_congelado_y_reserva_por_comando(setup, monkeypatch):
    operation, service, executor = setup
    snapshot = buda_snapshot()
    service.buda_snapshotter = lambda _: copy.deepcopy(snapshot)
    monkeypatch.setattr(BudaAdapter, "after", lambda *a: None)
    calls = []
    monkeypatch.setattr("apate.ledger.buda_adapter.execute_step", lambda step: calls.append(copy.deepcopy(step)))
    configure(setup, "buda", {"narrative_id": 1})
    plugin = proxy(executor, operation)
    plugin.deploy()
    snapshot["steps"][0]["server"] = "host-editado"
    snapshot["steps"][0]["command"] = "COMANDO EDITADO"
    plugin.adapter.run_batch(plugin.plugin.config["_execution_session"])
    assert [s["command"] for s in calls] == ["Get-Date", "Get-Process"]
    assert all(s["server"] == "https://host-A:5986" for s in calls)
    assert executor.status(operation.id)["reserved_modifications"] == 3
    commands = [r for r in service.ledger.history(operation.id) if r["kind"] == "command"]
    assert commands[-1]["actor"] == "system:buda"


def test_buda_parada_entre_pasos_impide_siguiente_winrm(setup, monkeypatch):
    operation, service, executor = setup
    service.buda_snapshotter = lambda _: buda_snapshot()
    monkeypatch.setattr(BudaAdapter, "after", lambda *a: None)
    calls = []
    def remote(step):
        calls.append(step["command"])
        state = service.ledger.operation(operation.id)
        service.ledger.stop(operation.id, target="paused", expected_revision=state["revision"], reason="Freno durante llamada", actor="admin")
    monkeypatch.setattr("apate.ledger.buda_adapter.execute_step", remote)
    configure(setup, "buda", {"narrative_id": 1})
    plugin = proxy(executor, operation)
    plugin.deploy()
    plugin.adapter.run_batch(plugin.plugin.config["_execution_session"])
    assert calls == ["Get-Date"]
    proxy(executor, operation).retire()
    assert proxy(executor, operation).effective_state.value == "retired"


def test_buda_lote_anterior_no_sigue_tras_rotate(setup, monkeypatch):
    operation, service, executor = setup
    service.buda_snapshotter = lambda _: buda_snapshot()
    monkeypatch.setattr(BudaAdapter, "after", lambda *a: None)
    calls = []
    monkeypatch.setattr("apate.ledger.buda_adapter.execute_step", lambda step: calls.append(step))
    configure(setup, "buda", {"narrative_id": 1})
    old = proxy(executor, operation)
    old.deploy()
    session = old.plugin.config["_execution_session"]
    proxy(executor, operation).rotate()
    old.adapter.run_batch(session)
    assert calls == []


def test_playground_no_relee_archivos_y_retiro_aislado(setup, docker, monkeypatch, tmp_path):
    operation, service, executor, plan, root = playground(setup, docker, monkeypatch, tmp_path)
    (root / "config.json").write_text("EDITADO", encoding="utf-8")
    plugin = proxy(executor, operation)
    plugin.deploy()
    frontend = next(c for c in docker.containers.objects.values() if c.attrs["Config"]["Labels"]["apate.resource"] == "service:frontend")
    materialized = next(iter(frontend.kwargs["volumes"]))
    from pathlib import Path
    assert Path(materialized).read_text(encoding="utf-8") == "APROBADO"
    proxy(executor, operation).execute_managed("rotate", parameters={"subaction": "attacker"})
    attacker = next(c for c in docker.containers.objects.values() if c.attrs["Config"]["Labels"]["apate.resource"] == "service:attacker")
    assert docker.executions[0][0] == attacker.id
    proxy(executor, operation).retire()
    assert not docker.containers.objects and not docker.networks.objects
    assert docker.volumes.objects  # Retención declarada, no borrado implícito.


@pytest.mark.parametrize("kind", ["opencanary", "dolost"])
def test_http_adaptador_aprobado_pasa_por_k1_k2(app, client, tmp_path, docker, kind):
    operation, _, service = web_operation(app, client, tmp_path)
    operation.plugins = [PluginBinding("cap", "network", plugin_kind=kind, config=decoy_config() if kind == "dolost" else {})]
    service.operations.save(operation)
    activate(service, operation.id, execution_policy=policy(operation.id, limit=30))
    response = client.post(f"/operations/{operation.id}/plugins/cap/{kind}/deploy", headers={"Accept": "application/json"})
    assert response.status_code == 200
    assert docker.containers.objects
    executor = app.config["OPERATION_EXECUTOR"]
    assert executor.status(operation.id)["reserved_modifications"] == 1
    state = service.ledger.operation(operation.id)
    service.ledger.stop(operation.id, target="paused", expected_revision=state["revision"], reason="Freno", actor="admin")
    assert client.post(f"/operations/{operation.id}/plugins/cap/{kind}/rotate").status_code == 409
    assert client.post(f"/operations/{operation.id}/plugins/cap/{kind}/retire", headers={"Accept": "application/json"}).status_code == 200
    assert not docker.containers.objects


@pytest.mark.parametrize("change", ["paused", "identity_revoked"])
def test_playground_worker_revalida_antes_de_efecto(app, client, tmp_path, docker, monkeypatch, change):
    operation, _, service = web_operation(app, client, tmp_path)
    root = tmp_path / "stack-http"
    root.mkdir()
    (root / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    (root / "config.json").write_text("APROBADO", encoding="utf-8")
    monkeypatch.setattr(descriptors.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(playground_document(root))))
    operation.plugins = [PluginBinding("lab", "laboratory", plugin_kind="playground", config={"path": str(root), "level": "basic"})]
    service.operations.save(operation)
    activate(service, operation.id, execution_policy=policy(operation.id, limit=30))
    headers = {"Accept": "application/json"}
    assert client.post(f"/playground/{operation.id}/start", data={"level": "complete"}, headers=headers).status_code == 409
    assert not docker.containers.objects
    assert client.post(f"/playground/{operation.id}/start", data={"level": "basic"}, headers=headers).status_code == 200
    tasks = []
    monkeypatch.setattr(app.extensions["socketio"], "start_background_task", lambda task: tasks.append(task))
    response = client.post(f"/playground/{operation.id}/attacker/run", headers=headers)
    assert response.status_code == 202
    if change == "paused":
        state = service.ledger.operation(operation.id)
        service.ledger.stop(operation.id, target="paused", expected_revision=state["revision"], reason="Freno", actor="admin")
    else:
        with client.session_transaction() as session:
            identity_id = session["identity_id"]
        provider = app.config["IDENTITY_PROVIDER"]
        provider.change_password(identity_id, "Clave-nueva-de-prueba")
    tasks[0]()
    assert docker.executions == []


def test_playground_worker_ejecuta_script_congelado(app, client, tmp_path, docker, monkeypatch):
    operation, _, service = web_operation(app, client, tmp_path)
    root = tmp_path / "stack-worker"
    root.mkdir()
    (root / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    (root / "config.json").write_text("APROBADO", encoding="utf-8")
    monkeypatch.setattr(descriptors.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(playground_document(root))))
    operation.plugins = [PluginBinding("lab", "laboratory", plugin_kind="playground", config={"path": str(root), "level": "basic"})]
    service.operations.save(operation)
    plan = activate(service, operation.id, execution_policy=policy(operation.id, limit=30))
    headers = {"Accept": "application/json"}
    assert client.post(f"/playground/{operation.id}/start", data={"level": "basic"}, headers=headers).status_code == 200
    tasks = []
    monkeypatch.setattr(app.extensions["socketio"], "start_background_task", lambda task: tasks.append(task))
    assert client.post(f"/playground/{operation.id}/attacker/run", headers=headers).status_code == 202
    operation.plugins[0].config["path"] = "ruta-editada"
    service.operations.save(operation)
    tasks[0]()
    assert len(docker.executions) == 1
    assert "attack_scripts/main_attacker.py" in docker.executions[0][1][-1]
    assert app.config["OPERATION_EXECUTOR"].status(operation.id)["pending"] == []


def test_buda_fuente_sql_y_credenciales_congeladas_cifradas(setup, mounted_app, monkeypatch):
    from BUDA.app import db
    from BUDA.models import Activity, Narrative, UserProfile
    operation, service, executor = setup
    monkeypatch.setattr(BudaAdapter, "after", lambda *a: None)
    with mounted_app.app_context():
        activity = Activity(activity_type="actividad")
        activity.set_approved_commands(["Get-Date"])
        profile = UserProfile(name="perfil", role="usuario", behavior_pattern="patrón", winrm_server="host-aprobado",
            winrm_username="usuario-aprobado", winrm_password="clave-aprobada")
        profile.activities.append(activity)
        narrative = Narrative(title="Narrativa", objective="Objetivo", end_date=date.today() + timedelta(days=1), is_running=False)
        narrative.user_profiles.append(profile)
        db.session.add(narrative)
        db.session.commit()
        configure(setup, "buda", {"narrative_id": narrative.id})
        profile.winrm_server = "host-editado"
        profile.winrm_password = "clave-editada"
        activity.set_approved_commands(["COMANDO EDITADO"])
        db.session.commit()
    calls = []
    monkeypatch.setattr("apate.ledger.buda_adapter.execute_step", lambda step: calls.append(copy.deepcopy(step)))
    plugin = proxy(executor, operation)
    plugin.deploy()
    plugin.adapter.run_batch(plugin.plugin.config["_execution_session"])
    assert [(s["server"], s["password"], s["command"]) for s in calls] == [("host-aprobado", "clave-aprobada", "Get-Date")]
    assert b"clave-aprobada" not in executor.ledger.path.read_bytes()


def test_buda_sin_autonomia_no_reserva_ni_inicia_worker(setup, monkeypatch):
    operation, service, executor = setup
    service.buda_snapshotter = lambda _: buda_snapshot()
    operation.plugins = [PluginBinding("cap", "identity", plugin_kind="buda", config={"narrative_id": 1})]
    service.operations.save(operation)
    activate(service, operation.id, execution_policy=policy(operation.id, limit=10, autonomous=False))
    with pytest.raises(LedgerError, match="admission_worker_autonomy"):
        proxy(executor, operation).deploy()
    assert executor.status(operation.id)["reserved_modifications"] == 0


def test_buda_error_remoto_no_repite_lote_y_reintento_conserva_orden(setup, monkeypatch):
    operation, service, executor = setup
    service.buda_snapshotter = lambda _: buda_snapshot()
    monkeypatch.setattr(BudaAdapter, "after", lambda *a: None)
    calls = []
    def failed(step):
        calls.append(step["command"])
        raise TimeoutError("Efecto desconocido")
    monkeypatch.setattr("apate.ledger.buda_adapter.execute_step", failed)
    configure(setup, "buda", {"narrative_id": 1})
    plugin = proxy(executor, operation)
    plugin.deploy()
    session = plugin.plugin.config["_execution_session"]
    plugin.adapter.run_batch(session)
    pending = executor.status(operation.id)["pending"][0]["command_id"]
    with pytest.raises(LedgerError, match="reconciliation_required"):
        proxy(executor, operation).retry_command(pending, reason="Sin conciliar")
    executor.reconcile_failed(operation.id, pending, reason="Transporte detenido y recurso conciliado", executor_quiescent=True)
    monkeypatch.setattr("apate.ledger.buda_adapter.execute_step", lambda step: calls.append(step["command"]))
    proxy(executor, operation).retry_command(pending, reason="Reintento explícito")
    assert calls == ["Get-Date", "Get-Date"]
    assert executor.status(operation.id)["reserved_modifications"] == 2
    assert executor.status(operation.id)["pending"] == []


def test_panel_adoptado_lee_recurso_aprobado_sin_nombres_globales(app, client, tmp_path, docker):
    operation, _, service = web_operation(app, client, tmp_path)
    operation.plugins = [PluginBinding("cap", "network", plugin_kind="opencanary", config={"services": {"ssh": {"enabled": True, "port": 2222}}})]
    service.operations.save(operation)
    activate(service, operation.id, execution_policy=policy(operation.id, limit=30))
    client.post(f"/operations/{operation.id}/plugins/cap/opencanary/deploy")
    operation.plugins[0].config["services"] = {"http": {"enabled": True, "port": 8000}}
    service.operations.save(operation)
    from apate.web._managed_panels import managed_panel
    with client.session_transaction() as authenticated:
        identity_session = dict(authenticated)
    with app.test_request_context():
        from flask import session
        session.update(identity_session)
        panel = managed_panel(operation.plugins[0], operation.id)
    assert panel["deployed"] is True and set(panel["services"]) == {"ssh"}


def test_playground_perfil_no_inicia_servicio_de_otro_nivel(setup, docker, monkeypatch, tmp_path):
    operation, service, executor, _, root = playground(setup, docker, monkeypatch, tmp_path)
    # Revisar con un servicio exclusivo de impossible, cuya imagen ni existe.
    document = playground_document(root)
    document["services"]["exclusivo"] = {"profiles": ["impossible"], "image": "imagen-no-preparada"}
    monkeypatch.setattr(descriptors.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=json.dumps(document)))
    old = executor.ledger.operation(operation.id)["active_plan_id"]
    activate(service, operation.id, parent=old, execution_policy=policy(operation.id, limit=30))
    proxy(executor, operation).deploy()
    assert {c.attrs["Config"]["Labels"]["apate.resource"] for c in docker.containers.objects.values()} == {"service:frontend", "service:attacker"}


def test_buda_worker_real_termina_lote_finito(setup, monkeypatch):
    operation, service, executor = setup
    service.buda_snapshotter = lambda _: buda_snapshot()
    calls = []
    monkeypatch.setattr("apate.ledger.buda_adapter.execute_step", lambda step: calls.append(step["command"]))
    configure(setup, "buda", {"narrative_id": 1})
    plugin = proxy(executor, operation)
    plugin.deploy()
    plugin.adapter.worker.join(timeout=5)
    assert not plugin.adapter.worker.is_alive()
    assert calls == ["Get-Date", "Get-Process"]
    assert executor.status(operation.id)["pending"] == []


def test_buda_presupuesto_impide_segundo_efecto_remoto(setup, monkeypatch):
    operation, service, executor = setup
    service.buda_snapshotter = lambda _: buda_snapshot()
    monkeypatch.setattr(BudaAdapter, "after", lambda *a: None)
    calls = []
    monkeypatch.setattr("apate.ledger.buda_adapter.execute_step", lambda step: calls.append(step["command"]))
    configure(setup, "buda", {"narrative_id": 1}, limit=2)
    plugin = proxy(executor, operation)
    plugin.deploy()
    plugin.adapter.run_batch(plugin.plugin.config["_execution_session"])
    assert calls == ["Get-Date"]
    assert executor.status(operation.id)["reserved_modifications"] == 2
    assert service.ledger.history(operation.id)[-1]["payload"]["reason"] == "budget"


def test_dolost_verifica_lote_completo_antes_de_retirar(setup, docker):
    operation, _, executor, _ = configure(setup, "dolost", decoy_config())
    proxy(executor, operation).deploy()
    collector = next(c for c in docker.containers.objects.values() if c.attrs["Config"]["Labels"]["apate.resource"] == "collector")
    collector.attrs["Config"]["Labels"]["apate.operation"] = "otro"
    with pytest.raises(LedgerError, match="resource_ownership_mismatch"):
        proxy(executor, operation).retire()
    assert all(c.calls == ["start"] for c in docker.containers.objects.values())


def test_playground_material_congelado_alterado_no_ejecuta_atacante(setup, docker, monkeypatch, tmp_path):
    operation, _, executor, _, _ = playground(setup, docker, monkeypatch, tmp_path)
    plugin = proxy(executor, operation)
    plugin.deploy()
    root = executor.ledger.path.parent / "execution_resources" / plugin.adapter.namespace
    (root / "config.json").write_text("ALTERADO", encoding="utf-8")
    with pytest.raises(LedgerError, match="materialized_snapshot_changed"):
        proxy(executor, operation).execute_managed("rotate", parameters={"subaction": "attacker"})
    assert docker.executions == []


def test_opencanary_imagen_revisada_no_se_sustituye_en_nueva_version(setup, docker):
    operation, service, executor, old = configure(setup, "opencanary")
    proxy(executor, operation).deploy()
    docker.references["thinkst/opencanary"] = OTHER_IMAGE
    activate(service, operation.id, parent=old["id"], execution_policy=policy(operation.id, limit=30))
    with pytest.raises(LedgerError, match="recorded_deployment_required"):
        proxy(executor, operation).rotate()
    assert all(c.calls == ["start"] for c in docker.containers.objects.values())


def test_sdk_docker_conserva_ipam_y_endpoints_del_plan(setup, docker):
    operation, _, executor, _ = configure(setup, "dolost", decoy_config())
    proxy(executor, operation).deploy()
    decoy = next(c for c in docker.containers.objects.values() if c.attrs["Config"]["Labels"]["apate.resource"] == "decoy:server")
    endpoints = decoy.engine_config["networking_config"]["EndpointsConfig"]
    assert len(endpoints) == 1
    assert next(iter(endpoints.values()))["IPAMConfig"]["IPv4Address"] == "192.0.2.10"
