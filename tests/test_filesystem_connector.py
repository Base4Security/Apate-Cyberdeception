"""El conector no adopta archivos ajenos ni atraviesa la raíz autorizada."""

import pytest

from apate.deployment import (
    DeploymentService, DeploymentStatus, DeploymentTarget,
    FilesystemHoneyfileConnector, JSONFileDeploymentRepository,
)
from apate.deployment.exceptions import DeploymentError


def test_filesystem_honeyfile_lifecycle_on_mounted_root(tmp_path):
    root = tmp_path / "share"
    (root / "finance").mkdir(parents=True)
    target = DeploymentTarget(name="SMB finanzas", connector_kind="filesystem-honeyfile",
                              address=str(root), config={"allowed_subdirs": ["finance"]})
    connector = FilesystemHoneyfileConnector(tmp_path / "receipts")
    service = DeploymentService(repository=JSONFileDeploymentRepository(tmp_path / "deployments"),
                                connectors={connector.kind: connector})
    plan = service.prepare(operation_id="op-1", plugin_id="honeyfile-finanzas", target=target,
                           configuration={"relative_path": "finance/credenciales.txt",
                                          "content": "usuario=demo", "rotation_content": "usuario=demo-rotado"})
    assert not (root / "finance" / "credenciales.txt").exists()
    record = service.execute(plan.id)
    assert record.status is DeploymentStatus.ACTIVE
    assert (root / "finance" / "credenciales.txt").read_text(encoding="utf-8") == "usuario=demo"
    assert service.execute(plan.id).id == record.id
    assert service.refresh(record.id).status is DeploymentStatus.ACTIVE
    service.rotate(record.id)
    assert (root / "finance" / "credenciales.txt").read_text(encoding="utf-8") == "usuario=demo-rotado"
    assert service.retire(record.id).status is DeploymentStatus.RETIRED
    assert not (root / "finance" / "credenciales.txt").exists()


def test_filesystem_connector_rejects_escape_and_unmanaged_file(tmp_path):
    root = tmp_path / "share"
    (root / "finance").mkdir(parents=True)
    target = DeploymentTarget(name="SMB", connector_kind="filesystem-honeyfile", address=str(root),
                              config={"allowed_subdirs": ["finance"]})
    connector = FilesystemHoneyfileConnector(tmp_path / "receipts")
    service = DeploymentService(repository=JSONFileDeploymentRepository(tmp_path / "deployments"),
                                connectors={connector.kind: connector})
    for relative in ("../fuera.txt", "other/archivo.txt"):
        with pytest.raises(DeploymentError):
            service.prepare(operation_id="op-1", plugin_id="file", target=target,
                            configuration={"relative_path": relative, "content": "demo"})
    (root / "finance" / "existing.txt").write_text("dato ajeno", encoding="utf-8")
    with pytest.raises(DeploymentError, match="no se adopta"):
        service.prepare(operation_id="op-1", plugin_id="file", target=target,
                        configuration={"relative_path": "finance/existing.txt", "content": "demo"})


def test_filesystem_connector_rejects_symlinked_allowed_folder(tmp_path):
    root = tmp_path / "share"
    (root / "other").mkdir(parents=True)
    try:
        (root / "finance").symlink_to(root / "other", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("El entorno no permite crear symlinks de directorio.")
    target = DeploymentTarget(name="SMB", connector_kind="filesystem-honeyfile", address=str(root),
                              config={"allowed_subdirs": ["finance"]})
    connector = FilesystemHoneyfileConnector(tmp_path / "receipts")
    with pytest.raises(DeploymentError, match="enlaces simbólicos"):
        connector.validate(target, {"relative_path": "finance/archivo.txt", "content": "demo"})


def test_timeout_tras_recibo_se_reconcilia_sin_duplicar_honeyfile(tmp_path, monkeypatch):
    """Un resultado incierto exige retry explícito y conserva el recurso propio."""

    root = tmp_path / "share"
    root.mkdir()
    target = DeploymentTarget(name="Share ficticio", connector_kind="filesystem-honeyfile",
        address=str(root))
    connector = FilesystemHoneyfileConnector(tmp_path / "receipts")
    service = DeploymentService(repository=JSONFileDeploymentRepository(tmp_path / "deployments"),
        connectors={connector.kind: connector})
    plan = service.prepare(operation_id="op-timeout", plugin_id="honeyfile", target=target,
        configuration={"relative_path": "señuelo.txt", "content": "solo prueba"})
    original = connector._write_receipt
    attempts = 0

    def write_then_timeout(*args):
        nonlocal attempts
        attempts += 1
        original(*args)
        raise TimeoutError("respuesta perdida después del efecto")

    monkeypatch.setattr(connector, "_write_receipt", write_then_timeout)
    with pytest.raises(DeploymentError):
        service.execute(plan.id)
    record = service.repository.find_record_for_plan(plan.id)
    assert record.status is DeploymentStatus.FAILED
    assert (root / "señuelo.txt").read_text(encoding="utf-8") == "solo prueba"
    assert service.execute(plan.id).status is DeploymentStatus.FAILED
    assert attempts == 1

    monkeypatch.setattr(connector, "_write_receipt", original)
    assert service.retry(record.id).status is DeploymentStatus.ACTIVE
    assert (root / "señuelo.txt").read_text(encoding="utf-8") == "solo prueba"
    assert len(list(root.iterdir())) == 1


def test_timeout_sin_recibo_no_adopta_archivo_existente(tmp_path, monkeypatch):
    """Si falta prueba de propiedad, el reintento no sobrescribe el efecto incierto."""

    root = tmp_path / "share"
    root.mkdir()
    target = DeploymentTarget(name="Share ficticio", connector_kind="filesystem-honeyfile",
        address=str(root))
    connector = FilesystemHoneyfileConnector(tmp_path / "receipts")
    service = DeploymentService(repository=JSONFileDeploymentRepository(tmp_path / "deployments"),
        connectors={connector.kind: connector})
    plan = service.prepare(operation_id="op-sin-recibo", plugin_id="honeyfile", target=target,
        configuration={"relative_path": "señuelo.txt", "content": "solo prueba"})
    monkeypatch.setattr(connector, "_write_receipt", lambda *args: (_ for _ in ()).throw(TimeoutError()))
    with pytest.raises(DeploymentError):
        service.execute(plan.id)
    record = service.repository.find_record_for_plan(plan.id)
    with pytest.raises(DeploymentError):
        service.retry(record.id)
    assert record.status is DeploymentStatus.FAILED
    assert (root / "señuelo.txt").read_text(encoding="utf-8") == "solo prueba"
    assert not list((tmp_path / "receipts").glob("*.json"))
