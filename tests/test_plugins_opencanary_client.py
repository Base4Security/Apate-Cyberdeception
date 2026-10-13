"""Tests para `apate.plugins.opencanary_client` (cliente Docker
autocontenido para OpenCanary). Ver docstring del módulo para el
diseño completo y qué quedó verificado contra un contenedor real (en
una sesión previa, no en esta -- ver docs/roadmap.md)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from apate.plugins.exceptions import OpenCanaryError
from apate.plugins.opencanary_client import (
    OpenCanaryHit,
    build_config,
    container_name,
    container_status,
    deploy_container,
    fetch_logs,
    restart_container,
    stop_and_remove_container,
)


# -- container_name() ----------------------------------------------------


def test_container_name_uses_fixed_convention():
    assert container_name("opencanary-1") == "OpenCanary-opencanary-1"


# -- build_config() -------------------------------------------------------


def test_build_config_flattens_services_with_dotted_keys():
    config = build_config(node_id="node-1", services={"ssh": {"enabled": True, "port": 2222}})

    assert config == {"device.node_id": "node-1", "ssh.enabled": True, "ssh.port": 2222}


def test_build_config_excludes_host_port_apate_only_key():
    config = build_config(node_id="n", services={"ssh": {"enabled": True, "port": 22, "host_port": 2222}})

    assert "ssh.host_port" not in config
    assert config["ssh.port"] == 22


def test_build_config_with_no_services_only_sets_node_id():
    assert build_config(node_id="n", services={}) == {"device.node_id": "n"}


# -- deploy_container() ----------------------------------------------------


def test_deploy_container_creates_injects_config_and_starts():
    client = MagicMock()
    container = MagicMock()
    container.id = "abc123"
    client.containers.create.return_value = container

    with patch("docker.from_env", return_value=client):
        result = deploy_container(name="OpenCanary-x", node_id="node-1", services={"ssh": {"enabled": True, "port": 2222}})

    assert result == "abc123"
    client.containers.create.assert_called_once()
    _, kwargs = client.containers.create.call_args
    assert kwargs["name"] == "OpenCanary-x"
    assert kwargs["ports"] == {"2222/tcp": 2222}
    container.put_archive.assert_called_once()
    put_args = container.put_archive.call_args
    assert put_args.args[0] == "/etc/opencanaryd"
    container.start.assert_called_once()


def test_deploy_container_injected_config_matches_build_config():
    import io
    import tarfile

    client = MagicMock()
    container = MagicMock()
    client.containers.create.return_value = container

    with patch("docker.from_env", return_value=client):
        deploy_container(name="x", node_id="node-1", services={"ssh": {"enabled": True, "port": 2222}})

    archive_bytes = container.put_archive.call_args.args[1]
    with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as tar:
        member = tar.getmember("opencanary.conf")
        content = tar.extractfile(member).read()
    assert json.loads(content) == {"device.node_id": "node-1", "ssh.enabled": True, "ssh.port": 2222}


def test_deploy_container_host_network_mode_skips_port_mapping():
    client = MagicMock()
    container = MagicMock()
    client.containers.create.return_value = container

    with patch("docker.from_env", return_value=client):
        deploy_container(
            name="x", node_id="n", services={"ssh": {"enabled": True, "port": 22}}, network_mode="host"
        )

    _, kwargs = client.containers.create.call_args
    assert kwargs["network_mode"] == "host"
    assert "ports" not in kwargs


def test_deploy_container_port_conflict_raises_opencanary_error():
    client = MagicMock()
    client.containers.create.side_effect = RuntimeError("port is already allocated")

    with patch("docker.from_env", return_value=client):
        with pytest.raises(OpenCanaryError, match="already allocated"):
            deploy_container(name="x", node_id="n", services={"ssh": {"enabled": True, "port": 22}})


def test_deploy_container_docker_unreachable_raises_opencanary_error():
    with patch("docker.from_env", side_effect=RuntimeError("no daemon")):
        with pytest.raises(OpenCanaryError):
            deploy_container(name="x", node_id="n", services={})


# -- restart_container() (rotate) ------------------------------------------


def test_restart_container_calls_docker_restart():
    client = MagicMock()
    container = MagicMock()
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        restart_container(name="OpenCanary-x")

    client.containers.get.assert_called_once_with("OpenCanary-x")
    container.restart.assert_called_once()


def test_restart_container_missing_container_raises():
    client = MagicMock()
    client.containers.get.side_effect = RuntimeError("not found")

    with patch("docker.from_env", return_value=client):
        with pytest.raises(OpenCanaryError):
            restart_container(name="OpenCanary-x")


# -- stop_and_remove_container() (retire) -----------------------------------


def test_stop_and_remove_container_stops_and_removes():
    client = MagicMock()
    container = MagicMock()
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        stop_and_remove_container(name="OpenCanary-x")

    container.stop.assert_called_once()
    container.remove.assert_called_once()


def test_stop_and_remove_container_already_gone_is_not_an_error():
    client = MagicMock()
    client.containers.get.side_effect = RuntimeError("not found")

    with patch("docker.from_env", return_value=client):
        stop_and_remove_container(name="OpenCanary-x")  # no debe lanzar


def test_stop_and_remove_container_propagates_real_failure():
    client = MagicMock()
    container = MagicMock()
    container.stop.side_effect = RuntimeError("daemon caido")
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        with pytest.raises(OpenCanaryError):
            stop_and_remove_container(name="OpenCanary-x")


# -- fetch_logs(): parseo JSON + sanitizacion --------------------------------


_REAL_SSH_LOG_LINE = json.dumps(
    {
        "logtype": 4002,
        "logdata": {"USERNAME": "fakeuser", "PASSWORD": "", "REMOTEVERSION": "SSH-2.0-OpenSSH_8.9"},
        "src_host": "172.17.0.1",
        "src_port": 51390,
        "node_id": "opencanary-1",
        "local_time": "2024-01-01 00:00:00.000000",
    }
)


def test_fetch_logs_parses_real_verified_ssh_log_shape():
    client = MagicMock()
    container = MagicMock()
    container.logs.return_value = (_REAL_SSH_LOG_LINE + "\n").encode("utf-8")
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        hits = fetch_logs(name="OpenCanary-x")

    assert len(hits) == 1
    hit = hits[0]
    assert hit.logtype == 4002
    assert hit.src_host == "172.17.0.1"
    assert hit.src_port == 51390
    assert hit.node_id == "opencanary-1"
    assert hit.logdata["USERNAME"] == "fakeuser"


def test_fetch_logs_passes_since_as_integer_seconds():
    client = MagicMock()
    container = MagicMock()
    container.logs.return_value = b""
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        fetch_logs(name="OpenCanary-x", since=1234.9)

    assert container.logs.call_args.kwargs["since"] == 1234


def test_fetch_logs_skips_non_json_lines():
    client = MagicMock()
    container = MagicMock()
    container.logs.return_value = b"not json\n" + (_REAL_SSH_LOG_LINE + "\n").encode("utf-8") + b"\n"
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        hits = fetch_logs(name="OpenCanary-x")

    assert len(hits) == 1


def test_fetch_logs_skips_non_dict_json_lines():
    client = MagicMock()
    container = MagicMock()
    container.logs.return_value = b"[1, 2, 3]\n"
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        assert fetch_logs(name="OpenCanary-x") == []


def test_fetch_logs_container_not_found_raises():
    client = MagicMock()
    client.containers.get.side_effect = RuntimeError("not found")

    with patch("docker.from_env", return_value=client):
        with pytest.raises(OpenCanaryError):
            fetch_logs(name="OpenCanary-x")


def test_opencanary_hit_sanitizes_long_logdata_values():
    from apate.plugins.opencanary_client import OpenCanaryHit as _Hit

    huge = "A" * 5000
    hit = _Hit.from_raw({"logtype": 1, "logdata": {"COMMAND": huge}, "src_host": "1.2.3.4"})

    assert len(hit.logdata["COMMAND"]) < 5000
    assert "truncado" in hit.logdata["COMMAND"]


# -- container_status(): distingue Docker inalcanzable de no desplegado -----


def test_container_status_running():
    client = MagicMock()
    container = MagicMock()
    container.status = "running"
    client.containers.get.return_value = container

    with patch("docker.from_env", return_value=client):
        status = container_status(name="OpenCanary-x")

    assert status == {"docker_available": True, "status": "running", "up": True}


def test_container_status_not_deployed_but_docker_available():
    client = MagicMock()
    client.containers.get.side_effect = RuntimeError("not found")

    with patch("docker.from_env", return_value=client):
        status = container_status(name="OpenCanary-x")

    assert status["docker_available"] is True
    assert status["up"] is False


def test_container_status_docker_unreachable():
    with patch("docker.from_env", side_effect=RuntimeError("no daemon")):
        status = container_status(name="OpenCanary-x")

    assert status == {"docker_available": False, "status": None, "up": None}
