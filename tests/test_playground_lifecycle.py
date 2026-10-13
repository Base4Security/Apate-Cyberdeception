import subprocess
from unittest.mock import patch

import pytest

from apate.core.models import DeceptionLevel
from apate.playground import lifecycle
from apate.playground.config import PlaygroundConfig
from apate.playground.exceptions import PlaygroundCommandError


def _make_config(tmp_path) -> PlaygroundConfig:
    checkout = tmp_path / "cyberdeception-playground"
    checkout.mkdir()
    (checkout / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return PlaygroundConfig.from_path(checkout)


def _completed(args, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=args, returncode=0, stdout=stdout, stderr=stderr)


def test_start_stack_invokes_docker_compose_up_with_profile_and_detach(tmp_path):
    config = _make_config(tmp_path)

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["docker", "compose", "up"])
        lifecycle.start_stack(config, DeceptionLevel.COMPLETE)

    args, kwargs = mock_run.call_args
    # --profile va antes del subcomando "up": Docker Compose real de
    # este entorno (v5.3.1) rechaza "up --profile ..." con "unknown
    # flag: --profile" -- confirmado contra Docker real, no solo el mock.
    assert args[0] == ["docker", "compose", "--profile", "complete", "up", "-d"]
    assert kwargs["cwd"] == config.path
    assert kwargs["check"] is True
    # DECEPTION_LEVEL es la variable que docker-compose.yml realmente
    # lee para decidir que contenido cargar (--profile solo decide que
    # contenedores arrancan) -- confirmado que sin esto el stack real
    # queda en "none" pase lo que pase con --profile.
    assert kwargs["env"]["DECEPTION_LEVEL"] == "complete"


def test_start_stack_without_detach_omits_dash_d(tmp_path):
    config = _make_config(tmp_path)

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["docker", "compose", "up"])
        lifecycle.start_stack(config, DeceptionLevel.NONE, detach=False)

    args, _ = mock_run.call_args
    assert args[0] == ["docker", "compose", "--profile", "none", "up"]


def test_stop_stack_invokes_docker_compose_down(tmp_path):
    config = _make_config(tmp_path)

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["docker", "compose", "down"])
        lifecycle.stop_stack(config)

    args, _ = mock_run.call_args
    # Los cuatro DeceptionLevel a la vez: cada servicio del compose real
    # exige un profile explicito (ninguno "siempre activo"), asi que un
    # down sin --profile no matchea nada y no hace nada, en silencio --
    # confirmado contra Docker real. stop_stack() no sabe con que nivel
    # se arranco (la sesion web no lo guarda), asi que cubre los cuatro.
    assert args[0] == [
        "docker",
        "compose",
        "--profile",
        "none",
        "--profile",
        "basic",
        "--profile",
        "complete",
        "--profile",
        "impossible",
        "down",
    ]


def test_run_attacker_script_invokes_docker_exec_interactive_with_main_attacker(tmp_path):
    # docker exec -i, no docker compose exec: attacker-tools se
    # referencia por nombre de contenedor (no por el proyecto de
    # compose), y el -i es obligatorio porque el script real es
    # interactivo y bloquea sin un stdin conectado.
    config = _make_config(tmp_path)
    fake_stdout = "  MITRE ATT&CK  |  T1595.003\n"

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["docker", "exec"], stdout=fake_stdout)
        result = lifecycle.run_attacker_script(config)

    args, kwargs = mock_run.call_args
    assert args[0] == [
        "docker",
        "exec",
        "-i",
        "attacker-tools",
        "python3",
        "attack_scripts/main_attacker.py",
    ]
    assert kwargs["cwd"] == config.path
    assert result.stdout == fake_stdout


def test_run_attacker_script_feeds_stdin_with_enough_continue_confirmations(tmp_path):
    # main_attacker.py tiene 8 fases reales (Fase 6.5 "Lateral Movement"
    # cuenta aparte de la Fase 6 "SSH Brute Force"), cada una bloqueada
    # en ask_continue() esperando una linea por stdin, sin flag para
    # saltarlo: hace falta alimentarle al menos 8 confirmaciones --
    # confirmado corriendo el script real de punta a punta (10x "c\n"
    # alcanzaron, con 2 de margen).
    config = _make_config(tmp_path)

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["docker", "exec"])
        lifecycle.run_attacker_script(config)

    _, kwargs = mock_run.call_args
    assert kwargs["input"].count("c\n") >= 8


def test_run_attacker_script_streaming_emits_each_stdout_line_and_keeps_stdin(tmp_path):
    config = _make_config(tmp_path)

    class FakeProcess:
        def __init__(self):
            from io import StringIO

            self.stdin = StringIO()
            self.stdout = iter(["fase 1\n", "fase 2\n"])
            self.stderr = StringIO("")

        def wait(self):
            return 0

    process = FakeProcess()
    received = []
    with patch("apate.playground.lifecycle.subprocess.Popen", return_value=process):
        result = lifecycle.run_attacker_script_streaming(config, received.append)

    assert received == ["fase 1\n", "fase 2\n"]
    assert result.stdout == "fase 1\nfase 2\n"
    assert process.stdin.closed


def test_run_attacker_script_does_not_accept_arguments(tmp_path):
    # main_attacker.py no tiene argparse: pasarle argumentos no
    # tendria ningun efecto, asi que la funcion no expone esa opcion.
    config = _make_config(tmp_path)

    with pytest.raises(TypeError):
        lifecycle.run_attacker_script(config, "--target", "andesfinance-backend")


def test_command_error_wraps_called_process_error(tmp_path):
    config = _make_config(tmp_path)

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1, cmd=["docker", "compose", "up"], stderr="fallo el compose"
        )
        with pytest.raises(PlaygroundCommandError):
            lifecycle.start_stack(config, DeceptionLevel.BASIC)


def test_command_error_wraps_missing_docker_executable(tmp_path):
    config = _make_config(tmp_path)

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError("docker no encontrado")
        with pytest.raises(PlaygroundCommandError):
            lifecycle.stop_stack(config)


@pytest.mark.parametrize("level", list(DeceptionLevel))
def test_start_stack_maps_every_deception_level_to_a_profile(tmp_path, level):
    config = _make_config(tmp_path)

    with patch("apate.playground.lifecycle.subprocess.run") as mock_run:
        mock_run.return_value = _completed(["docker", "compose", "up"])
        lifecycle.start_stack(config, level)

    args, _ = mock_run.call_args
    assert "--profile" in args[0]
    assert args[0][args[0].index("--profile") + 1] == level.value
