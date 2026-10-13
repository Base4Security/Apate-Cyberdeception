import pytest

from apate.playground.config import ENV_VAR, VENDORED_PLAYGROUND_PATH, PlaygroundConfig
from apate.playground.exceptions import PlaygroundConfigError


def _make_checkout(tmp_path, *, compose_filename="docker-compose.yml"):
    checkout = tmp_path / "cyberdeception-playground"
    checkout.mkdir()
    (checkout / compose_filename).write_text("services: {}\n", encoding="utf-8")
    return checkout


def test_from_path_accepts_directory_with_docker_compose_yml(tmp_path):
    checkout = _make_checkout(tmp_path)

    config = PlaygroundConfig.from_path(checkout)

    assert config.path == checkout


def test_from_path_accepts_docker_compose_yaml_variant(tmp_path):
    checkout = _make_checkout(tmp_path, compose_filename="docker-compose.yaml")

    config = PlaygroundConfig.from_path(checkout)

    assert config.path == checkout


def test_from_path_raises_if_directory_does_not_exist(tmp_path):
    with pytest.raises(PlaygroundConfigError):
        PlaygroundConfig.from_path(tmp_path / "no-existe")


def test_from_path_raises_if_no_compose_file_present(tmp_path):
    checkout = tmp_path / "cyberdeception-playground"
    checkout.mkdir()

    with pytest.raises(PlaygroundConfigError):
        PlaygroundConfig.from_path(checkout)


def test_from_env_defaults_to_vendored_stack_if_env_var_not_set():
    # Correccion post-M14 (vendorizacion, ver docs/roadmap.md): ya no hace
    # falta APATE_PLAYGROUND_PATH para tener un stack usable -- si no esta
    # definida, cae al subconjunto vendorizado en playground-stack/.
    config = PlaygroundConfig.from_env(env={})

    assert config.path == VENDORED_PLAYGROUND_PATH


def test_from_env_reads_configured_path(tmp_path):
    checkout = _make_checkout(tmp_path)

    config = PlaygroundConfig.from_env(env={ENV_VAR: str(checkout)})

    assert config.path == checkout
