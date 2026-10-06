"""Confirma que la vendorizacion de DOLOS-T/BUDA (correccion de
empaquetado post-M14, ver docs/roadmap.md) funciona de verdad: `DOLOST`
y `BUDA` tienen que resolver como codigo fuente dentro de `src/` de
este mismo repo, no como un paquete instalado aparte (editable o no) en
el `site-packages` del entorno -- la version anterior de este test
(implicita, nunca escrita) hubiera sido "que `import DOLOST`/
`import BUDA` no fallen", que seguiria pasando igual con las
instalaciones editables viejas y no hubiera detectado una regresion de
la vendorizacion en si. Este test especifico es la forma concreta de
notar en el futuro si alguien rompe la vendorizacion sin darse cuenta
(ej. reinstalando accidentalmente `dolost`/`BUDA` desde otro lado, o
borrando `src/DOLOST`/`src/BUDA` sin querer)."""

from pathlib import Path

import BUDA
import DOLOST

_REPO_ROOT = Path(__file__).resolve().parent.parent


def test_dolost_resolves_from_this_repos_src_directory():
    dolost_path = Path(DOLOST.__file__).resolve()
    assert dolost_path.is_relative_to(_REPO_ROOT / "src" / "DOLOST")


def test_buda_resolves_from_this_repos_src_directory():
    buda_path = Path(BUDA.__file__).resolve()
    assert buda_path.is_relative_to(_REPO_ROOT / "src" / "BUDA")


def test_dolost_is_not_installed_as_a_separate_site_packages_distribution():
    # Si alguien todavia tuviera un `pip install -e ../DOLOS-T` viejo
    # activo en el mismo entorno, __file__ apuntaria a ese checkout
    # hermano en vez de a src/DOLOST/ de este repo -- confirmamos la
    # ruta absoluta, no solo que el import funcione.
    dolost_path = Path(DOLOST.__file__).resolve()
    assert "site-packages" not in dolost_path.parts


def test_buda_is_not_installed_as_a_separate_site_packages_distribution():
    buda_path = Path(BUDA.__file__).resolve()
    assert "site-packages" not in buda_path.parts


def test_dolost_and_buda_license_files_are_vendored_alongside_the_code():
    assert (_REPO_ROOT / "src" / "DOLOST" / "LICENSE").is_file()
    assert (_REPO_ROOT / "src" / "BUDA" / "LICENSE").is_file()


def test_playground_stack_is_vendored_with_its_license():
    assert (_REPO_ROOT / "playground-stack" / "docker-compose.yml").is_file()
    assert (_REPO_ROOT / "playground-stack" / "LICENSE").is_file()


def test_playground_config_defaults_to_the_vendored_stack_without_the_env_var(monkeypatch):
    from apate.playground.config import VENDORED_PLAYGROUND_PATH, PlaygroundConfig

    monkeypatch.delenv("APATE_PLAYGROUND_PATH", raising=False)
    config = PlaygroundConfig.from_env()

    assert config.path == VENDORED_PLAYGROUND_PATH
    assert config.path == _REPO_ROOT / "playground-stack"
