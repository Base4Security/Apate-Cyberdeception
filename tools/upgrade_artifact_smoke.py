"""Ensaya actualización y rollback desde dos wheels, sin red ni deploy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import tempfile
import venv


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _data_fingerprints(root: Path) -> dict[str, str]:
    """Compara los archivos persistentes; ignora journals efímeros."""

    transient = (".db-wal", ".db-shm", ".db-journal", ".lock", ".tmp")
    return {path.relative_to(root).as_posix(): _digest(path)
            for path in sorted(root.rglob("*"))
            if path.is_file() and not path.name.endswith(transient)}


def _python(directory: Path) -> Path:
    return directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _run(python: Path, *arguments: str, cwd: Path) -> None:
    """Ejecuta una fase sin shell ni conexiones iniciadas por este programa."""

    environment = os.environ.copy()
    inherited = [str(Path(entry).resolve()) for entry in environment.get("PYTHONPATH", "").split(os.pathsep) if entry]
    # La wheel del entorno hijo debe preceder a las dependencias heredadas.
    # El runner también tiene APATE instalado para otros chequeos de CI.
    directory = python.parent.parent
    child_site = (directory / "Lib" / "site-packages" if os.name == "nt" else
                  directory / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages")
    inherited.append(str(Path(sysconfig.get_paths()["purelib"]).resolve()))
    environment["PYTHONPATH"] = os.pathsep.join([str(child_site), *inherited])
    result = subprocess.run([str(python), *arguments], cwd=cwd, capture_output=True,
                            text=True, check=False, env=environment)
    if result.returncode:
        raise RuntimeError(f"upgrade_step_failed:{arguments[0]}:{result.stderr[-2000:]}")


def exercise(baseline_wheel: Path, candidate_wheel: Path, *, scratch: Path | None = None) -> dict:
    """Usa la copia pre-actualización para volver a la wheel anterior."""

    baseline_wheel = baseline_wheel.resolve(strict=True)
    candidate_wheel = candidate_wheel.resolve(strict=True)
    if baseline_wheel == candidate_wheel or _digest(baseline_wheel) == _digest(candidate_wheel):
        raise ValueError("upgrade_requires_distinct_artifacts")
    if scratch is not None:
        scratch = scratch.resolve()
        scratch.mkdir(parents=True, exist_ok=True)
    probe = Path(__file__).with_name("upgrade_probe.py").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="apate-upgrade-", dir=scratch) as temporary:
        root = Path(temporary)
        baseline_env, candidate_env = root / "baseline-env", root / "candidate-env"
        for directory, wheel in ((baseline_env, baseline_wheel), (candidate_env, candidate_wheel)):
            venv.EnvBuilder(with_pip=True).create(directory)
            _run(_python(directory), "-m", "pip", "install", "--no-index", "--no-deps",
                 "--force-reinstall", str(wheel), cwd=root)
        old, new = _python(baseline_env), _python(candidate_env)
        original, backup, candidate, candidate_backup, restored_candidate, rollback = (
            root / name for name in ("original", "backup", "candidate", "candidate-backup", "candidate-restored", "rollback"))
        fixture = root / "fixture.json"

        def probe_phase(python: Path, phase: str, data: Path) -> None:
            _run(python, str(probe), phase, "--data-dir", str(data), "--fixture", str(fixture), cwd=root)

        def backup_phase(python: Path, command: str, first: Path, second: Path | None = None) -> None:
            arguments = ["-m", "apate.backup", command, str(first)]
            if second is not None:
                arguments.append(str(second))
            _run(python, *arguments, cwd=root)

        probe_phase(old, "prepare", original)
        original_fingerprints = _data_fingerprints(original)
        backup_phase(old, "create", original, backup)
        backup_phase(old, "verify", backup)
        backup_phase(new, "restore", backup, candidate)
        probe_phase(new, "verify", candidate)
        probe_phase(new, "mutate", candidate)
        backup_phase(new, "create", candidate, candidate_backup)
        backup_phase(new, "verify", candidate_backup)
        backup_phase(new, "restore", candidate_backup, restored_candidate)
        probe_phase(new, "verify-mutated", restored_candidate)
        backup_phase(old, "restore", backup, rollback)
        probe_phase(old, "verify", rollback)
        probe_phase(old, "verify", original)
        if _data_fingerprints(original) != original_fingerprints:
            raise RuntimeError("upgrade_original_data_modified")
        return {"format": 1, "baseline_wheel_sha256": _digest(baseline_wheel),
                "candidate_wheel_sha256": _digest(candidate_wheel),
                "upgrade": "ok", "candidate_restore": "ok", "rollback": "ok",
                "original_unchanged": True, "external_services": "not_used"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-wheel", type=Path, required=True)
    parser.add_argument("--candidate-wheel", type=Path, required=True)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = exercise(args.baseline_wheel, args.candidate_wheel, scratch=args.scratch)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
