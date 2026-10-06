"""Copia y restauración verificable del directorio persistente de APATE.

Se ejecuta con el servicio detenido: los repositorios JSON no comparten una
transacción global con las bases SQLite. La copia de cada base usa la API de
backup de SQLite, y el manifiesto detecta pérdidas o cambios antes de restaurar.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
from pathlib import Path

from .atomic_write import write_json_atomically
from .schema_version import SCHEMA_VERSION

MANIFEST = "apate-backup-manifest.json"
_TRANSIENT_SUFFIXES = (".tmp", ".lock", ".db-journal", ".db-wal", ".db-shm")


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"No se admite un enlace simbólico en los datos: {path}")
        if path.is_file() and not path.name.endswith(_TRANSIENT_SUFFIXES):
            yield path


def create_backup(data_dir: Path | str, destination: Path | str) -> dict:
    """Crea una copia nueva; nunca sobrescribe otra copia existente."""

    source = Path(data_dir).resolve()
    target = Path(destination).resolve()
    if not source.is_dir():
        raise ValueError(f"No existe el directorio de datos: {source}")
    if target == source or source in target.parents or target in source.parents:
        raise ValueError("La copia y los datos deben estar en directorios separados.")
    custom_db = os.environ.get("APATE_BUDA_DATABASE_URI", "")
    if custom_db and custom_db.startswith("sqlite:///"):
        custom_path = Path(custom_db.removeprefix("sqlite:///"))
        if custom_path.is_absolute() and source not in custom_path.resolve().parents:
            raise ValueError("La base BUDA configurada está fuera de APATE_DATA_DIR; respaldala por separado.")
    target.mkdir(parents=True, exist_ok=False)
    try:
        entries = []
        for path in _files(source):
            relative = path.relative_to(source)
            copy = target / relative
            copy.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix == ".db":
                with sqlite3.connect(path) as origin, sqlite3.connect(copy) as replica:
                    origin.backup(replica)
            else:
                shutil.copy2(path, copy)
            entries.append({"path": relative.as_posix(), "sha256": _hash(copy), "size": copy.stat().st_size})
        manifest = {
            "format": 1,
            "schema_version": SCHEMA_VERSION,
            "external_secret_key_required": bool(os.environ.get("APATE_SECRET_ENCRYPTION_KEY")),
            "files": entries,
        }
        write_json_atomically(target / MANIFEST, manifest)
        verify_backup(target)
        return manifest
    except BaseException:
        shutil.rmtree(target)
        raise


def verify_backup(directory: Path | str) -> dict:
    """Verifica contenido, rutas y las bases SQLite del manifiesto."""

    root = Path(directory).resolve()
    manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    if manifest.get("format") != 1 or not isinstance(manifest.get("files"), list):
        raise ValueError("Formato de copia desconocido.")
    declared = set()
    for entry in manifest["files"]:
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in declared:
            raise ValueError("El manifiesto contiene una ruta inválida o repetida.")
        declared.add(relative.as_posix())
        path = root / relative
        if path.is_symlink() or not path.is_file() or path.stat().st_size != entry["size"] or _hash(path) != entry["sha256"]:
            raise ValueError(f"La copia no coincide con el manifiesto: {relative}")
        if path.suffix == ".db":
            with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True) as connection:
                if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError(f"La base SQLite está dañada: {relative}")
    actual = {path.relative_to(root).as_posix() for path in _files(root) if path.name != MANIFEST}
    if actual != declared:
        raise ValueError("La copia contiene archivos no declarados o incompletos.")
    return manifest


def restore_backup(directory: Path | str, destination: Path | str) -> dict:
    """Restaura solo hacia un destino nuevo o vacío."""

    source = Path(directory).resolve()
    target = Path(destination).resolve()
    manifest = verify_backup(source)
    if manifest["schema_version"] > SCHEMA_VERSION:
        raise ValueError("La copia usa una versión de esquema más nueva.")
    if target == source or source in target.parents or target in source.parents:
        raise ValueError("La copia y los datos deben estar en directorios separados.")
    if target.exists() and any(target.iterdir()):
        raise ValueError("El destino de restauración debe estar vacío.")
    target.mkdir(parents=True, exist_ok=True)
    for entry in manifest["files"]:
        relative = Path(entry["path"])
        output = target / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, output)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Respaldo verificable de APATE (detener el servicio antes de crear o restaurar).")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "restore"):
        command = commands.add_parser(name)
        command.add_argument("source")
        command.add_argument("destination")
    commands.add_parser("verify").add_argument("directory")
    args = parser.parse_args()
    if args.command == "create":
        result = create_backup(args.source, args.destination)
    elif args.command == "restore":
        result = restore_backup(args.source, args.destination)
    else:
        result = verify_backup(args.directory)
    print(f"Copia verificada: {len(result['files'])} archivos.")


if __name__ == "__main__":
    main()
