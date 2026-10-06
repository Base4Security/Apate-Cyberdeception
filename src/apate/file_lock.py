"""Bloqueo exclusivo entre hilos y procesos para repositorios JSON."""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

_guard = threading.Lock()
_thread_locks: dict[Path, threading.RLock] = {}


@contextmanager
def exclusive_file_lock(path: Path | str, *, timeout: float = 30.0) -> Iterator[None]:
    """Serializa una lectura-modificación-escritura en el mismo host."""

    lock_path = Path(path).resolve()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with _guard:
        thread_lock = _thread_locks.setdefault(lock_path, threading.RLock())
    with thread_lock:
        with open(lock_path, "a+b") as lock_file:
            # msvcrt bloquea un byte desde la posición actual.
            lock_file.seek(0)
            if lock_file.read(1) == b"":
                lock_file.write(b"\0")
                lock_file.flush()
            deadline = time.monotonic() + timeout
            while True:
                try:
                    if os.name == "nt":
                        import msvcrt

                        lock_file.seek(0)
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"No se pudo obtener el bloqueo de {lock_path}")
                    time.sleep(0.05)
            try:
                yield
            finally:
                if os.name == "nt":
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
