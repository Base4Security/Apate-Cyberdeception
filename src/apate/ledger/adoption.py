"""Cerco durable de admisión heredada; nunca deduce quiescencia por antigüedad."""

from contextlib import contextmanager
import sqlite3
import uuid
import os

from .repository import LedgerError, canonical, digest, now, text_required


class AdoptionGate:
    def __init__(self, path):
        self.path = path
        with self._connection() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS gates (operation_id TEXT PRIMARY KEY, state TEXT NOT NULL, report TEXT)")
            connection.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, operation_id TEXT NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL, actor TEXT NOT NULL, started_at TEXT NOT NULL, ended_at TEXT, reason TEXT)")
            if "owner_pid" not in {row[1] for row in connection.execute("PRAGMA table_info(jobs)")}:
                connection.execute("ALTER TABLE jobs ADD COLUMN owner_pid INTEGER")

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def enter(self, operation_id, *, kind, actor):
        identifier = str(uuid.uuid4())
        with self._connection() as connection:
            gate = connection.execute("SELECT state FROM gates WHERE operation_id=?", (operation_id,)).fetchone()
            if gate and gate[0] != "legacy":
                raise LedgerError("legacy_admission_fenced")
            connection.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,NULL,NULL,?)",
                (identifier, operation_id, kind, "running", actor, now(), os.getpid()))
        return identifier

    def finish(self, identifier, *, unknown=False):
        with self._connection() as connection:
            connection.execute("UPDATE jobs SET state=?,ended_at=? WHERE id=? AND state='running'",
                ("unknown" if unknown else "finished", now(), identifier))

    def fence(self, operation_id, inventory):
        with self._connection() as connection:
            connection.execute("INSERT INTO gates VALUES (?,'fencing',NULL) ON CONFLICT(operation_id) DO NOTHING", (operation_id,))
            connection.execute("UPDATE gates SET state='fencing' WHERE operation_id=? AND state='legacy'", (operation_id,))
            jobs = [dict(row) for row in connection.execute("SELECT * FROM jobs WHERE operation_id=? AND state IN ('running','unknown') ORDER BY id", (operation_id,))]
            report = {"operation_id": operation_id, "jobs": jobs, "inventory": inventory,
                "scope": "APATE_admission_not_external_process_discovery"}
            connection.execute("UPDATE gates SET report=? WHERE operation_id=?", (canonical(report), operation_id))
        return {**report, "digest": digest(report)}

    def complete(self, operation_id, report, attestation, actor):
        """Exige revisión exacta; trabajos running siempre bloquean la adopción."""
        with self._connection() as connection:
            row = connection.execute("SELECT report FROM gates WHERE operation_id=?", (operation_id,)).fetchone()
            if not row or row[0] != canonical({k: v for k, v in report.items() if k != "digest"}):
                raise LedgerError("stale_adoption_inventory")
            current = [dict(row) for row in connection.execute("SELECT * FROM jobs WHERE operation_id=? AND state IN ('running','unknown') ORDER BY id", (operation_id,))]
            if current != report["jobs"]:
                raise LedgerError("stale_adoption_inventory")
            if any(job["state"] == "running" for job in current):
                raise LedgerError("legacy_work_in_flight")
            required = bool(current or report["inventory"]["external_executors"])
            if required:
                if not isinstance(attestation, dict) or attestation.get("inventory_digest") != report["digest"] or attestation.get("workers_quiescent") is not True or attestation.get("legacy_authority_disabled") is not True:
                    raise LedgerError("explicit_legacy_quiescence_required")
                text_required(attestation.get("reason"))
            return {"inventory": report, "attestation": attestation if required else None,
                "actor": actor, "basis": "administrator_attestation" if required else "no_registered_external_executor",
                "external_verification": "not_established"}

    def adopted(self, operation_id):
        with self._connection() as connection:
            connection.execute("UPDATE gates SET state='adopted' WHERE operation_id=?", (operation_id,))

    def reconcile(self, operation_id, job_id, *, actor, reason, workers_quiescent, legacy_authority_disabled):
        text_required(reason)
        if workers_quiescent is not True or legacy_authority_disabled is not True:
            raise LedgerError("explicit_legacy_quiescence_required")
        with self._connection() as connection:
            job = connection.execute("SELECT * FROM jobs WHERE operation_id=? AND id=?", (operation_id, job_id)).fetchone()
            if not job or job["state"] not in {"running", "unknown"}:
                raise LedgerError("legacy_job_not_pending")
            if job["state"] == "running" and process_alive(job["owner_pid"]):
                raise LedgerError("legacy_local_executor_still_alive")
            connection.execute("UPDATE jobs SET state='quiescent',ended_at=?,reason=? WHERE id=?",
                (now(), canonical({"actor": actor, "reason": reason, "basis": "administrator_attestation"}), job_id))


def process_alive(pid):
    """PID vivo bloquea conservadoramente; nunca se mata un proceso para probarlo."""
    if pid is None:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return ctypes.get_last_error() != 87
        try:
            code = wintypes.DWORD()
            return not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
