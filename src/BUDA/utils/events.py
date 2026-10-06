"""
Structured, in-process event accumulation (APATE roadmap milestone M8b --
see docs/roadmap.md and docs/plugin-event-contract.md in the APATE repo for
the schema this feeds into on the consumer side).

utils/narrative_worker.py and utils/orchestrator.py reported simulated
activity with plain print() calls from a background thread, with no
structured, externally consumable form. This module doesn't replace those
prints (kept as-is, for local visibility) but adds a small in-memory queue
alongside them: no new HTTP endpoint, this is meant to be imported directly
and drained in the same process by an external caller (e.g. APATE's BUDA
adapter, M8c).

Thread-safety: narrative_engine() (narrative_worker.py) runs in a
background daemon thread, so every access to the underlying queue goes
through a lock.
"""

from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

# Bounded so a narrative left running indefinitely with nobody draining
# events can't grow this queue without limit -- oldest events are dropped
# first once full, the same trade-off logging.handlers.RotatingFileHandler
# makes for the same reason.
_MAX_QUEUED_EVENTS = 1000

_lock = threading.Lock()
_events: "deque[dict[str, Any]]" = deque(maxlen=_MAX_QUEUED_EVENTS)


def record_event(
    *,
    kind: str,
    detail: str,
    ttp_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    hash_value: Optional[str] = None,
    credential: Optional[str] = None,
    domain: Optional[str] = None,
    url: Optional[str] = None,
    **extra: Any,
) -> dict[str, Any]:
    """
    Builds a structured event dict and appends it to the in-memory queue.
    Follows this key convention (not every key is set on every event, only
    the ones that apply):

      - kind (str): free-form event category, e.g. "narrative_step",
        "winrm_command_executed".
      - detail (str): human-readable description of the step.
      - ttp_id (str | None): MITRE ATT&CK technique id if it applies to
        this kind of event, else None.
      - source_ip / hash / credential / domain / url: only included when
        applicable (see optional_fields below); `hash_value` is the
        parameter name (avoids shadowing the `hash` builtin) but still
        becomes the "hash" key in the resulting dict, to match the
        documented convention.
      - timestamp (str): UTC ISO-8601, always set.

    SECURITY: `credential` exists for interface symmetry with the
    documented key convention, but nothing in this codebase may ever pass
    a real WinRM credential value here -- see the module docstring and
    tests/test_events_no_credential_leak.py, which asserts on this
    directly. It's reserved for a future event kind that legitimately
    captures a *decoy* credential value (bait offered to an attacker),
    which is a fundamentally different thing from this app's own real
    WinRM credentials used to connect to a target host.
    """

    event: dict[str, Any] = {
        "kind": kind,
        "detail": detail,
        "ttp_id": ttp_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    optional_fields = {
        "source_ip": source_ip,
        "hash": hash_value,
        "credential": credential,
        "domain": domain,
        "url": url,
    }
    event.update({key: value for key, value in optional_fields.items() if value is not None})
    event.update(extra)

    with _lock:
        _events.append(event)
    return event


def drain_events(narrative_id: Optional[Any] = None) -> list[dict[str, Any]]:
    """Atomically removes and returns every event currently queued -- the
    intended read path for an external consumer (e.g. APATE, M8c): each
    call returns only what's new since the last drain.

    Si ``narrative_id`` se informa, retira solo los eventos de esa
    narrativa y conserva el resto en el mismo orden. Esto permite que
    APATE atribuya varias narrativas concurrentes a operaciones distintas
    sin que el primer adaptador vacíe la cola global completa.
    """

    with _lock:
        if narrative_id is None:
            drained = list(_events)
            _events.clear()
        else:
            drained = []
            retained = []
            expected = str(narrative_id)
            while _events:
                event = _events.popleft()
                if str(event.get("narrative_id")) == expected:
                    drained.append(event)
                else:
                    retained.append(event)
            _events.extend(retained)
    return drained


def peek_events() -> list[dict[str, Any]]:
    """Returns a snapshot of currently queued events without removing them.
    Useful for a local dashboard or for tests; an external consumer that
    owns reading this queue should use drain_events() instead, to avoid
    re-delivering the same events to multiple readers."""

    with _lock:
        return list(_events)


def clear_events() -> None:
    """Discards every currently queued event without returning them.
    Mainly useful for tests that need a clean slate between cases, since
    the queue is module-level (shared) state."""

    with _lock:
        _events.clear()
