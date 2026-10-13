"""
Structured event extraction for direct, in-process consumption (M8a of the
APATE roadmap: see docs/roadmap.md and docs/plugin-event-contract.md in the
APATE repository for the PluginEvent schema this feeds into).

This module reads the same "observable" activity logs that ActivityViewer
(services/activity.py) already exposes to the DOLOS-T dashboard, but returns
a list of plain dicts in a normalized event schema instead of building
HTML/JSON strings for a UI widget. There is no new HTTP endpoint here: this
is meant to be imported directly, in the same process, by an external
caller (e.g. APATE's DOLOS-T adapter, M8c) -- APATE already has its own
deployment API to call (blueprints/api.py), all that was missing was a safe,
structured way to read activity back out.

Security note -- this replaces an unsafe pattern, not just avoids adding one:
services/activity.py's review_observable_usage() used to call eval() on a
string built from log content to turn it back into a dict. A honeypot's logs
are, by definition, partially attacker-influenced (that's the point of a
honeypot), so eval()-ing anything derived from them is a remote code
execution risk if an attacker can shape what ends up in a log line. That
eval() has been removed (see the accompanying fix in activity.py, which now
uses ast.literal_eval() -- already the established "safe eval" pattern
elsewhere in this codebase, see services/docker_manager.py's `ast.literal_eval`
use for container port lists). This module follows the same rule: every
field extracted here comes from str.split()/explicit indexing, never
eval()/exec() on anything derived from a log file.
"""

from __future__ import annotations

from typing import Any, Optional

from .docker_manager import DockerManager
from .logger import DolostLogger

logger = DolostLogger.get_instance()
docker_manager = DockerManager.get_instance()

_COLLECTOR_CONTAINER = "DolosT-Collector"
_IPS_LOG_PATH = "/var/log/observables/observable_ips.log"
_USAGE_LOG_PATH = "/var/log/observables/observable_usage.log"
_INTERESTING_LOG_PATH = "/var/log/observables/observable_interesting.log"

# Same exclusion list as ActivityViewer.review_observable_ips() (loopback /
# link-local placeholders that show up in the logs but are never a real
# attacker source).
_EXCLUDED_IPS = {"127.0.0.1", "127.0.0.0", "122.0.0.0", "0.0.0.0", "200.100.0.1"}

# Out of scope on purpose: ActivityViewer.review_logs() tails the raw,
# per-decoy log files under /var/log/decoys/ (free-form text, format depends
# on which decoy produced it). The three "observable_*" logs read here are
# already CSV-structured records that DOLOS-T itself writes out as its own
# activity summary, which is what makes them safe to parse generically with
# str.split(',') and a fixed field count. Extracting structured fields
# (hash/credential/domain/url) out of arbitrary raw decoy log text would
# need a parser per decoy type that doesn't exist in this codebase today --
# building one now would mean guessing a format instead of reading it from
# real, confirmed log output, exactly the kind of mistake this milestone is
# trying to avoid repeating.


def _collector_exists() -> bool:
    # APATE puede arrancar con la integración disponible pero todavía
    # sin un cliente Docker configurado. En ese estado no hay collector
    # que leer: es ausencia de actividad, no un error de extracción.
    if docker_manager.client is None:
        return False
    filters = {"name": [_COLLECTOR_CONTAINER]}
    return bool(docker_manager.client.api.containers(filters=filters))


def _read_log_file(path: str) -> list[str]:
    """Runs `cat <path>` inside the collector container and returns the
    decoded output split into non-empty lines. Only decodes bytes to text
    and splits on line breaks -- never evaluates the content as code."""

    if not _collector_exists():
        return []

    command = f"sh -c 'cat {path}'"
    exec_id = docker_manager.client.api.exec_create(_COLLECTOR_CONTAINER, command, tty=True)

    chunks = [chunk.decode("utf-8", errors="replace") for chunk in docker_manager.client.api.exec_start(exec_id["Id"], stream=True)]
    raw_output = "".join(chunks)

    if "No such file or directory" in raw_output:
        return []

    return [line for line in raw_output.strip().split("\r\n") if line.strip()]


def _parse_csv_record(line: str, field_count: int) -> Optional[list[str]]:
    """Splits a single log line on ',' and returns the fields only if the
    count matches exactly what's expected. Explicit, defensive parsing --
    never eval()/exec() on log content. A line with the wrong number of
    fields is skipped (and logged at debug level) instead of raising: a
    honeypot log is attacker-influenced and shouldn't be able to crash
    event extraction just by being malformed."""

    fields = line.split(",")
    if len(fields) != field_count:
        logger.debug(f"[events] Skipping malformed log line (expected {field_count} fields): {line!r}", ws=False)
        return None
    return [field.strip() for field in fields]


def _events_from_ips_log() -> list[dict[str, Any]]:
    events = []
    for line in _read_log_file(_IPS_LOG_PATH):
        record = _parse_csv_record(line, 3)
        if record is None:
            continue
        timestamp, decoy, ip_address = record
        if ip_address in _EXCLUDED_IPS:
            continue
        events.append(
            {
                "kind": "network_connection",
                "detail": f"Connection observed to decoy '{decoy}' from {ip_address}",
                "ttp_id": None,
                "source_ip": ip_address,
                "decoy": decoy,
                "timestamp": timestamp,
            }
        )
    return events


def _events_from_usage_log() -> list[dict[str, Any]]:
    events = []
    seen: set[tuple[str, str]] = set()
    for line in _read_log_file(_USAGE_LOG_PATH):
        record = _parse_csv_record(line, 2)
        if record is None:
            continue
        usage, decoy = record
        key = (decoy, usage)
        if key in seen:
            continue
        seen.add(key)
        events.append(
            {
                "kind": "decoy_usage",
                "detail": f"Activity '{usage}' recorded on decoy '{decoy}'",
                "ttp_id": None,
                "decoy": decoy,
            }
        )
    return events


def _events_from_interesting_log() -> list[dict[str, Any]]:
    events = []
    for line in _read_log_file(_INTERESTING_LOG_PATH):
        record = _parse_csv_record(line, 3)
        if record is None:
            continue
        timestamp, decoy, interesting_data = record
        events.append(
            {
                "kind": "interesting_observable",
                "detail": interesting_data,
                "ttp_id": None,
                "decoy": decoy,
                "timestamp": timestamp,
            }
        )
    return events


def get_structured_events() -> list[dict[str, Any]]:
    """
    Returns current honeypot activity as a list of structured event dicts,
    safe for direct in-process consumption (no HTTP round-trip needed) --
    e.g. by APATE's DOLOS-T adapter (M8c), which maps each dict onto its own
    event schema (see docs/plugin-event-contract.md in the APATE repo:
    PluginEvent's event_type/payload).

    Each dict follows this key convention -- not every key is present on
    every event, only the ones that apply to that kind of observation:

      - kind (str): free-form event category, e.g. "network_connection",
        "decoy_usage", "interesting_observable".
      - detail (str): human-readable description.
      - ttp_id (str | None): MITRE ATT&CK technique id if it can be
        inferred from the data available here, else None. None for every
        event kind produced today: the three underlying logs (ips/usage/
        interesting) don't carry enough signal on their own to map to a
        specific technique without guessing, so this is left for a future
        milestone rather than fabricated now.
      - source_ip (str, optional): origin IP, when available.
      - hash / credential / domain / url (str, optional): only included
        when applicable to that kind of event. NEVER the real value of a
        captured credential, even if a honeypot happened to capture a real
        one by mistake -- same rule APATE's own HoneytokenPlugin follows
        for its synthetic credentials (see docs/plugin-event-contract.md,
        section 3.4, in the APATE repo). None of the event kinds produced
        here currently populate these keys, since the underlying logs
        don't carry that data; they're part of the contract for future
        event kinds, not unused today.

    Never raises: a missing collector container, a missing log file, or a
    malformed log line all just result in fewer events, not an exception --
    this mirrors the leniency of the pre-existing ActivityViewer methods
    this function is meant to replace for programmatic (non-UI) consumers.
    """

    return [
        *_events_from_ips_log(),
        *_events_from_usage_log(),
        *_events_from_interesting_log(),
    ]
