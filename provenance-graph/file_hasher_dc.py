"""
file_hasher_dc.py - tails the Wazuh manager's raw archive
(archives.log) for Sysmon Event ID 1 (process creation) records from
the DC agent, and upserts each one as a Process node (reusing
GraphWriter.upsert_process() unchanged, by building an event dict
shaped exactly like Tetragon's) plus a File node for the process
image's SHA-256/MD5/IMPHASH (GraphWriter.upsert_file_hash()).

Why archives.log and not alerts.json: Sysmon process-creation events
never match any default Wazuh rule, so they never reach alerts.json at
all (confirmed empirically - zero win.eventdata fields anywhere in
alerts.json). Same blind spot detect_kerberoasting.py already works
around for a different event type (raw Kerberos ticket events); same
fix applied here for Sysmon process creation. See build_progress.md
for the full investigation.

Gives DC the same Process-node lineage Target already has via
Tetragon, so DC-originated alerts can correlate to a root-cause
process chain the same way Target's already do - see the matching
patch to graph_writer.py's correlate_alert_to_processes(), which widens
its hardcoded Linux-binary filter to also accept DC's process names.

Windows has no POSIX uid - the Sysmon 'user' field (e.g.
'NT AUTHORITY\\SYSTEM') is stored in that same Process.uid slot. It's
just an identity-of-the-process-owner field either way, and keeping
one property name avoids a Process-node schema fork between hosts.

Run as a systemd service (afx-file-hasher-dc.service), same
tail-from-EOF pattern as ingest_wazuh.py/detect_kerberoasting.py.
"""

from __future__ import annotations

import json
import logging
import time

import config
from graph_writer import GraphWriter

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [file_hasher_dc] %(levelname)s %(message)s"
)
log = logging.getLogger("file_hasher_dc")

ARCHIVES_LOG = "/var/ossec/logs/archives/archives.log"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PROCESS_CREATE_EVENT_ID = "1"


def follow(path: str):
    """Tails a file from EOF, same pattern as ingest_wazuh.py's
    follow() - yields new lines as they're appended."""
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def _extract_json(line: str):
    """archives.log lines look like '<prefix text> {json}' - the real
    payload starts at the line's first '{'. Returns None if the line
    has no JSON or it doesn't parse (mirrors ingest_tetragon.py's
    skip-and-log-a-warning handling of bad lines, just without the
    warning spam here since archives.log has many non-JSON lines by
    design, unlike Tetragon's getevents stream)."""
    idx = line.find("{")
    if idx == -1:
        return None
    try:
        return json.loads(line[idx:])
    except json.JSONDecodeError:
        return None


def _to_iso_utc(sysmon_ts):
    """Sysmon's utcTime fields look like '2026-11-04 03:33:07.041' -
    space-separated, no timezone marker. dateutil.parser.isoparse
    happily parses that into a NAIVE datetime, which would silently
    break correlate_alert_to_processes()'s duration.between() once it
    reaches Neo4j (Wazuh's own timestamps are timezone-aware, e.g.
    '...9277809Z'). The field name says UTC, so make that explicit
    before it goes anywhere near GraphWriter."""
    if not sysmon_ts:
        return None
    return sysmon_ts.replace(" ", "T") + "Z"


def _parse_hashes(hashes_str) -> dict:
    """Sysmon's Hashes field is a single string like
    'MD5=...,SHA256=...,IMPHASH=...' - splits it into a dict keyed by
    algorithm name."""
    out = {}
    if not hashes_str:
        return out
    for part in hashes_str.split(","):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip().upper()] = v.strip()
    return out


def _build_process_event(win: dict):
    """Builds a Tetragon-shaped event dict from a raw Sysmon Event ID 1
    record, so it can go straight into GraphWriter.upsert_process()
    unchanged. exec_id is synthesized as 'dc:<ProcessGuid>' - Tetragon
    generates its own exec_id internally (no literal format to mirror),
    and Sysmon's ProcessGuid is already a real GUID, so collisions
    aren't a concern."""
    eventdata = win.get("eventdata", {}) or {}
    process_guid = eventdata.get("processGuid")
    if not process_guid:
        return None

    event = {
        "node_name": "dc",
        "process": {
            "exec_id": f"dc:{process_guid}",
            "pid": eventdata.get("processId"),
            "uid": eventdata.get("user"),
            "binary": eventdata.get("image"),
            "arguments": eventdata.get("commandLine", ""),
            "start_time": _to_iso_utc(eventdata.get("utcTime")),
        },
    }

    parent_guid = eventdata.get("parentProcessGuid")
    if parent_guid:
        event["parent"] = {
            "exec_id": f"dc:{parent_guid}",
            "pid": eventdata.get("parentProcessId"),
            "binary": eventdata.get("parentImage"),
        }

    return event


def main() -> None:
    writer = GraphWriter(
        config.NEO4J_URI, config.NEO4J_USER, config.NEO4J_PASSWORD, config.HOST_NAME
    )
    log.info("Tailing %s for DC Sysmon process-creation events", ARCHIVES_LOG)

    try:
        for line in follow(ARCHIVES_LOG):
            if SYSMON_CHANNEL not in line:
                continue
            payload = _extract_json(line)
            if not payload:
                continue

            win = payload.get("win")
            if not win:
                continue
            system = win.get("system", {}) or {}
            if system.get("eventID") != PROCESS_CREATE_EVENT_ID:
                continue
            if system.get("channel") != SYSMON_CHANNEL:
                continue

            event = _build_process_event(win)
            if not event:
                continue

            exec_id = writer.upsert_process(event)
            if not exec_id:
                continue

            eventdata = win.get("eventdata", {}) or {}
            hashes = _parse_hashes(eventdata.get("hashes"))
            sha256 = hashes.get("SHA256")
            if sha256:
                writer.upsert_file_hash(
                    exec_id=exec_id,
                    sha256=sha256,
                    md5=hashes.get("MD5"),
                    imphash=hashes.get("IMPHASH"),
                    path=eventdata.get("image"),
                    first_seen_str=_to_iso_utc(eventdata.get("utcTime")),
                )
                log.info("Process %s: hashed image (sha256=%s)", exec_id[:24], sha256[:16])
            else:
                log.info("Process %s: no hash in event", exec_id[:24])
    except KeyboardInterrupt:
        log.info("Stopping file_hasher_dc.")
    finally:
        writer.close()


if __name__ == "__main__":
    main()
