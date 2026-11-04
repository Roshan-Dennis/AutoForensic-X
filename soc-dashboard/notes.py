"""
notes.py - local state for the SOC analyst workflow the graph itself has
no place for: incident ticket status, disposition, SLA timestamps, and
free-text analyst notes.

Deliberately NOT stored in Neo4j. This app's whole data model rests on
Alert/Process/Remediation nodes being the untouched, replayable record of
what the collectors and SOAR actually saw and did - the Metrics page's
MTTD/MTTR numbers depend on that staying true. Ticket-workflow state
("who's working this", "is it contained", "was it a real attack", analyst
commentary) is a separate concern, so it lives in its own small JSON file
instead of mutating graph nodes other parts of this app rely on staying
exactly as ingested.

Ticket model (per incident_id):
    {
        "status": one of STATUSES,
        "disposition": one of DISPOSITIONS or None (set on close),
        "claimed_by": str or None,
        "claimed_at": ISO-8601 str or None (set on first claim),
        "contained_at": ISO-8601 str or None (set on first containment),
        "closed_at": ISO-8601 str or None (set on first close),
        "history": [ {ts, action, status, disposition, actor, note}, ... ],
    }

Schema note (2026-11-03): this replaces an earlier, flatter
status-only scheme (STATUSES = new/acknowledged/investigating/resolved/
false_positive). Existing incident_status.json entries from that scheme
were migrated in place by migrate_ticket_schema.py - see that file's
docstring. This module only ever reads/writes the new scheme.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

import config

_LOCK = threading.Lock()

STATUSES = ["open", "in_progress", "contained", "closed"]
DISPOSITIONS = ["true_positive", "false_positive", "benign", "duplicate"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_entry() -> dict:
    return {
        "status": "open",
        "disposition": None,
        "claimed_by": None,
        "claimed_at": None,
        "contained_at": None,
        "closed_at": None,
        "history": [],
    }


def _load() -> dict:
    if not os.path.exists(config.INCIDENT_STATE_PATH):
        return {}
    try:
        with open(config.INCIDENT_STATE_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict):
    directory = os.path.dirname(config.INCIDENT_STATE_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp_path = config.INCIDENT_STATE_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, config.INCIDENT_STATE_PATH)


def get(incident_id: str) -> dict:
    entry = _load().get(incident_id)
    if entry is None:
        return _default_entry()
    # Tolerate entries saved before a field existed (e.g. a fresh
    # _default_entry() gained a key after some tickets were already
    # written) without requiring another migration pass.
    merged = _default_entry()
    merged.update(entry)
    return merged


def all_statuses() -> dict:
    return _load()


def _record(incident_id: str, *, action: str, actor: str, note: str = "", **field_updates) -> dict:
    with _LOCK:
        data = _load()
        entry = data.get(incident_id)
        if entry is None:
            entry = _default_entry()
        for key, value in field_updates.items():
            entry[key] = value
        entry.setdefault("history", []).append(
            {
                "ts": _now(),
                "action": action,
                "status": entry.get("status"),
                "disposition": entry.get("disposition"),
                "actor": actor,
                "note": note or None,
            }
        )
        data[incident_id] = entry
        _save(data)
        return entry


def claim(incident_id: str, actor: str = "analyst", note: str = "") -> dict:
    """Mark this incident as being worked by `actor`. Always updates
    claimed_by/claimed_at to reflect current ownership - re-claiming
    (e.g. handing off) is expected and just overwrites who has it now."""
    return _record(
        incident_id,
        action="claimed",
        actor=actor,
        note=note,
        status="in_progress",
        claimed_by=actor,
        claimed_at=_now(),
    )


def contain(incident_id: str, actor: str = "analyst", note: str = "") -> dict:
    """Mark the threat as contained. contained_at is only set the first
    time, so it stays a true containment-SLA timestamp even if this is
    called again later (e.g. to re-affirm containment)."""
    existing = get(incident_id)
    return _record(
        incident_id,
        action="contained",
        actor=actor,
        note=note,
        status="contained",
        contained_at=existing.get("contained_at") or _now(),
    )


def close(incident_id: str, disposition: str, actor: str = "analyst", note: str = "") -> dict:
    """Close the ticket with a final disposition. closed_at is only set
    the first time (same reasoning as contained_at); disposition is
    always updated, so a wrong disposition can be corrected by closing
    again."""
    if disposition not in DISPOSITIONS:
        raise ValueError(
            f"Unknown disposition '{disposition}'. Must be one of: {', '.join(DISPOSITIONS)}."
        )
    existing = get(incident_id)
    return _record(
        incident_id,
        action="closed",
        actor=actor,
        note=note,
        status="closed",
        disposition=disposition,
        closed_at=existing.get("closed_at") or _now(),
    )


def false_positive(incident_id: str, actor: str = "analyst", note: str = "") -> dict:
    """Shortcut for the common one-click "this wasn't real" case: closes
    the ticket with disposition=false_positive directly, skipping
    claim/contain, same as a real analyst would for an obvious FP."""
    existing = get(incident_id)
    return _record(
        incident_id,
        action="false_positive",
        actor=actor,
        note=note or "Marked false positive",
        status="closed",
        disposition="false_positive",
        closed_at=existing.get("closed_at") or _now(),
    )


def add_note(incident_id: str, note: str, actor: str = "analyst") -> dict:
    """Append a free-text analyst note without changing status/
    disposition - separate from the AI-generated narrative.md, and
    separate from the status-transition history entries above, though
    it's stored in the same history list/timeline for a single
    chronological view."""
    note = (note or "").strip()
    if not note:
        raise ValueError("Note text cannot be empty.")
    return _record(incident_id, action="note", actor=actor, note=note)
