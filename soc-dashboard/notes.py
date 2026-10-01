"""
notes.py — local state for the SOC analyst workflow the graph itself has
no place for: incident triage status and free-text notes.

Deliberately NOT stored in Neo4j. This app's whole data model rests on
Alert/Process/Remediation nodes being the untouched, replayable record of
what the collectors and SOAR actually saw and did — the Metrics page's
MTTD/MTTR numbers depend on that staying true. Triage state ("seen this",
"false positive", analyst commentary) is a separate concern, so it lives
in its own small JSON file instead of mutating graph nodes other parts of
this app rely on staying exactly as ingested.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

import config

_LOCK = threading.Lock()

STATUSES = ["new", "acknowledged", "investigating", "resolved", "false_positive"]


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
    return _load().get(incident_id, {"status": "new", "history": []})


def all_statuses() -> dict:
    return _load()


def set_status(incident_id: str, status: str, note: str = "", actor: str = "analyst") -> dict:
    if status not in STATUSES:
        raise ValueError(f"Unknown status '{status}'.")
    with _LOCK:
        data = _load()
        entry = data.get(incident_id, {"status": "new", "history": []})
        entry["status"] = status
        entry["history"].append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "status": status,
                "note": note or None,
                "actor": actor,
            }
        )
        data[incident_id] = entry
        _save(data)
        return entry
