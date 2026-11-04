"""
migrate_ticket_schema.py - ONE-TIME migration script, run once on
2026-11-03 against the live ~/soc-dashboard/incident_status.json.

Converts incident_status.json entries from the old, flatter
notes.py status scheme (STATUSES = new/acknowledged/investigating/
resolved/false_positive, no disposition/SLA fields) into the new
ticket-workflow schema notes.py now reads/writes (status =
open/in_progress/contained/closed, plus disposition/claimed_by/
claimed_at/contained_at/closed_at). See notes.py's module docstring
for the full new schema shape.

Safe to re-run: any entry whose status is already one of the new
values is left untouched (idempotent), so running this twice is a
no-op the second time.

Usage (from ~/soc-dashboard, with config.py importable):
    python3 migrate_ticket_schema.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import config

OLD_TO_NEW_STATUS = {
    "new": "open",
    "acknowledged": "in_progress",
    "investigating": "in_progress",
    "resolved": "closed",
    "false_positive": "closed",
}

NEW_STATUSES = {"open", "in_progress", "contained", "closed"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    path = config.INCIDENT_STATE_PATH
    if not os.path.exists(path):
        print(f"No state file at {path} - nothing to migrate.")
        return

    with open(path, "r") as f:
        data = json.load(f)

    migrated = 0
    skipped = 0
    for incident_id, entry in data.items():
        old_status = entry.get("status")
        if old_status in NEW_STATUSES:
            skipped += 1
            continue
        if old_status not in OLD_TO_NEW_STATUS:
            print(f"  WARNING: {incident_id} has unrecognized status {old_status!r} - leaving as-is.")
            skipped += 1
            continue

        new_status = OLD_TO_NEW_STATUS[old_status]
        disposition = "false_positive" if old_status == "false_positive" else None

        entry["status"] = new_status
        entry["disposition"] = disposition
        entry.setdefault("claimed_by", None)
        entry.setdefault("claimed_at", None)
        entry.setdefault("contained_at", None)
        entry["closed_at"] = _now() if new_status == "closed" else None

        # Rewrite old status values inside the existing history entries too,
        # so the timeline reads consistently with the new scheme.
        for h in entry.get("history", []):
            h_status = h.get("status")
            if h_status in OLD_TO_NEW_STATUS:
                h["status"] = OLD_TO_NEW_STATUS[h_status]
            h.setdefault("disposition", None)

        entry.setdefault("history", []).append(
            {
                "ts": _now(),
                "action": "migrated",
                "status": new_status,
                "disposition": disposition,
                "actor": "migrate_ticket_schema.py",
                "note": f"Migrated from legacy status '{old_status}'.",
            }
        )
        migrated += 1

    tmp_path = path + ".migrate.tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)

    print(f"Migrated {migrated} incident(s), skipped {skipped} (already on the new schema or unrecognized).")


if __name__ == "__main__":
    main()
