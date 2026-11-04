"""
patch_priority_generate_ticket.py - ONE-TIME patch script, run once on
2026-11-04 against the live ~/soc-dashboard/generate_ticket.py, to
switch it from computing asset criticality itself at render time (the
old placeholder behavior, per the 2026-10-15 roadmap note) to reading
priority/asset_criticality off the incident package - now populated by
incident_packager.py (see patch_priority_incident_packager.py), which
in turn reads them from queries.py (see patch_priority_queries.py),
which in turn reads them off the Alert node itself, written at ingest
time by graph_writer.py (see patch_priority_graph_writer.py). Also
adds a Priority row to the rendered ticket template.

Same safety discipline as the other patch scripts in this project.

Usage (from ~/soc-dashboard):
    python3 patch_priority_generate_ticket.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

TARGET = pathlib.Path("generate_ticket.py")


def _replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        print(
            f"FAILED: anchor matched {count} times (expected exactly 1) - "
            f"aborting with NO changes written.\nLooking for:\n{old!r}",
            file=sys.stderr,
        )
        sys.exit(1)
    return text.replace(old, new)


def main() -> None:
    if not TARGET.exists():
        print(f"FAILED: {TARGET} not found in the current directory.", file=sys.stderr)
        sys.exit(1)

    text = TARGET.read_text()
    original = text

    # 1. Replace the old render-time-only ASSET_CRITICALITY block (and
    #    its explanatory comment, now stale) with an updated comment.
    #    The dict itself moved to queries.py/graph_writer.py - no longer
    #    needed here at all, since the package now carries the computed
    #    value through from the Alert node (or queries.py's fallback).
    old1 = (
        "# Hardcoded asset-criticality lookup by hostname, per the roadmap's\n"
        "# priority-field plan (severity x asset criticality). This is NOT yet\n"
        "# wired into ingest_wazuh.py/detect_kerberoasting.py as a stored Alert\n"
        "# property (separate future task) - here it's computed at render time\n"
        "# from the package's host field, purely for display on the ticket. Never\n"
        "# invented beyond what this lookup actually states.\n"
        "ASSET_CRITICALITY = {\n"
        '    "dc": "critical",\n'
        '    "target": "standard",\n'
        '    "kali": "low",\n'
        '    "soc": "standard",\n'
        "}\n"
    )
    new1 = (
        "# Priority and asset criticality are now computed once, at ingest\n"
        "# time, in provenance-graph/graph_writer.py (with a computed\n"
        "# fallback in soc-dashboard/queries.py for older Alert nodes), and\n"
        "# carried through on the incident package by incident_packager.py.\n"
        "# This module just renders whatever the package already has - no\n"
        "# lookup table needed here anymore (2026-11-04).\n"
    )
    text = _replace_once(text, old1, new1)

    # 2. Replace the render-time host/criticality computation with a
    #    straight read-through from the package, plus priority.
    old2 = (
        'host = (package.get("host") or "").lower()\n'
        '    criticality = ASSET_CRITICALITY.get(host, "unclassified")\n'
    )
    new2 = (
        'criticality = package.get("asset_criticality") or "unclassified"\n'
        '    priority = package.get("priority") or "unscored"\n'
    )
    text = _replace_once(text, old2, new2)

    # 3. Pass priority into the template render call alongside criticality.
    old3 = "criticality=criticality,\n"
    new3 = "criticality=criticality,\n        priority=priority,\n"
    text = _replace_once(text, old3, new3)

    # 4. Add a Priority row to TICKET_TEMPLATE, right before Severity.
    old4 = "| Severity | {{ p.severity }} |\n"
    new4 = "| Priority | {{ priority }} |\n| Severity | {{ p.severity }} |\n"
    text = _replace_once(text, old4, new4)

    if text == original:
        print("FAILED: no changes were actually produced - aborting.", file=sys.stderr)
        sys.exit(1)

    backup_path = TARGET.with_suffix(f".py.bak-{int(datetime.datetime.now().timestamp())}")
    backup_path.write_text(original)
    TARGET.write_text(text)

    try:
        py_compile.compile(str(TARGET), doraise=True)
    except py_compile.PyCompileError as e:
        print(f"FAILED: patched {TARGET} does not compile: {e}", file=sys.stderr)
        print(f"Backup is at {backup_path} - restore it if needed.", file=sys.stderr)
        sys.exit(1)

    print(f"OK: patched {TARGET}. Backup at {backup_path}. Compiles clean.")


if __name__ == "__main__":
    main()
