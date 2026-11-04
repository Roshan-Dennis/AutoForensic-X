"""
patch_queries_agent_name.py - ONE-TIME follow-up patch, run once on
2026-11-04 against the live ~/soc-dashboard/queries.py (already
patched today by patch_priority_queries.py), to fix an incidental bug
found while verifying the priority field: real_incidents() fetches
a.agent_name in its Cypher row (needed for the priority/criticality
fallback computation) but never puts it in the dict it returns, so
incident_packager.py's `incident.get("agent_name")` host fallback is
always None - this is why a just-generated ticket showed "Host | None"
even though the alert's agent_name was present in Neo4j the whole
time. One-line fix: add "agent_name" to the returned dict too.

Anchors on the exact asset_criticality line patch_priority_queries.py
added earlier today, so this only applies cleanly on top of that
patch (which is the live state of this file right now).

Usage (from ~/soc-dashboard):
    python3 patch_queries_agent_name.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

TARGET = pathlib.Path("queries.py")


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

    old = (
        '"asset_criticality": r["asset_criticality"] or ASSET_CRITICALITY.get((r["agent_name"] or "").lower(), "standard"),\n'
    )
    new = old + '                "agent_name": r["agent_name"],\n'
    text = _replace_once(text, old, new)

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
