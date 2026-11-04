"""
patch_priority_graph_writer.py - ONE-TIME patch script, run once on
2026-11-04 against the live ~/provenance-graph/graph_writer.py, to
compute and store a priority field (severity x asset criticality) on
Alert nodes at ingest time, per the roadmap's priority-field plan.

Covers both ingest_wazuh.py and detect_kerberoasting.py, since both
call GraphWriter.upsert_alert() - one change here reaches both.

Uses short, high-confidence single-line anchors with indentation
auto-detected from the file itself (not hand-typed), rather than
matching large multi-line blocks reconstructed from a terminal
screenshot - avoids the exact corruption risk that bit the base64
delivery method earlier in this project. Aborts with no changes
written if any anchor isn't found exactly once (or exactly twice,
for the one documented multi-match case).

Usage (from ~/provenance-graph):
    python3 patch_priority_graph_writer.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

TARGET = pathlib.Path("graph_writer.py")

NEW_CONSTANTS = '''
# Asset-criticality lookup by agent/host name, and the severity x
# criticality -> priority scoring formula. Mirrors the lookup that used
# to live only in soc-dashboard/generate_ticket.py (render-time-only,
# per the 2026-10-15 roadmap note) - computed here instead, once, at
# ingest time, and stored on the Alert node. Kept as its own small copy
# rather than a cross-directory import (provenance-graph and
# soc-dashboard are independent script directories with their own
# config.py each, same existing pattern).
ASSET_CRITICALITY = {
    "dc": "critical",
    "target": "standard",
    "kali": "low",
    "soc": "standard",
}

_SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
_CRITICALITY_SCORE = {"critical": 3, "standard": 2, "low": 1}


def _severity_bucket(rule_level) -> str:
    """Same thresholds as soc-dashboard/queries.py's severity_bucket() -
    kept in sync by hand since the two directories don't share a package."""
    if rule_level is None:
        return "unknown"
    try:
        lvl = int(rule_level)
    except (TypeError, ValueError):
        return "unknown"
    if lvl >= 12:
        return "critical"
    if lvl >= 9:
        return "high"
    if lvl >= 5:
        return "medium"
    return "low"


def _compute_priority(rule_level, agent_name) -> tuple[str, str]:
    """Returns (priority, asset_criticality). Priority is severity x
    asset-criticality, composite score mapped to P1 (highest) - P4
    (lowest). Uses the alert's own reporting agent (agent_name), not the
    GraphWriter's own configured host_name - agent_name is the Wazuh
    manager's record of which VM the event actually came from, which is
    what asset criticality should be about."""
    severity = _severity_bucket(rule_level)
    criticality = ASSET_CRITICALITY.get((agent_name or "").lower(), "standard")
    score = _SEVERITY_SCORE[severity] * _CRITICALITY_SCORE[criticality]
    if score >= 9:
        priority = "P1"
    elif score >= 6:
        priority = "P2"
    elif score >= 3:
        priority = "P3"
    else:
        priority = "P4"
    return priority, criticality

'''


def _insert_after(text: str, anchor_line: str, insertion: str, *, expected_count: int = 1) -> str:
    """Finds anchor_line (exact substring, must appear expected_count
    times), and inserts `insertion` immediately after each occurrence."""
    count = text.count(anchor_line)
    if count != expected_count:
        print(
            f"FAILED: anchor {anchor_line!r} matched {count} times "
            f"(expected exactly {expected_count}) - aborting with NO changes written.",
            file=sys.stderr,
        )
        sys.exit(1)
    return text.replace(anchor_line, anchor_line + insertion)


def _replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        print(
            f"FAILED: replacement text matched {count} times (expected exactly 1) - "
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

    # 1. Insert the new constants/helpers right after the logger line
    #    (module level, indentation-free, zero risk).
    anchor1 = 'log = logging.getLogger("graph_writer")\n'
    text = _insert_after(text, anchor1, NEW_CONSTANTS)

    # 2. Compute priority/asset_criticality right after the timestamp
    #    line inside upsert_alert(). Indentation is auto-detected from
    #    the anchor line itself so it always matches its surroundings.
    anchor2 = 'timestamp = _parse_ts(alert.get("timestamp"))\n'
    idx = text.index(anchor2)
    line_start = text.rfind("\n", 0, idx) + 1
    indent = text[line_start:idx]
    insertion2 = f'{indent}priority, asset_criticality = _compute_priority(rule.get("level"), agent.get("name"))\n'
    text = _insert_after(text, anchor2, insertion2)

    # 3. Add the two new properties to the Cypher ON CREATE SET clause.
    #    This is inside a triple-quoted Cypher string, so exact
    #    indentation here is cosmetic only - Cypher doesn't care.
    old3 = "a.agent_name = $agent_name\n"
    new3 = (
        "a.agent_name = $agent_name,\n"
        "                    a.priority = $priority,\n"
        "                    a.asset_criticality = $asset_criticality\n"
    )
    text = _replace_once(text, old3, new3)

    # 4. Add the two new params to the session.run() call. This is
    #    inside an open paren, so Python doesn't enforce alignment here -
    #    any consistent indentation is syntactically valid.
    old4 = 'agent_name=agent.get("name"),\n'
    new4 = (
        'agent_name=agent.get("name"),\n'
        "            priority=priority,\n"
        "            asset_criticality=asset_criticality,\n"
    )
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
