"""
patch_priority_queries.py - ONE-TIME patch script, run once on
2026-11-04 against the live ~/soc-dashboard/queries.py, to surface the
new Alert.priority / Alert.asset_criticality properties (written by
graph_writer.py's upsert_alert, see patch_priority_graph_writer.py) on
real_incidents(), with a computed fallback for Alert nodes ingested
before this change (which won't have the properties stored yet). Also
adds a priority to the two synthetic (non-Alert-node) incident types
in synthetic_incidents(), using the same formula.

Same safety discipline as the other patch scripts in this project:
short, high-confidence anchors, indentation auto-detected or cosmetic
(inside strings/open parens) wherever possible, exact-match-count
assertions, abort-with-no-changes on any mismatch.

Usage (from ~/soc-dashboard):
    python3 patch_priority_queries.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

TARGET = pathlib.Path("queries.py")

NEW_HELPERS = '''

# Asset-criticality lookup + priority scoring, mirrors
# provenance-graph/graph_writer.py's copy (new Alert nodes get
# priority/asset_criticality stored at ingest time there; this is only
# used as a fallback here for Alert nodes ingested before that change,
# and for the two synthetic non-Alert-node incident types below, which
# have nothing stored to read).
ASSET_CRITICALITY = {
    "dc": "critical",
    "target": "standard",
    "kali": "low",
    "soc": "standard",
}
_SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
_CRITICALITY_SCORE = {"critical": 3, "standard": 2, "low": 1}


def priority_for(severity: str, criticality: str) -> str:
    score = _SEVERITY_SCORE.get(severity, 1) * _CRITICALITY_SCORE.get(criticality, 2)
    if score >= 9:
        return "P1"
    if score >= 6:
        return "P2"
    if score >= 3:
        return "P3"
    return "P4"

'''


def _replace_n(text: str, old: str, new: str, *, expected_count: int) -> str:
    count = text.count(old)
    if count != expected_count:
        print(
            f"FAILED: anchor matched {count} times (expected exactly {expected_count}) - "
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

    # 1. Insert ASSET_CRITICALITY + priority_for() right after
    #    severity_bucket()'s final line.
    anchor1 = '    if lvl >= 5:\n        return "medium"\n    return "low"\n'
    text = _replace_n(text, anchor1, anchor1 + NEW_HELPERS, expected_count=1)

    # 2. Add the two new fields to real_incidents()'s Cypher RETURN.
    #    Inside a triple-quoted Cypher string - indentation is cosmetic.
    old2 = "a.mitre_tactic AS mitre_tactic, a.srcip AS srcip,\n"
    new2 = (
        "a.mitre_tactic AS mitre_tactic, a.srcip AS srcip,\n"
        "                a.priority AS priority, a.asset_criticality AS asset_criticality,\n"
        "                a.agent_name AS agent_name,\n"
    )
    text = _replace_n(text, old2, new2, expected_count=1)

    # 3. real_incidents()'s output dict: add priority/asset_criticality,
    #    reading the stored value with a computed fallback for older
    #    Alert nodes that predate this change.
    old3 = '"severity": severity_bucket(r["rule_level"]),\n'
    new3 = (
        '"severity": severity_bucket(r["rule_level"]),\n'
        '                "priority": r["priority"] or priority_for(\n'
        '                    severity_bucket(r["rule_level"]),\n'
        '                    r["asset_criticality"] or ASSET_CRITICALITY.get((r["agent_name"] or "").lower(), "standard"),\n'
        '                ),\n'
        '                "asset_criticality": r["asset_criticality"] or ASSET_CRITICALITY.get((r["agent_name"] or "").lower(), "standard"),\n'
    )
    text = _replace_n(text, old3, new3, expected_count=1)

    # 4. synthetic_incidents(): both loops (reverse-shell, web-shell)
    #    hardcode severity="high" - both only ever fire on the Target VM
    #    in this lab (confirmed: neither Cypher pattern joins to Host,
    #    and their entry-binary patterns - php-fpm/nginx/sshd - are
    #    Target-only), so asset_criticality is fixed "standard" rather
    #    than adding an untested Cypher join for a value already known.
    #    Deliberately patches BOTH occurrences (expected_count=2).
    old4 = '"severity": "high",\n'
    new4 = (
        '"severity": "high",\n'
        '                "priority": priority_for("high", "standard"),\n'
        '                "asset_criticality": "standard",\n'
    )
    text = _replace_n(text, old4, new4, expected_count=2)

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
