"""
patch_priority_incident_packager.py - ONE-TIME patch script, run once
on 2026-11-04 against the live ~/soc-dashboard/incident_packager.py,
to pass the new priority/asset_criticality fields (now present in
queries.py's incident dicts, see patch_priority_queries.py) through
build_package()'s output, so generate_ticket.py can render them.

Same safety discipline as the other patch scripts in this project.

Usage (from ~/soc-dashboard):
    python3 patch_priority_incident_packager.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

TARGET = pathlib.Path("incident_packager.py")


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

    # build_package()'s returned dict: add priority/asset_criticality
    # right after the existing severity line. Inside a dict literal with
    # consistent existing indentation - matched exactly as-is below.
    old = '"severity": incident.get("severity"),\n'
    new = (
        '"severity": incident.get("severity"),\n'
        '        "priority": incident.get("priority"),\n'
        '        "asset_criticality": incident.get("asset_criticality"),\n'
    )
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
