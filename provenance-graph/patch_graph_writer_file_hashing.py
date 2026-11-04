"""
patch_graph_writer_file_hashing.py - ONE-TIME patch script, run once
on 2026-11-04 against the live ~/provenance-graph/graph_writer.py, to
support DC-side file hashing (see build_progress.md for the full
investigation - Sysmon Event ID 1 never reaches alerts.json, so a new
standalone tailer, file_hasher_dc.py, reads archives.log directly and
needs two things from graph_writer.py):

1. A new upsert_file_hash() method - attaches a File node (identified
   by sha256) to an already-upserted Process via a HAS_IMAGE edge.
2. correlate_alert_to_processes()'s hardcoded binary-name filter
   (sshd/nginx/bash/sh) is tuned to the existing Linux attack
   scenarios and would never match a Windows process name - without a
   fix, DC's new Process nodes would never correlate to DC alerts at
   all. Widened to skip that filter specifically for DC-sourced
   processes (p.node_name = 'dc'), correlating those by time+window
   alone, while leaving the existing Target-side behavior unchanged.

Same safety discipline as the other patch scripts in this project:
exact-match-count assertions, abort-with-no-changes on any mismatch,
backup + py_compile verification before any file is touched.

Usage (from ~/provenance-graph):
    python3 patch_graph_writer_file_hashing.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

TARGET = pathlib.Path("graph_writer.py")

NEW_METHOD = '''
    def upsert_file_hash(
        self,
        exec_id: str,
        sha256: str,
        md5: Optional[str],
        imphash: Optional[str],
        path: Optional[str],
        first_seen_str: Optional[str],
    ) -> None:
        """Attaches a File node (identified by sha256, the canonical
        hash for this purpose) to the Process already upserted under
        exec_id, via a HAS_IMAGE edge. Used by file_hasher_dc.py for
        DC's Sysmon Event ID 1 process-image hashes. Target-side
        (Tetragon) file hashing is a separate, not-yet-built piece
        (needs its own gRPC-stream tailer - Tetragon doesn't carry
        Sysmon-style hash data)."""
        if not sha256:
            return
        first_seen = _parse_ts(first_seen_str)
        with self.driver.session() as session:
            session.run(
                """
                MERGE (f:File {sha256: $sha256})
                ON CREATE SET
                    f.md5 = $md5,
                    f.imphash = $imphash,
                    f.path = $path,
                    f.first_seen = $first_seen
                MERGE (p:Process {exec_id: $exec_id})
                MERGE (p)-[:HAS_IMAGE]->(f)
                """,
                sha256=sha256,
                md5=md5,
                imphash=imphash,
                path=path,
                first_seen=first_seen,
                exec_id=exec_id,
            )
'''


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

    old1 = "AND (p.binary CONTAINS 'sshd' OR p.binary CONTAINS 'nginx' OR p.binary CONTAINS 'bash' OR p.binary CONTAINS 'sh')\n"
    new1 = (
        "AND (\n"
        "                p.node_name = 'dc'\n"
        "                OR p.binary CONTAINS 'sshd' OR p.binary CONTAINS 'nginx' OR p.binary CONTAINS 'bash' OR p.binary CONTAINS 'sh'\n"
        "              )\n"
    )
    text = _replace_once(text, old1, new1)

    old2 = 'return record["edges"] if record else 0\n'
    new2 = old2 + NEW_METHOD
    text = _replace_once(text, old2, new2)

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
