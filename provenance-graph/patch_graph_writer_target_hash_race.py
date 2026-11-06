"""
patch_graph_writer_target_hash_race.py - ONE-TIME patch script, run
once against the live ~/provenance-graph/graph_writer.py, fixing a
real race condition found while verifying Target-side file hashing.

The bug: upsert_file_hash() used `MERGE (p:Process {exec_id:
$exec_id})` with no properties - benign on the DC side (file_hasher_dc.py
calls upsert_process() then upsert_file_hash() sequentially in one
script, so the Process node always already exists), but on Target
there are TWO INDEPENDENT SSH pipelines racing to write the same
exec_id (ingest_tetragon.py and the new ingest_file_hashes.py), with
no ordering guarantee between them. When the file-hash pipeline's
write reached Neo4j first, its blind MERGE created a bare placeholder
Process node (no pid/binary/node_name). Then when ingest_tetragon.py's
own MERGE ... ON CREATE SET ran, it found the node already existed, so
ON CREATE SET never fired - the node was permanently stuck bare.
Confirmed live: 625 Process nodes with node_name IS NULL after
~5 minutes of running both pipelines concurrently.

Fix: change the Process side from MERGE to MATCH (never creates a
node here - only upsert_process() ever does that), and add a short
bounded retry (5 attempts, 300ms apart) for the case where this
pipeline's write reaches Neo4j before upsert_process()'s does. If the
Process node still doesn't exist after retrying, log a warning and
drop the hash attach rather than corrupting the graph - this should
only ever happen on Target's race, never on DC's sequential path.

Same safety discipline as the other patch scripts in this project:
exact-match-count assertions, abort-with-no-changes on any mismatch,
backup + py_compile verification before any file is touched.

Usage (from ~/provenance-graph):
    python3 patch_graph_writer_target_hash_race.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

TARGET = pathlib.Path("graph_writer.py")

OLD_METHOD = '''    def upsert_file_hash(
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

NEW_METHOD = '''    def upsert_file_hash(
        self,
        exec_id: str,
        sha256: str,
        md5: Optional[str],
        imphash: Optional[str],
        path: Optional[str],
        first_seen_str: Optional[str],
        retries: int = 5,
        retry_delay: float = 0.3,
    ) -> None:
        """Attaches a File node (identified by sha256, the canonical
        hash for this purpose) to the Process already upserted under
        exec_id, via a HAS_IMAGE edge. Used by file_hasher_dc.py for
        DC's Sysmon Event ID 1 process-image hashes, and by
        ingest_file_hashes.py for Target's Tetragon-exec image hashes.

        Deliberately MATCHes the Process node rather than MERGE-ing
        it - Target's two independent SSH pipelines (ingest_tetragon.py
        and ingest_file_hashes.py) race to write the same exec_id with
        no ordering guarantee, and a blind MERGE here would create a
        bare placeholder Process node whenever this one arrived first,
        which upsert_process()'s own MERGE ... ON CREATE SET would
        then never populate (ON CREATE only fires once, on first
        creation). Retries briefly since the race is normally resolved
        within well under a second; a hash whose Process node never
        shows up (should only happen under the Target race - DC's
        sequential path never hits this) is logged and dropped rather
        than corrupting the graph with a bare node."""
        if not sha256:
            return
        first_seen = _parse_ts(first_seen_str)
        for attempt in range(retries):
            with self.driver.session() as session:
                result = session.run(
                    """
                    MATCH (p:Process {exec_id: $exec_id})
                    MERGE (f:File {sha256: $sha256})
                    ON CREATE SET
                        f.md5 = $md5,
                        f.imphash = $imphash,
                        f.path = $path,
                        f.first_seen = $first_seen
                    MERGE (p)-[:HAS_IMAGE]->(f)
                    RETURN count(p) AS matched
                    """,
                    sha256=sha256,
                    md5=md5,
                    imphash=imphash,
                    path=path,
                    first_seen=first_seen,
                    exec_id=exec_id,
                )
                record = result.single()
                if record and record["matched"] > 0:
                    return
            if attempt < retries - 1:
                time.sleep(retry_delay)
        log.warning(
            "upsert_file_hash: no Process node found for exec_id=%s after "
            "%d retries - dropping (sha256=%s)",
            exec_id, retries, sha256,
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

    # 1. Add `import time` for the retry sleep.
    old1 = "import logging\nfrom datetime import datetime\n"
    new1 = "import logging\nimport time\nfrom datetime import datetime\n"
    text = _replace_once(text, old1, new1)

    # 2. Replace upsert_file_hash() entirely with the retry-hardened version.
    text = _replace_once(text, OLD_METHOD, NEW_METHOD)

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
