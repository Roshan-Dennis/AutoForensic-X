"""
ingest_file_hashes.py - streams Target's file-hash JSONL log
(afx-file-hasher.service's output on Target, see file_hasher.py) into
the provenance graph.

Runs `$FILEHASH_CMD` (an SSH command tailing Target's
/var/log/afx-file-hashes.jsonl over a second, narrowly-scoped key
under the afx-sensor account - no sudo needed this time, that file's
world-readable, unlike tetragon.log) as a subprocess and feeds each
JSON line to GraphWriter.upsert_file_hash() unchanged - the exact
same method already built for the DC side (file_hasher_dc.py).
Mirrors ingest_tetragon.py's structure exactly.
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import sys

import config
from graph_writer import GraphWriter

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [file_hashes] %(levelname)s %(message)s"
)
log = logging.getLogger("ingest_file_hashes")


def stream_events(writer: GraphWriter) -> None:
    if not os.environ.get("FILEHASH_CMD"):
        log.error("FILEHASH_CMD not set - nothing to run.")
        return
    cmd = shlex.split(os.environ["FILEHASH_CMD"])
    log.info("Starting: %s", " ".join(cmd))

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
    )
    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Skipping unparseable line: %.200s", line)
                continue

            exec_id = record.get("exec_id")
            sha256 = record.get("sha256")
            if not exec_id or not sha256:
                continue

            writer.upsert_file_hash(
                exec_id=exec_id,
                sha256=sha256,
                md5=record.get("md5"),
                imphash=None,
                path=record.get("path"),
                first_seen_str=record.get("first_seen"),
            )
            log.info("%s: hashed image (sha256=%s)", exec_id[:16], sha256[:16])
    except KeyboardInterrupt:
        log.info("Stopping file-hash ingest.")
    finally:
        proc.terminate()


def main() -> None:
    writer = GraphWriter(
        config.NEO4J_URI, config.NEO4J_USER, config.NEO4J_PASSWORD, config.HOST_NAME
    )
    try:
        stream_events(writer)
    finally:
        writer.close()


if __name__ == "__main__":
    sys.exit(main())
