"""
ingest_tetragon.py — streams live events from Tetragon into the provenance
graph.

Runs `tetra --server-address <socket> getevents -o json` as a subprocess
(the same command you already used manually to watch events) and feeds
each JSON line to GraphWriter. Run this as root, or as a user in the
group that can read the Tetragon unix socket — same requirement as
running `tetra getevents` by hand.
"""

import json
import shlex
import os
import logging
import subprocess
import sys

import config
from graph_writer import GraphWriter

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [tetragon] %(levelname)s %(message)s"
)
log = logging.getLogger("ingest_tetragon")


def stream_events(writer: GraphWriter):
    if os.environ.get("TETRAGON_CMD"):
        cmd = shlex.split(os.environ["TETRAGON_CMD"])
    else:
        cmd = ["tetra", "--server-address", config.TETRAGON_SOCKET, "getevents", "-o", "json"]
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
                event = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Skipping unparseable line: %.200s", line)
                continue

            # Tetragon wraps the real payload under a key naming the event
            # type — we only care about process lifecycle events for the
            # provenance graph right now.
            for key in ("process_exec", "process_exit"):
                if key in event:
                    exec_id = writer.upsert_process(event[key])
                    if exec_id:
                        log.info("%s: %s", key, exec_id[:16])
                    break
    except KeyboardInterrupt:
        log.info("Stopping Tetragon ingest.")
    finally:
        proc.terminate()


def main():
    writer = GraphWriter(
        config.NEO4J_URI, config.NEO4J_USER, config.NEO4J_PASSWORD, config.HOST_NAME
    )
    try:
        stream_events(writer)
    finally:
        writer.close()


if __name__ == "__main__":
    sys.exit(main())
