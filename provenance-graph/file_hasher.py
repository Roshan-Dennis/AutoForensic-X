"""
file_hasher.py - tails Tetragon's local JSON export log
(/var/log/tetragon/tetragon.log, the same file ingest_tetragon.py
already consumes remotely over SSH) for process_exec events, and for
each one whose binary path exists and is readable, computes SHA-256 +
MD5 and appends a line to /var/log/afx-file-hashes.jsonl for the SOC
to pick up (via a second, narrowly-scoped SSH key under the
afx-sensor account - see build_progress.md for the full design).

Runs as the dedicated afx-filehasher service account (nologin shell),
which has exactly one NOPASSWD sudo rule - the same tail command
afx-sensor's forced SSH command already runs against this same log -
mirroring that account's least-privilege pattern rather than
widening it.

No IMPHASH here (that's a PE/Windows-only concept - see
file_hasher_dc.py for the DC side, which has it from Sysmon). No
timezone-fixup needed either - Tetragon's own start_time timestamps
are already proper RFC3339 with a trailing Z (unlike Sysmon's
space-separated utcTime on the DC side).

A small in-memory cache keyed on (path, mtime, size) avoids
re-hashing an unchanged binary on every single exec - Tetragon fires
on EVERY exec, not just a rare subset, so /bin/bash, /bin/ls etc.
would otherwise get re-hashed constantly.

Run as a systemd service (afx-file-hasher.service). Deployed on the
Target VM (note: lives at /opt/afx/file_hasher.py there, not in
~/provenance-graph - that directory is SOC-only. Copied here into the
repo purely for version control).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import subprocess

TETRAGON_LOG = "/var/log/tetragon/tetragon.log"
OUTPUT_LOG = "/var/log/afx-file-hashes.jsonl"
TAIL_CMD = ["sudo", "/usr/bin/tail", "-n0", "-F", TETRAGON_LOG]
_CACHE_CAP = 5000

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [file_hasher] %(levelname)s %(message)s"
)
log = logging.getLogger("file_hasher")

# (path, mtime, size) -> (sha256, md5)
_hash_cache: dict[tuple[str, float, int], tuple[str, str]] = {}


def _hash_file(path: str):
    """Returns (sha256, md5) for path, using the in-memory cache to
    skip re-hashing an unchanged binary that just got exec'd again.
    Returns None if the path doesn't exist, isn't a regular file, or
    can't be read (e.g. permission denied - file_hasher runs as an
    unprivileged account, same assumption the DC side implicitly
    makes: ordinary system binaries are world-readable, which covers
    the overwhelming majority of real exec events in this lab)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None

    key = (path, st.st_mtime, st.st_size)
    cached = _hash_cache.get(key)
    if cached:
        return cached

    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
    except OSError:
        return None

    result = (sha256.hexdigest(), md5.hexdigest())
    # Simple cap rather than a real LRU - exact eviction policy
    # doesn't matter much here: worst case after a clear is a handful
    # of common binaries getting re-hashed once.
    if len(_hash_cache) > _CACHE_CAP:
        _hash_cache.clear()
    _hash_cache[key] = result
    return result


def stream_events() -> None:
    log.info("Starting: %s", " ".join(TAIL_CMD))
    proc = subprocess.Popen(
        TAIL_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
    )
    try:
        with open(OUTPUT_LOG, "a") as out:
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("Skipping unparseable line: %.200s", line)
                    continue

                payload = event.get("process_exec")
                if not payload:
                    continue
                proc_data = payload.get("process")
                if not proc_data:
                    continue
                exec_id = proc_data.get("exec_id")
                binary = proc_data.get("binary")
                if not exec_id or not binary:
                    continue

                hashes = _hash_file(binary)
                if not hashes:
                    continue
                sha256, md5 = hashes

                record = {
                    "exec_id": exec_id,
                    "sha256": sha256,
                    "md5": md5,
                    "path": binary,
                    "first_seen": proc_data.get("start_time"),
                }
                out.write(json.dumps(record) + "\n")
                out.flush()
                log.info("Hashed %s (sha256=%s)", binary, sha256[:16])
    except KeyboardInterrupt:
        log.info("Stopping file_hasher.")
    finally:
        proc.terminate()


def main() -> None:
    stream_events()


if __name__ == "__main__":
    main()
