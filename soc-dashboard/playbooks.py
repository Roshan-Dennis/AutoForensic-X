"""
playbooks.py — runs the REAL soar_ssh_bruteforce.py / soar_reverse_shell.py
scripts on demand, instead of re-implementing their corroboration logic
here. Both scripts already do their own detection, safety checks
(allowlist, 2-source corroboration, live PID re-verification before any
kill) and audit logging — this module just invokes them the same way you
would by hand over SSH, using the `--yes` flag added to both scripts so
they don't block on a terminal `input()` that will never come from a web
request.

This is deliberately a thin subprocess wrapper, not a reimplementation:
the whole point of "trigger playbook" is that it's the SAME code path as
running it interactively, so nothing about the safety model changes
depending on how it was invoked.
"""

from __future__ import annotations

import subprocess

import config

PLAYBOOKS = {
    "ssh_bruteforce": {
        "label": "SSH Brute Force",
        "script": "soar_ssh_bruteforce.py",
        "description": "Corroborates a Wazuh auth-failure cluster against a Tetragon-confirmed sshd process before blocking the source IP (inbound).",
    },
    "reverse_shell": {
        "label": "Reverse Shell",
        "script": "soar_reverse_shell.py",
        "description": "Corroborates a /dev/tcp/ command against confirmed process ancestry from a network-facing service before killing the shell and blocking the listener IP (outbound).",
    },
}


def run_playbook(name: str, dry_run: bool = True, timeout: int = 60) -> dict:
    """Runs the named playbook and returns its raw stdout/stderr for
    display — the playbook's own audit.py-compatible JSON lines already
    land in soar_audit.log, so Automation History picks up whatever it
    did without this module needing to parse or duplicate that."""
    if name not in PLAYBOOKS:
        raise ValueError(f"Unknown playbook '{name}'.")

    script_path = f"{config.PLAYBOOK_DIR}/{PLAYBOOKS[name]['script']}"
    cmd = [config.PLAYBOOK_PYTHON, script_path]
    cmd.append("--dry-run" if dry_run else "--yes")

    try:
        proc = subprocess.run(
            cmd, cwd=config.PLAYBOOK_DIR, capture_output=True, text=True, timeout=timeout
        )
        stdout, stderr, returncode = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as e:
        stdout = (e.stdout or "") if isinstance(e.stdout, str) else (e.stdout or b"").decode(errors="replace")
        stderr = f"Timed out after {timeout}s — a stuck sudo prompt is the most likely cause."
        returncode = -1
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        stdout, stderr, returncode = "", str(e), -1

    return {
        "playbook": name,
        "dry_run": dry_run,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
    }
