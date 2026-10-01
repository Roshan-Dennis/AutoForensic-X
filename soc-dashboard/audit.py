"""
audit.py — parser for soar_audit.log, the JSON-lines file both SOAR
playbooks append to.

The two playbooks log slightly different shapes:

  soar_ssh_bruteforce.py writes rows like:
    {"ts": "...", "action": "blocked", "ip": "...", "alert_ids": [...],
     "sshd_confirmations": N, "dry_run": false, "approved": true}
    (no "playbook" key at all — this is the tell for "ssh_bruteforce")

  soar_reverse_shell.py writes rows like:
    {"ts": "...", "playbook": "reverse_shell", "action": "blocked",
     "ip": "...", "exec_id": "...", "actions": ["kill", "iptables-output-drop"],
     "reason": "...", "dry_run": false, "approved": true}

Both use "blocked" / "unblock" as the action name for the IP-block
lifecycle, which is what lets us track active blocks generically across
both playbooks without needing a shared schema.
"""

import ipaddress
import json
import os
import subprocess
import time
from datetime import datetime, timezone

import config
import remote_action


def _remote_iptables(action, ip):
    """Run block/unblock on the sensor host via Wazuh active response.
    Returns a list shaped like the old per-chain iptables results."""
    try:
        r = remote_action.run(action, ip)
    except remote_action.RemoteActionError as e:
        return [{"chain": "remote", "returncode": -1, "stderr": str(e)}]
    chains = r.get("chains")
    if chains:
        out = []
        for c in chains:
            item = {"chain": c.get("chain"), "returncode": c.get("returncode", -1),
                    "stderr": c.get("stderr", "")}
            if c.get("already"):
                item["already"] = True
            out.append(item)
        return out
    return [{"chain": "remote", "returncode": 0 if r.get("ok") else -1,
             "stderr": r.get("detail", "")}]


def _parse_ts(raw_ts):
    if raw_ts is None:
        return None
    try:
        s = str(raw_ts)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def read_events(path: str | None = None) -> list[dict]:
    """Read every line of the audit log, normalized into one row shape.
    Returns oldest-first. Malformed lines are skipped, not fatal — this is
    a live-tailed operational log, a half-written last line is expected."""
    path = path or config.SOAR_AUDIT_LOG
    if not os.path.exists(path):
        return []

    rows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue

            playbook = raw.get("playbook") or "ssh_bruteforce"
            action = raw.get("action", "unknown")
            ip = raw.get("ip")
            exec_id = raw.get("exec_id")
            dry_run = bool(raw.get("dry_run", False))
            approved = raw.get("approved")
            ts = raw.get("ts")

            evidence_bits = []
            if raw.get("alert_ids"):
                evidence_bits.append(f"{len(raw['alert_ids'])} Wazuh alert(s)")
            if raw.get("sshd_confirmations") is not None:
                evidence_bits.append(
                    f"{raw['sshd_confirmations']} Tetragon sshd confirmation(s)"
                )
            if raw.get("reason"):
                evidence_bits.append(str(raw["reason"]))
            if exec_id:
                evidence_bits.append(f"Tetragon exec_id {exec_id}")
            if raw.get("note"):
                evidence_bits.append(str(raw["note"]))
            evidence = "; ".join(evidence_bits) or "—"

            if dry_run:
                status = "dry_run"
            elif action.endswith("_failed"):
                status = "failed"
            elif action.startswith("skip"):
                # The playbooks log "skip"/"skip_kill"/"skip_block" for a
                # candidate they looked at and correctly declined to act
                # on (allowlisted, already blocked, no corroboration...).
                # That's a real decision, but it's not an "applied" action
                # — mislabeling it that way (the original bug here) made
                # routine no-ops indistinguishable from real remediation.
                status = "skipped"
            elif approved is False:
                status = "rejected"
            else:
                status = "applied"

            actions_list = raw.get("actions")
            action_summary = action if not actions_list else ", ".join(actions_list)

            rows.append(
                {
                    "ts": ts,
                    "ts_parsed": _parse_ts(ts),
                    "playbook": playbook,
                    "action": action,
                    "action_summary": action_summary,
                    "ip": ip,
                    "exec_id": exec_id,
                    "target": ip or exec_id or "—",
                    "evidence": evidence,
                    "status": status,
                    "raw": raw,
                }
            )
    rows.sort(key=lambda r: r["ts_parsed"] or datetime.min.replace(tzinfo=timezone.utc))
    return rows


def active_blocks(events: list[dict] | None = None) -> dict[str, dict]:
    """Walk the (chronological) event list and return the current block
    state per IP: {ip: {"blocked": bool, "since": ts, "playbook": str}}.
    Last "blocked"/"unblock" action for an IP wins."""
    events = events if events is not None else read_events()
    state: dict[str, dict] = {}
    for ev in events:
        ip = ev.get("ip")
        if not ip:
            continue
        if ev["action"] == "blocked" and ev["status"] == "applied":
            state[ip] = {"blocked": True, "since": ev["ts"], "playbook": ev["playbook"]}
        elif ev["action"] == "unblock" and ev["status"] == "applied":
            state[ip] = {"blocked": False, "since": ev["ts"], "playbook": ev["playbook"]}
    return {ip: s for ip, s in state.items() if s["blocked"]}


class AuditLogWriteError(Exception):
    """Raised when soar_audit.log can't be written — most commonly because
    the file is owned by root (the SOAR playbooks write it via `sudo`)
    while the dashboard itself runs unprivileged. Callers should degrade
    gracefully rather than let this bubble up into a 500: the underlying
    iptables action may well have succeeded even if we can't log it."""


def append_event(event: dict, path: str | None = None):
    path = path or config.SOAR_AUDIT_LOG
    try:
        with open(path, "a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as e:
        raise AuditLogWriteError(
            f"Could not write to {path}: {e}. Likely fix: "
            f"`sudo chown autoforensic:autoforensic {path}` "
            f"(the SOAR playbooks create it as root via sudo)."
        ) from e


def unblock_ip(ip: str, actor: str = "dashboard") -> dict:
    """Best-effort undo: try removing a DROP rule for this IP from both
    INPUT and OUTPUT (we don't know from the audit log alone which chain
    the original block used), then record the *actual* outcome back to
    the audit log — not an assumed success. Requires the dashboard
    process to have passwordless sudo for iptables, same as the playbooks
    themselves — see README for setup. `sudo -n` is used deliberately so
    a missing sudoers rule fails fast with a clear stderr message instead
    of hanging (there's no terminal attached to type a password into)."""
    ipaddress.ip_address(ip)  # raises ValueError if not a valid IP

    results = _remote_iptables("unblock", ip)

    # A rule removal on EITHER chain counts as success — we don't know
    # which chain the original block used. If neither succeeded, this is
    # a real failure, not a completed unblock, and must not be logged as
    # one (active_blocks() relies on "unblock"+"applied" to clear a
    # block; a silently-assumed success here would make a still-blocked
    # IP disappear from the active-blocks list).
    succeeded = any(r["returncode"] == 0 for r in results)

    note = None
    if not succeeded:
        sudo_denied = any("password is required" in (r["stderr"] or "").lower() for r in results)
        note = (
            "sudo denied — passwordless sudo for iptables isn't configured for this process"
            if sudo_denied
            else "iptables rule removal failed on both chains (see raw event for stderr)"
        )

    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "playbook": "dashboard",
        "action": "unblock" if succeeded else "unblock_failed",
        "ip": ip,
        "actor": actor,
        "dry_run": False,
        "approved": succeeded,
        "iptables_results": results,
        "note": note,
    }
    try:
        append_event(event)
        event["logged"] = True
    except AuditLogWriteError as e:
        # The iptables attempt above already happened — don't lose that
        # outcome just because we couldn't also persist it. Surface the
        # write failure to the caller instead so it can be shown as a
        # clear banner rather than a 500.
        event["logged"] = False
        event["log_error"] = str(e)
    return event


def _log_best_effort(event: dict) -> dict:
    """Shared tail end for the manual actions below: append to the audit
    log, and if that write itself fails, don't lose the real-world outcome
    that already happened (iptables rule added, process killed) — flag it
    on the returned event instead of raising."""
    try:
        append_event(event)
        event["logged"] = True
    except AuditLogWriteError as e:
        event["logged"] = False
        event["log_error"] = str(e)
    return event


def block_ip(ip: str, actor: str = "dashboard") -> dict:
    """Manual, analyst-initiated block — unlike the playbooks (which each
    pick one direction based on their own detection pattern: SSH
    brute-force blocks inbound, reverse-shell blocks outbound), this
    blocks BOTH directions, since an analyst reaching for a manual block
    button is usually trying to fully quarantine a host rather than
    mirror one playbook's narrower rule. Skips a chain that's already
    dropping the IP instead of adding a duplicate rule."""
    ipaddress.ip_address(ip)

    results = _remote_iptables("block", ip)

    succeeded = all(r["returncode"] == 0 for r in results)
    note = "manually blocked (both directions) by analyst via dashboard"
    if not succeeded:
        sudo_denied = any("password is required" in (r["stderr"] or "").lower() for r in results)
        note = (
            "sudo denied — passwordless sudo for iptables isn't configured for this process"
            if sudo_denied
            else "iptables rule add failed on at least one chain (see raw event for stderr)"
        )

    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "playbook": "dashboard",
        "action": "blocked" if succeeded else "block_failed",
        "ip": ip,
        "actor": actor,
        "dry_run": False,
        "approved": succeeded,
        "iptables_results": results,
        "note": note,
    }
    return _log_best_effort(event)


def kill_process(pid: int, exec_id: str | None = None, actor: str = "dashboard") -> dict:
    """Kill a live process by PID — the same action soar_reverse_shell.py
    takes on a confirmed reverse-shell chain, but callable here for ANY
    process an analyst is looking at (incident graph, process entity
    page), not just ones matching that playbook's specific pattern.
    Re-checks /proc for a live cmdline before killing, the same PID-reuse
    guard the playbook uses — the pid recorded in the graph may no longer
    refer to the same process by the time this runs."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        raise ValueError("PID must be an integer.")
    if pid <= 1:
        raise ValueError("Refusing to act on an invalid or dangerously low PID.")

    import db
    expected = None
    if exec_id:
        try:
            row = db.run_one("MATCH (p:Process {exec_id: $e}) RETURN p.binary AS b", e=exec_id)
            expected = row.get("b") if isinstance(row, dict) else None
        except Exception:
            expected = None
    kill_args = ["kill", pid] + ([expected] if expected else [])
    cmdline = None
    outcome = None
    try:
        res = remote_action.run(*kill_args)
        succeeded = bool(res.get("ok"))
        stderr = res.get("detail") or ""
        cmdline = res.get("cmdline")
        outcome = res.get("outcome")
    except remote_action.RemoteActionError as e:
        succeeded = False
        stderr = str(e)

    if outcome == "skip_kill":
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "playbook": "dashboard",
            "action": "skip_kill",
            "pid": pid,
            "exec_id": exec_id,
            "actor": actor,
            "dry_run": False,
            "approved": False,
            "note": "process is not currently running on the sensor (no matching /proc entry) - nothing to kill",
        }
        return _log_best_effort(event)

    note = "manually killed by analyst via dashboard"
    if not succeeded:
        note = (
            "sudo denied — passwordless sudo for kill isn't configured for this process"
            if "password is required" in stderr.lower()
            else (stderr or "kill failed for an unknown reason")
        )

    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "playbook": "dashboard",
        "action": "killed" if succeeded else "kill_failed",
        "pid": pid,
        "exec_id": exec_id,
        "actor": actor,
        "dry_run": False,
        "approved": succeeded,
        "cmdline_at_kill": cmdline,
        "note": note,
    }
    return _log_best_effort(event)
