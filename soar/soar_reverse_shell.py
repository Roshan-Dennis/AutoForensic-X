"""
soar_reverse_shell.py — AutoForensic-X SOAR playbook: reverse-shell
detection and remediation.

Companion to soar_ssh_bruteforce.py, following the same safety template,
but for an attack Wazuh generates NO alert for (see build_progress.md's
"detection gap" finding). Since there's no SIEM alert to corroborate
against, this playbook draws its second signal from the provenance graph
itself: a raw `/dev/tcp/...` command is only acted on if it is a
Tetragon-confirmed DESCENDANT of a network-facing service (php-fpm, nginx,
sshd) — i.e. it didn't just appear from nowhere, it was spawned through a
real exploitation chain. A shell command someone typed by hand at a
terminal has no such ancestry and is correctly ignored.

Safety rules (same principles as soar_ssh_bruteforce.py):
  1. Corroboration — pattern match (the /dev/tcp/ string) AND confirmed
     kernel-level process ancestry from a network service. Neither signal
     alone is enough.
  2. Allowlist — the extracted destination IP is checked against the same
     ALLOWLIST as the SSH playbook before any block.
  3. Input validation — IP is parsed via ipaddress before any subprocess
     call; the PID is re-verified as a real running process with matching
     cmdline on THIS system before any kill, to guard against PID reuse
     (the pid recorded in the graph may no longer refer to the same
     process by the time this runs).
  4. Human-approval-gated — separate y/N confirmation for the process kill
     and for the IP block; --dry-run skips both and just reports findings.
  5. Full audit trail — soar_audit.log (same file as the SSH playbook) +
     a Remediation node in Neo4j linked to the killed process's exec_id
     and/or the blocked IP.

Run as root:
    sudo -E $(which python3) soar_reverse_shell.py --dry-run
    sudo -E $(which python3) soar_reverse_shell.py
    sudo -E $(which python3) soar_reverse_shell.py --unblock 192.168.56.104
"""

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

import config
from neo4j import GraphDatabase

ALLOWLIST = {
    "192.168.56.1",   # host-only network gateway / Windows host
    "127.0.0.1",
}

AUDIT_LOG_PATH = "soar_audit.log"
DEV_TCP_PATTERN = re.compile(r"/dev/tcp/([0-9.]+)/([0-9]+)")


def audit(event: dict):
    event["ts"] = datetime.now(timezone.utc).isoformat()
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"[audit] {event}")


def validate_ip(ip_str: str) -> str:
    return str(ipaddress.IPv4Address(ip_str))


def find_reverse_shell_candidates(driver):
    """Process nodes containing a /dev/tcp/ pattern that are confirmed
    descendants (via PARENT_OF, any depth up to 6 hops) of a network-facing
    service. Returns raw rows; IP/port extraction happens in Python."""
    query = """
    MATCH (svc:Process)-[:PARENT_OF*1..6]->(p:Process)
    WHERE p.arguments CONTAINS 'dev/tcp'
      AND (svc.binary CONTAINS 'php-fpm' OR svc.binary CONTAINS 'nginx' OR svc.binary CONTAINS 'sshd')
    RETURN DISTINCT p.exec_id AS exec_id, p.pid AS pid, p.binary AS binary,
           p.arguments AS arguments, svc.binary AS entry_point
    """
    with driver.session() as session:
        result = session.run(query)
        return [dict(record) for record in result]


def is_pid_still_this_process(pid: int, expected_arg_fragment: str) -> bool:
    """Re-check the LIVE system, not just the graph, before killing anything.
    PIDs get reused — a pid recorded hours ago may now belong to a totally
    different, innocent process. Refuse to kill unless /proc confirms it's
    still the same command."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().replace(b"\x00", b" ").decode(errors="replace")
    except FileNotFoundError:
        return False  # process no longer exists at all
    return expected_arg_fragment in cmdline


def kill_process(pid: int):
    subprocess.run(["sudo", "kill", "-9", str(pid)], check=True)


def is_already_blocked(ip: str) -> bool:
    result = subprocess.run(
        ["sudo", "iptables", "-C", "OUTPUT", "-d", ip, "-j", "DROP"],
        capture_output=True,
    )
    return result.returncode == 0


def block_ip(ip: str):
    subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)


def unblock_ip(ip: str):
    subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)


def write_remediation_node(driver, exec_id: str, ip: str, actions: list):
    with driver.session() as session:
        session.run(
            """
            MERGE (r:Remediation {exec_id: $exec_id, applied_at: datetime()})
            SET r.ip = $ip, r.actions = $actions, r.host_name = $host_name
            WITH r
            MATCH (p:Process {exec_id: $exec_id})
            MERGE (r)-[:REMEDIATES]->(p)
            """,
            exec_id=exec_id,
            ip=ip,
            actions=actions,
            host_name=config.HOST_NAME,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--unblock", metavar="IP", help="Remove a previously-added outbound DROP rule.")
    args = parser.parse_args()

    driver = GraphDatabase.driver(
        config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD)
    )

    if args.unblock:
        try:
            ip = validate_ip(args.unblock)
        except ValueError:
            print(f"Refusing: '{args.unblock}' is not a valid IPv4 address.")
            sys.exit(1)
        unblock_ip(ip)
        audit({"playbook": "reverse_shell", "action": "unblock", "ip": ip, "result": "removed"})
        print(f"Unblocked outbound traffic to {ip}.")
        driver.close()
        return

    candidates = find_reverse_shell_candidates(driver)
    if not candidates:
        print("No Tetragon-confirmed reverse-shell process chains found.")
        driver.close()
        return

    for c in candidates:
        match = DEV_TCP_PATTERN.search(c["arguments"] or "")
        if not match:
            continue
        ip_raw, port = match.group(1), match.group(2)
        pid = c["pid"]
        exec_id = c["exec_id"]

        print(f"\nCandidate: pid {pid} ({c['binary']}) — reverse shell to "
              f"{ip_raw}:{port}, descendant of {c['entry_point']} (Tetragon-confirmed ancestry).")

        actions_taken = []

        # --- Kill the live process ---
        if not is_pid_still_this_process(pid, "dev/tcp"):
            audit({"playbook": "reverse_shell", "action": "skip_kill", "pid": pid,
                   "reason": "pid_no_longer_matches_or_exited", "exec_id": exec_id})
            print(f"  Process pid {pid} is no longer running (or pid was reused) — skipping kill.")
        else:
            print(f"  PROPOSED ACTION: kill -9 pid {pid} (live-verified via /proc)")
            if args.dry_run:
                audit({"playbook": "reverse_shell", "action": "dry_run_proposed_kill",
                       "pid": pid, "exec_id": exec_id})
            else:
                answer = input(f"  Kill pid {pid}? This is destructive. [y/N] ").strip().lower()
                if answer == "y":
                    kill_process(pid)
                    actions_taken.append("kill_process")
                    audit({"playbook": "reverse_shell", "action": "killed", "pid": pid,
                           "exec_id": exec_id})
                    print(f"  Killed pid {pid}.")
                else:
                    audit({"playbook": "reverse_shell", "action": "skip_kill", "pid": pid,
                           "reason": "human_declined", "exec_id": exec_id})
                    print("  Skipped by operator.")

        # --- Block the listener IP ---
        try:
            ip = validate_ip(ip_raw)
        except ValueError:
            audit({"playbook": "reverse_shell", "action": "skip_block", "ip": ip_raw,
                   "reason": "invalid_ip_format"})
            print(f"  SKIP block — '{ip_raw}' is not a valid IPv4 address.")
            continue

        if ip in ALLOWLIST:
            audit({"playbook": "reverse_shell", "action": "skip_block", "ip": ip,
                   "reason": "allowlisted"})
            print(f"  SKIP block — {ip} is on the allowlist.")
        elif is_already_blocked(ip):
            audit({"playbook": "reverse_shell", "action": "skip_block", "ip": ip,
                   "reason": "already_blocked"})
            print(f"  SKIP block — outbound to {ip} already blocked.")
        else:
            print(f"  PROPOSED ACTION: iptables OUTPUT DROP rule for {ip} (the listener)")
            if args.dry_run:
                audit({"playbook": "reverse_shell", "action": "dry_run_proposed_block", "ip": ip})
            else:
                answer = input(f"  Block outbound traffic to {ip}? [y/N] ").strip().lower()
                if answer == "y":
                    block_ip(ip)
                    actions_taken.append("block_outbound_ip")
                    audit({"playbook": "reverse_shell", "action": "blocked", "ip": ip,
                           "exec_id": exec_id})
                    print(f"  Blocked outbound traffic to {ip}.")
                    print(f"  To undo: sudo -E $(which python3) soar_reverse_shell.py --unblock {ip}")
                else:
                    audit({"playbook": "reverse_shell", "action": "skip_block", "ip": ip,
                           "reason": "human_declined"})
                    print("  Skipped by operator.")

        if actions_taken and not args.dry_run:
            write_remediation_node(driver, exec_id, ip_raw, actions_taken)
            print(f"  Logged to Neo4j (Remediation node, actions: {actions_taken}).")

    driver.close()


if __name__ == "__main__":
    main()
