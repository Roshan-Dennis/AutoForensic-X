"""
soar_ssh_bruteforce.py — AutoForensic-X minimal SOAR playbook: SSH brute-force
auto-remediation.

On-demand script (not a background service). Run it whenever you want to
check the provenance graph for brute-force patterns and remediate them.

Safety rules this playbook follows (per the project's SOAR design):
  1. Corroborate across >=2 independent telemetry sources before acting —
     requires BOTH a cluster of Wazuh auth-failure alerts from an IP AND at
     least one of those alerts correlated (CORRELATES_WITH) to a real sshd
     Process node captured by Tetragon. An alert with no kernel-level
     confirmation is not acted on.
  2. Hard-coded allowlist — an IP on the allowlist is NEVER blocked, no
     matter what the graph says. Edit ALLOWLIST below for your environment.
  3. Input validation — every IP is parsed with Python's `ipaddress` module
     before it ever reaches a subprocess/iptables call. Anything that isn't
     a real, valid, non-allowlisted IPv4 address is rejected outright.
  4. Human-approval-gated — blocking is a destructive/disruptive action, so
     this script always prints what it intends to do and asks for
     confirmation before touching iptables. Use --dry-run to skip execution
     entirely and just see what WOULD happen.
  5. Full audit trail — every decision (blocked, skipped, already-blocked)
     is appended to soar_audit.log as JSON lines, and a Remediation node is
     written into Neo4j linked to the triggering alert.
  6. One-click undo — `--unblock <ip>` removes a previously-added rule.

Run as root (or via sudo) because it needs to call iptables:
    sudo -E $(which python3) soar_ssh_bruteforce.py
    sudo -E $(which python3) soar_ssh_bruteforce.py --dry-run
    sudo -E $(which python3) soar_ssh_bruteforce.py --unblock 192.168.56.104
"""

import argparse
import ipaddress
import json
import subprocess
import sys
from datetime import datetime, timezone

import config
from neo4j import GraphDatabase

# ---------------------------------------------------------------------------
# SAFETY CONFIG — edit for your environment before running for real.
# ---------------------------------------------------------------------------

# IPs that must NEVER be auto-blocked, no matter what the graph shows.
# Defaults cover this lab's host-only gateway (the Windows host, which is
# Roshan's own management access point) and localhost. Add your own
# management/SSH source IP here if it differs.
ALLOWLIST = {
    "192.168.56.1",   # host-only network gateway / Windows host
    "127.0.0.1",
}

# How many distinct auth-failure alerts from one IP counts as "brute force."
FAILURE_THRESHOLD = 5

AUDIT_LOG_PATH = "soar_audit.log"


def audit(event: dict):
    """Append one JSON line to the audit log — the durable record of every
    decision this playbook made, whether or not it acted."""
    event["ts"] = datetime.now(timezone.utc).isoformat()
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"[audit] {event}")


def validate_ip(ip_str: str) -> str:
    """Parse and re-render the IP through Python's ipaddress module. Raises
    ValueError for anything malformed — this is what stands between graph
    data and a subprocess call, so nothing except a clean, well-formed
    address ever reaches iptables."""
    return str(ipaddress.IPv4Address(ip_str))


def find_bruteforce_candidates(driver):
    """Query the graph for source IPs with >= FAILURE_THRESHOLD auth-failure
    alerts, where at least one of those alerts is corroborated by a real
    sshd Process node (Tetragon-confirmed) — the two-source rule."""
    query = """
    MATCH (a:Alert)
    WHERE a.srcip IS NOT NULL
      AND toLower(a.rule_description) CONTAINS 'authentication failed'
    WITH a.srcip AS srcip, collect(a) AS alerts, count(a) AS failures
    WHERE failures >= $threshold
    UNWIND alerts AS a
    OPTIONAL MATCH (a)-[:CORRELATES_WITH]->(p:Process)
    WHERE p.binary CONTAINS 'sshd'
    WITH srcip, failures, collect(DISTINCT a.alert_id) AS alert_ids,
         count(p) AS sshd_confirmations
    RETURN srcip, failures, alert_ids, sshd_confirmations
    ORDER BY failures DESC
    """
    with driver.session() as session:
        result = session.run(query, threshold=FAILURE_THRESHOLD)
        return [dict(record) for record in result]


def is_already_blocked(ip: str) -> bool:
    result = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
    )
    return result.returncode == 0


def block_ip(ip: str):
    subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        check=True,
    )


def unblock_ip(ip: str):
    subprocess.run(
        ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        check=True,
    )


def write_remediation_node(driver, ip: str, alert_ids: list, action: str):
    with driver.session() as session:
        session.run(
            """
            MERGE (r:Remediation {ip: $ip, action: $action, applied_at: datetime()})
            SET r.alert_ids = $alert_ids, r.host_name = $host_name
            WITH r
            UNWIND $alert_ids AS aid
            MATCH (a:Alert {alert_id: aid})
            MERGE (r)-[:REMEDIATES]->(a)
            """,
            ip=ip,
            action=action,
            alert_ids=alert_ids,
            host_name=config.HOST_NAME,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                         help="Show what would happen, don't touch iptables or ask to confirm.")
    parser.add_argument("--unblock", metavar="IP",
                         help="Remove a previously-added DROP rule for this IP.")
    args = parser.parse_args()

    driver = GraphDatabase.driver(
        config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD)
    )

    # --- Undo path ---------------------------------------------------
    if args.unblock:
        try:
            ip = validate_ip(args.unblock)
        except ValueError:
            print(f"Refusing: '{args.unblock}' is not a valid IPv4 address.")
            sys.exit(1)
        unblock_ip(ip)
        audit({"action": "unblock", "ip": ip, "result": "removed"})
        print(f"Unblocked {ip}.")
        driver.close()
        return

    # --- Detection path ------------------------------------------------
    candidates = find_bruteforce_candidates(driver)
    if not candidates:
        print(f"No IPs with >= {FAILURE_THRESHOLD} corroborated auth-failure alerts found.")
        driver.close()
        return

    for c in candidates:
        ip_raw = c["srcip"]
        failures = c["failures"]
        alert_ids = c["alert_ids"]
        sshd_confirmations = c["sshd_confirmations"]

        print(f"\nCandidate: {ip_raw} — {failures} auth-failure alerts, "
              f"{sshd_confirmations} corroborated by Tetragon sshd process events.")

        try:
            ip = validate_ip(ip_raw)
        except ValueError:
            audit({"action": "skip", "ip": ip_raw, "reason": "invalid_ip_format"})
            print(f"  SKIP — '{ip_raw}' is not a valid IPv4 address, refusing to act on it.")
            continue

        if ip in ALLOWLIST:
            audit({"action": "skip", "ip": ip, "reason": "allowlisted"})
            print(f"  SKIP — {ip} is on the allowlist, will never be auto-blocked.")
            continue

        if sshd_confirmations == 0:
            audit({"action": "skip", "ip": ip, "reason": "no_tetragon_corroboration",
                   "alert_ids": alert_ids})
            print(f"  SKIP — no Tetragon-confirmed sshd process activity correlated "
                  f"to these alerts (single-source only, doesn't meet the 2-source rule).")
            continue

        if is_already_blocked(ip):
            audit({"action": "skip", "ip": ip, "reason": "already_blocked",
                   "alert_ids": alert_ids})
            print(f"  SKIP — {ip} already has an active DROP rule.")
            continue

        print(f"  PROPOSED ACTION: iptables DROP rule for {ip} "
              f"(based on {len(alert_ids)} alert(s): {alert_ids})")

        if args.dry_run:
            audit({"action": "dry_run_proposed", "ip": ip, "alert_ids": alert_ids})
            print("  --dry-run set: not executing, not asking for confirmation.")
            continue

        answer = input(f"  Block {ip}? This is a destructive action. [y/N] ").strip().lower()
        if answer != "y":
            audit({"action": "skip", "ip": ip, "reason": "human_declined",
                   "alert_ids": alert_ids})
            print("  Skipped by operator.")
            continue

        block_ip(ip)
        write_remediation_node(driver, ip, alert_ids, action="iptables_drop")
        audit({"action": "blocked", "ip": ip, "alert_ids": alert_ids,
               "failures": failures, "sshd_confirmations": sshd_confirmations})
        print(f"  BLOCKED {ip}. Logged to {AUDIT_LOG_PATH} and to Neo4j (Remediation node).")
        print(f"  To undo: sudo -E $(which python3) soar_ssh_bruteforce.py --unblock {ip}")

    driver.close()


if __name__ == "__main__":
    main()
