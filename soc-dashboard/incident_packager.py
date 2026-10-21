#!/usr/bin/env python3
"""
incident_packager.py — assembles one incident's full context (alert/graph
metadata + root-cause process chain + remediation history) into a single
JSON package, ready to hand to Ollama for narrative/Sigma/hardening/exec-
summary generation (AutoForensic-X Ollama/Sigma phase, step 1: data
assembly).

Lives alongside queries.py / db.py / audit.py / config.py (soc-dashboard/)
and reuses them via plain imports rather than duplicating any Cypher — the
root-cause walk in particular is just queries.lineage_for(), re-ordered
into a flat root-to-leaf list.

Usage (from inside soc-dashboard/):
    python3 incident_packager.py --list
    python3 incident_packager.py <incident_id> [--save]

incident_id looks like "alert-<alert_id>" (Wazuh-sourced) or
"graph-<exec_id>" (graph-detected, no native Wazuh alert) — same ids the
console itself uses (see queries.all_incidents()).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import audit
import db
import queries

# Final home per roadmap.md is /opt/afx/incidents/ (needs root to create).
# Using a home-dir location for now so this runs without sudo while we're
# still validating the pipeline; can be pointed at /opt/afx/incidents later
# in the same pass that wires up the console's "AI report" tab.
SAVE_DIR = Path.home() / "afx-incidents"


def _host_for_exec_id(exec_id: str | None) -> str | None:
    if not exec_id:
        return None
    row = db.run_one(
        """
        MATCH (p:Process {exec_id: $exec_id})-[:RAN_ON]->(h:Host)
        RETURN h.name AS host
        """,
        exec_id=exec_id,
    )
    return row["host"] if row else None


def _ordered_process_chain(lineage: dict | None) -> list[dict]:
    """lineage_for() returns an unordered node/edge set shaped for
    Cytoscape. Reorder it into a single root-to-leaf list by walking
    PARENT_OF edges from root_exec_id — what a narrative/report actually
    wants to read, rather than a flat node bag."""
    if not lineage or not lineage.get("nodes"):
        return []

    nodes_by_id = {n["exec_id"]: n for n in lineage["nodes"]}
    children: dict[str, list[str]] = {}
    for edge in lineage["edges"]:
        children.setdefault(edge["source"], []).append(edge["target"])

    root = lineage.get("root_exec_id") or lineage.get("focus_exec_id")
    ordered: list[dict] = []
    seen: set[str] = set()

    def walk(eid: str) -> None:
        if eid in seen or eid not in nodes_by_id:
            return
        seen.add(eid)
        ordered.append(nodes_by_id[eid])
        for child in sorted(
            children.get(eid, []),
            key=lambda c: nodes_by_id.get(c, {}).get("start_time") or "",
        ):
            walk(child)

    if root:
        walk(root)
    # Catch any nodes the walk missed (shouldn't normally happen, but a
    # disconnected sibling node must not silently vanish from the report).
    for eid, node in nodes_by_id.items():
        if eid not in seen:
            ordered.append(node)
    return ordered


def _remediation_history(incident: dict, process_chain: list[dict]) -> list[dict]:
    """Match SOAR audit-log events to this incident by IP (SSH-bruteforce
    style) or by exec_id appearing anywhere in the process chain
    (reverse-shell style) — the two keying schemes audit.py documents."""
    srcip = incident.get("srcip")
    chain_exec_ids = {p["exec_id"] for p in process_chain}

    events = audit.read_events()
    matched = [
        e
        for e in events
        if (srcip and e.get("ip") == srcip)
        or (e.get("exec_id") and e["exec_id"] in chain_exec_ids)
    ]
    # Drop the bulky raw/iptables_results blobs here — useful for
    # debugging the playbook itself, not for an incident narrative.
    return [
        {
            "ts": e.get("ts"),
            "playbook": e.get("playbook"),
            "action": e.get("action"),
            "action_summary": e.get("action_summary"),
            "status": e.get("status"),
            "evidence": e.get("evidence"),
        }
        for e in matched
    ]


def build_package(incident_id: str) -> dict:
    incident = queries.find_incident(incident_id)
    if incident is None:
        raise SystemExit(f"No incident found with id {incident_id!r}")

    focus_exec_id = incident.get("focus_exec_id")
    lineage = queries.lineage_for(focus_exec_id) if focus_exec_id else None
    process_chain = _ordered_process_chain(lineage)

    host = _host_for_exec_id(focus_exec_id) or incident.get("agent_name")
    remediation = _remediation_history(incident, process_chain)

    return {
        "incident_id": incident_id,
        "source": incident.get("source"),  # "wazuh" | "graph"
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "mitre_technique": incident.get("mitre_technique"),
        "mitre_tactic": incident.get("mitre_tactic"),
        "host": host,
        "srcip": incident.get("srcip"),
        "timestamp": incident.get("timestamp"),
        "corroborations": incident.get("corroborations"),
        "entry_point": incident.get("entry_point"),
        "raw_detail": incident.get("detail"),
        "root_cause_process_chain": process_chain,
        "remediation_history": remediation,
    }


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    if sys.argv[1] == "--list":
        for row in queries.all_incidents():
            print(f"{row['id']:38s} {row['severity']:10s} {row['title']}")
        sys.exit(0)

    incident_id = sys.argv[1]
    save = "--save" in sys.argv[2:]

    package = build_package(incident_id)
    text = json.dumps(package, indent=2, default=str)
    print(text)

    if save:
        folder = SAVE_DIR / incident_id.replace("/", "_")
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "incident.json").write_text(text)
        print(f"\nSaved to {folder / 'incident.json'}", file=sys.stderr)


if __name__ == "__main__":
    main()
