"""
graph_writer.py — thin wrapper around the Neo4j driver for AutoForensic-X.

Both ingest_tetragon.py and ingest_wazuh.py import this module rather than
talking to Neo4j directly, so the graph schema lives in exactly one place.
"""

import logging
from datetime import datetime
from typing import Optional

from dateutil import parser as dateutil_parser
from neo4j import GraphDatabase

log = logging.getLogger("graph_writer")

# Asset-criticality lookup by agent/host name, and the severity x
# criticality -> priority scoring formula. Mirrors the lookup that used
# to live only in soc-dashboard/generate_ticket.py (render-time-only,
# per the 2026-10-15 roadmap note) - computed here instead, once, at
# ingest time, and stored on the Alert node. Kept as its own small copy
# rather than a cross-directory import (provenance-graph and
# soc-dashboard are independent script directories with their own
# config.py each, same existing pattern).
ASSET_CRITICALITY = {
    "dc": "critical",
    "target": "standard",
    "kali": "low",
    "soc": "standard",
}

_SEVERITY_SCORE = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
_CRITICALITY_SCORE = {"critical": 3, "standard": 2, "low": 1}


def _severity_bucket(rule_level) -> str:
    """Same thresholds as soc-dashboard/queries.py's severity_bucket() -
    kept in sync by hand since the two directories don't share a package."""
    if rule_level is None:
        return "unknown"
    try:
        lvl = int(rule_level)
    except (TypeError, ValueError):
        return "unknown"
    if lvl >= 12:
        return "critical"
    if lvl >= 9:
        return "high"
    if lvl >= 5:
        return "medium"
    return "low"


def _compute_priority(rule_level, agent_name) -> tuple[str, str]:
    """Returns (priority, asset_criticality). Priority is severity x
    asset-criticality, composite score mapped to P1 (highest) - P4
    (lowest). Uses the alert's own reporting agent (agent_name), not the
    GraphWriter's own configured host_name - agent_name is the Wazuh
    manager's record of which VM the event actually came from, which is
    what asset criticality should be about."""
    severity = _severity_bucket(rule_level)
    criticality = ASSET_CRITICALITY.get((agent_name or "").lower(), "standard")
    score = _SEVERITY_SCORE[severity] * _CRITICALITY_SCORE[criticality]
    if score >= 9:
        priority = "P1"
    elif score >= 6:
        priority = "P2"
    elif score >= 3:
        priority = "P3"
    else:
        priority = "P4"
    return priority, criticality



def _parse_ts(ts: str) -> Optional[datetime]:
    """Best-effort ISO8601 parser — Tetragon and Wazuh both emit slightly
    different timestamp formats (nanosecond precision, offsets with no
    colon), which Python's built-in fromisoformat is too strict for. This
    dateutil parser handles nearly any real-world variant."""
    if not ts:
        return None
    try:
        return dateutil_parser.isoparse(ts)
    except (ValueError, OverflowError):
        log.warning("Could not parse timestamp: %r", ts)
        return None


class GraphWriter:
    def __init__(self, uri: str, user: str, password: str, host_name: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.host_name = host_name
        with self.driver.session() as session:
            session.run(
                "MERGE (h:Host {name: $name})", name=self.host_name
            )

    def close(self):
        self.driver.close()

    # ------------------------------------------------------------------
    # Tetragon side
    # ------------------------------------------------------------------

    def upsert_process(self, event: dict) -> Optional[str]:
        """Takes one Tetragon process_exec or process_exit event and
        upserts the Process node (+ its parent, + the PARENT_OF edge,
        + RAN_ON edge to this Host). Returns the exec_id written, or
        None if the event had no process payload."""

        proc = event.get("process")
        if not proc:
            return None

        exec_id = proc.get("exec_id")
        if not exec_id:
            return None

        is_exit = "status" in event  # process_exit events carry a status code
        start_time = _parse_ts(proc.get("start_time"))
        event_time = _parse_ts(event.get("time"))

        with self.driver.session() as session:
            session.run(
                """
                MERGE (p:Process {exec_id: $exec_id})
                ON CREATE SET
                    p.pid = $pid,
                    p.uid = $uid,
                    p.binary = $binary,
                    p.arguments = $arguments,
                    p.start_time = $start_time,
                    p.node_name = $node_name
                SET
                    p.exit_time = CASE WHEN $is_exit THEN $event_time ELSE p.exit_time END,
                    p.status = CASE WHEN $is_exit THEN $status ELSE p.status END
                MERGE (h:Host {name: $host_name})
                MERGE (p)-[:RAN_ON]->(h)
                """,
                exec_id=exec_id,
                pid=proc.get("pid"),
                uid=proc.get("uid"),
                binary=proc.get("binary"),
                arguments=proc.get("arguments", ""),
                start_time=start_time,
                node_name=event.get("node_name", self.host_name),
                is_exit=is_exit,
                event_time=event_time,
                status=event.get("status"),
                host_name=self.host_name,
            )

            parent = event.get("parent")
            if parent and parent.get("exec_id"):
                session.run(
                    """
                    MERGE (parent:Process {exec_id: $parent_exec_id})
                    ON CREATE SET parent.pid = $parent_pid, parent.binary = $parent_binary
                    MERGE (child:Process {exec_id: $exec_id})
                    MERGE (parent)-[:PARENT_OF]->(child)
                    """,
                    parent_exec_id=parent.get("exec_id"),
                    parent_pid=parent.get("pid"),
                    parent_binary=parent.get("binary"),
                    exec_id=exec_id,
                )

        return exec_id

    # ------------------------------------------------------------------
    # Wazuh side
    # ------------------------------------------------------------------

    def upsert_alert(self, alert: dict) -> Optional[str]:
        """Takes one parsed line from Wazuh's alerts.json and upserts
        an Alert node. Returns the alert_id written."""

        alert_id = alert.get("id")
        if not alert_id:
            return None

        rule = alert.get("rule", {})
        mitre = rule.get("mitre", {}) or {}
        agent = alert.get("agent", {}) or {}
        timestamp = _parse_ts(alert.get("timestamp"))
        priority, asset_criticality = _compute_priority(rule.get("level"), agent.get("name"))

        with self.driver.session() as session:
            session.run(
                """
                MERGE (a:Alert {alert_id: $alert_id})
                ON CREATE SET
                    a.timestamp = $timestamp,
                    a.rule_id = $rule_id,
                    a.rule_description = $rule_description,
                    a.rule_level = $rule_level,
                    a.mitre_technique = $mitre_technique,
                    a.mitre_tactic = $mitre_tactic,
                    a.srcip = $srcip,
                    a.agent_name = $agent_name,
                    a.priority = $priority,
                    a.asset_criticality = $asset_criticality
                MERGE (h:Host {name: $host_name})
                MERGE (a)-[:SEEN_ON]->(h)
                """,
                alert_id=alert_id,
                timestamp=timestamp,
                rule_id=rule.get("id"),
                rule_description=rule.get("description"),
                rule_level=rule.get("level"),
                mitre_technique=", ".join(mitre.get("id", [])) if mitre.get("id") else None,
                mitre_tactic=", ".join(mitre.get("tactic", [])) if mitre.get("tactic") else None,
                srcip=alert.get("data", {}).get("srcip"),
                agent_name=agent.get("name"),
            priority=priority,
            asset_criticality=asset_criticality,
                host_name=self.host_name,
            )

        return alert_id

    # ------------------------------------------------------------------
    # Correlation
    # ------------------------------------------------------------------

    def correlate_alert_to_processes(
        self, alert_id: str, window_seconds: int = 5
    ) -> int:
        """Links an Alert to any Process whose start_time falls within
        `window_seconds` of the alert's timestamp, on the same host.
        This is the V1 heuristic — a straightforward time-window join,
        not causal inference. Returns the number of edges created."""

        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (a:Alert {alert_id: $alert_id})-[:SEEN_ON]->(h:Host)
                MATCH (p:Process)-[:RAN_ON]->(h)
                WHERE p.start_time IS NOT NULL
                  AND a.timestamp IS NOT NULL
                  AND abs(duration.between(p.start_time, a.timestamp).seconds) <= $window
                  AND (
                p.node_name = 'dc'
                OR p.binary CONTAINS 'sshd' OR p.binary CONTAINS 'nginx' OR p.binary CONTAINS 'bash' OR p.binary CONTAINS 'sh'
              )
                MERGE (a)-[r:CORRELATES_WITH]->(p)
                ON CREATE SET r.method = 'time_window', r.confidence = 'low', r.window_seconds = $window
                RETURN count(r) AS edges
                """,
                alert_id=alert_id,
                window=window_seconds,
            )
            record = result.single()
            return record["edges"] if record else 0

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
