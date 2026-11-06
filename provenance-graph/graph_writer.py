"""
graph_writer.py — thin wrapper around the Neo4j driver for AutoForensic-X.

Both ingest_tetragon.py and ingest_wazuh.py import this module rather than
talking to Neo4j directly, so the graph schema lives in exactly one place.
"""

import logging
import time
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


    # ------------------------------------------------------------------
    # Threat-intel enrichment (ti_enricher.py)
    # ------------------------------------------------------------------

    def get_alert_srcips(self) -> list[str]:
        """Returns every distinct non-null Alert.srcip currently in the
        graph - the candidate set ti_enricher.py decides whether to
        (re-)enrich."""
        with self.driver.session() as session:
            result = session.run(
                "MATCH (a:Alert) WHERE a.srcip IS NOT NULL "
                "RETURN DISTINCT a.srcip AS ip"
            )
            return [record["ip"] for record in result]

    def get_ioc_status(self) -> dict:
        """Returns {ip: {"verdict": str, "checked_at": datetime|None}}
        for every existing IoC node, so ti_enricher.py can skip anything
        already fresh (within its TTL) or permanently marked 'internal'
        without spending API quota re-checking it."""
        with self.driver.session() as session:
            result = session.run(
                "MATCH (i:IoC) RETURN i.value AS ip, i.verdict AS verdict, "
                "i.checked_at AS checked_at"
            )
            out = {}
            for record in result:
                checked_at = record["checked_at"]
                if checked_at is not None and hasattr(checked_at, "to_native"):
                    checked_at = checked_at.to_native()
                out[record["ip"]] = {"verdict": record["verdict"], "checked_at": checked_at}
            return out

    def upsert_ioc(self, ip: str, data: dict) -> None:
        """Writes one IoC node (currently IP-type only) from
        ti_enricher.py's composite-verdict dict - see that module's
        build_composite() / enrich_ip() for the shape of `data`."""
        with self.driver.session() as session:
            session.run(
                """
                MERGE (i:IoC {value: $ip})
                ON CREATE SET i.type = 'ip'
                SET
                    i.verdict = $verdict,
                    i.confidence = $confidence,
                    i.summary = $summary,
                    i.sources_checked = $sources_checked,
                    i.sources_flagged = $sources_flagged,
                    i.abuseipdb_score = $abuseipdb_score,
                    i.abuseipdb_reports = $abuseipdb_reports,
                    i.otx_pulse_count = $otx_pulse_count,
                    i.virustotal_malicious = $virustotal_malicious,
                    i.virustotal_suspicious = $virustotal_suspicious,
                    i.threatfox_malware = $threatfox_malware,
                    i.threatfox_confidence = $threatfox_confidence,
                    i.checked_at = $checked_at
                """,
                ip=ip,
                verdict=data.get("verdict"),
                confidence=data.get("confidence"),
                summary=data.get("summary"),
                sources_checked=data.get("sources_checked", []),
                sources_flagged=data.get("sources_flagged", []),
                abuseipdb_score=data.get("abuseipdb_score"),
                abuseipdb_reports=data.get("abuseipdb_reports"),
                otx_pulse_count=data.get("otx_pulse_count"),
                virustotal_malicious=data.get("virustotal_malicious"),
                virustotal_suspicious=data.get("virustotal_suspicious"),
                threatfox_malware=data.get("threatfox_malware"),
                threatfox_confidence=data.get("threatfox_confidence"),
                checked_at=data.get("checked_at"),
            )

    def link_iocs_to_alerts(self) -> int:
        """Idempotent MERGE pass: attaches an INVOLVES_IOC edge from
        every Alert to the IoC node matching its srcip. Safe/cheap to
        run on every ti_enricher.py pass regardless of what was just
        enriched - covers Alert nodes that arrived after their IP
        already had a fresh IoC node from a previous pass."""
        with self.driver.session() as session:
            result = session.run(
                """
                MATCH (i:IoC)
                MATCH (a:Alert {srcip: i.value})
                MERGE (a)-[:INVOLVES_IOC]->(i)
                RETURN count(*) AS linked
                """
            )
            record = result.single()
            return record["linked"] if record else 0
