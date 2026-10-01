"""
queries.py — every Cypher query the console runs, plus the small amount of
Python needed to shape results for the templates. Kept in one module so
the schema this app actually depends on is visible in one place.

Ground truth (from provenance-graph/schema.cypher, verified against the
real ingest code — NOT the same as the field names sometimes assumed
casually elsewhere):

  (:Host {name})
  (:Process {exec_id, pid, uid, binary, arguments, start_time, exit_time,
              status, node_name})
  (:Alert {alert_id, timestamp, rule_id, rule_description, rule_level,
            mitre_technique, mitre_tactic, srcip, agent_name, raw})
  (:Remediation {...})  -- shape differs per playbook, see audit.py's
                            docstring; linked via (:Remediation)-[:REMEDIATES]->(target)

  (:Process)-[:PARENT_OF]->(:Process)
  (:Process)-[:RAN_ON]->(:Host)
  (:Alert)-[:SEEN_ON]->(:Host)
  (:Alert)-[:CORRELATES_WITH {method, confidence}]->(:Process)

There is no stored `severity` property (rule_level is the closest real
analogue — Wazuh's own 0..15 rule level), no `cwd`/`auid`/`parent_exec_id`
property (ancestry is only ever the PARENT_OF edge, and `uid` is the
numeric Linux uid Tetragon captured, not an audit-subsystem auid).
"""

from __future__ import annotations

import db


def severity_bucket(rule_level) -> str:
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


# ---------------------------------------------------------------------------
# Overview

def kpi_counts() -> dict:
    open_alerts_by_severity = db.run(
        """
        MATCH (a:Alert)
        RETURN a.rule_level AS rule_level, count(*) AS count
        """
    )
    buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for row in open_alerts_by_severity:
        buckets[severity_bucket(row["rule_level"])] += row["count"]

    techniques = db.run_one(
        "MATCH (a:Alert) WHERE a.mitre_technique IS NOT NULL "
        "RETURN count(DISTINCT a.mitre_technique) AS c"
    )["c"]

    import audit

    events = audit.read_events()
    applied = [e for e in events if e["status"] == "applied"]
    blocks = audit.active_blocks(events)

    return {
        "severity": buckets,
        "techniques_detected": techniques,
        "soar_actions_taken": len(applied),
        "active_blocks": len(blocks),
    }


def exec_timeline() -> list[dict]:
    """Tetragon exec events over time, bucketed by minute, for the
    Overview timeline chart. Process.start_time is the exec timestamp.

    Bucketed in Python rather than with Cypher's datetime()/date()
    functions: start_time's exact stored type (native temporal vs. ISO
    string vs. epoch) isn't something to gamble a query's syntax on, and
    db.to_epoch() already normalizes all of those shapes elsewhere in
    this module."""
    from datetime import datetime, timezone

    rows = db.run("MATCH (p:Process) WHERE p.start_time IS NOT NULL RETURN p.start_time AS start_time")
    buckets: dict[str, int] = {}
    for r in rows:
        epoch = db.to_epoch(r["start_time"])
        if epoch is None:
            continue
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc).replace(second=0, microsecond=0)
        key = dt.isoformat()
        buckets[key] = buckets.get(key, 0) + 1

    out = []
    for key in sorted(buckets):
        dt = datetime.fromisoformat(key)
        out.append({"day": dt.date().isoformat(), "hour": dt.hour, "minute": dt.minute, "count": buckets[key]})
    return out


# ---------------------------------------------------------------------------
# Incidents (real, Wazuh-sourced)

def real_incidents() -> list[dict]:
    rows = db.run(
        """
        MATCH (a:Alert)
        OPTIONAL MATCH (a)-[:CORRELATES_WITH]->(p:Process)
        WITH a, count(DISTINCT p) AS corroborations
        RETURN a.alert_id AS alert_id, a.rule_description AS rule_description,
               a.rule_level AS rule_level, a.mitre_technique AS mitre_technique,
               a.mitre_tactic AS mitre_tactic, a.srcip AS srcip,
               a.timestamp AS timestamp, corroborations
        ORDER BY a.timestamp DESC
        LIMIT 300
        """
    )
    out = []
    for r in rows:
        out.append(
            {
                "id": f"alert-{r['alert_id']}",
                "source": "wazuh",
                "title": r["rule_description"] or "(no description)",
                "severity": severity_bucket(r["rule_level"]),
                "mitre_technique": r["mitre_technique"],
                "mitre_tactic": r["mitre_tactic"],
                "srcip": r["srcip"],
                "timestamp": r["timestamp"],
                "corroborations": r["corroborations"],
                "focus_exec_id": None,  # resolved lazily on incident-detail open
                "alert_id": r["alert_id"],
            }
        )
    return out


def _focus_exec_id_for_alert(alert_id: str) -> str | None:
    row = db.run_one(
        """
        MATCH (a:Alert {alert_id: $alert_id})-[:CORRELATES_WITH]->(p:Process)
        RETURN p.exec_id AS exec_id
        ORDER BY p.start_time ASC
        LIMIT 1
        """,
        alert_id=alert_id,
    )
    return row["exec_id"] if row else None


# ---------------------------------------------------------------------------
# Synthetic, graph-detected-but-not-Wazuh-alerted incidents

REVERSE_SHELL_QUERY = """
MATCH (entry:Process)-[:PARENT_OF*1..6]->(shell:Process)
WHERE shell.arguments IS NOT NULL AND shell.arguments CONTAINS '/dev/tcp'
  AND (entry.binary CONTAINS 'php-fpm' OR entry.binary CONTAINS 'nginx'
       OR entry.binary CONTAINS 'sshd')
RETURN DISTINCT shell.exec_id AS exec_id, shell.pid AS pid,
       shell.binary AS binary, shell.arguments AS arguments,
       shell.start_time AS start_time,
       entry.exec_id AS entry_exec_id, entry.binary AS entry_point
ORDER BY shell.start_time DESC
"""

WEB_SHELL_QUERY = """
MATCH (entry:Process)-[:PARENT_OF]->(shell:Process)
WHERE (entry.binary CONTAINS 'php-fpm' OR entry.binary CONTAINS 'nginx')
  AND (shell.binary CONTAINS '/sh' OR shell.binary CONTAINS '/bash')
  AND shell.arguments IS NOT NULL AND shell.arguments CONTAINS '-c'
  AND NOT shell.arguments CONTAINS '/dev/tcp'
RETURN DISTINCT shell.exec_id AS exec_id, shell.pid AS pid,
       shell.binary AS binary, shell.arguments AS arguments,
       shell.start_time AS start_time,
       entry.exec_id AS entry_exec_id, entry.binary AS entry_point
ORDER BY shell.start_time DESC
"""


def synthetic_incidents() -> list[dict]:
    out = []
    for row in db.run(REVERSE_SHELL_QUERY):
        out.append(
            {
                "id": f"graph-{row['exec_id']}",
                "source": "graph",
                "title": f"Reverse shell via {row['entry_point']} (no Wazuh alert)",
                "severity": "high",
                "mitre_technique": "T1059.004, T1095",
                "mitre_tactic": "Execution, Command and Control",
                "srcip": None,
                "timestamp": row["start_time"],
                "corroborations": 1,
                "focus_exec_id": row["exec_id"],
                "alert_id": None,
                "entry_point": row["entry_point"],
                "detail": row["arguments"],
            }
        )
    for row in db.run(WEB_SHELL_QUERY):
        out.append(
            {
                "id": f"graph-{row['exec_id']}",
                "source": "graph",
                "title": f"Web shell command execution via {row['entry_point']} (no Wazuh alert)",
                "severity": "high",
                "mitre_technique": "T1505.003",
                "mitre_tactic": "Persistence",
                "srcip": None,
                "timestamp": row["start_time"],
                "corroborations": 1,
                "focus_exec_id": row["exec_id"],
                "alert_id": None,
                "entry_point": row["entry_point"],
                "detail": row["arguments"],
            }
        )
    return out


def all_incidents(severity=None, technique=None, source=None) -> list[dict]:
    rows = real_incidents() + synthetic_incidents()
    rows.sort(key=lambda r: r["timestamp"] or "", reverse=True)
    if severity and severity != "all":
        rows = [r for r in rows if r["severity"] == severity]
    if technique and technique != "all":
        rows = [r for r in rows if r["mitre_technique"] and technique in r["mitre_technique"]]
    if source and source != "all":
        rows = [r for r in rows if r["source"] == source]
    return rows


def find_incident(incident_id: str) -> dict | None:
    if incident_id.startswith("alert-"):
        alert_id = incident_id[len("alert-") :]
        for r in real_incidents():
            if r["alert_id"] == alert_id:
                r["focus_exec_id"] = _focus_exec_id_for_alert(alert_id)
                return r
        return None
    if incident_id.startswith("graph-"):
        for r in synthetic_incidents():
            if r["id"] == incident_id:
                return r
        return None
    return None


# ---------------------------------------------------------------------------
# Lineage (incident graph view + process entity page)

LINEAGE_QUERY = """
MATCH (focus:Process {exec_id: $exec_id})
OPTIONAL MATCH anc = (root:Process)-[:PARENT_OF*0..15]->(focus)
  WHERE NOT ( ()-[:PARENT_OF]->(root) )
OPTIONAL MATCH desc = (focus)-[:PARENT_OF*0..15]->(leaf:Process)
  WHERE NOT ( (leaf)-[:PARENT_OF]->() )
RETURN focus, anc, desc
LIMIT 50
"""


def lineage_for(exec_id: str) -> dict:
    """Returns {"nodes": [...], "edges": [...], "focus_exec_id", "root_exec_id"}
    shaped for Cytoscape.js, covering full ancestor-to-descendant chain
    around one process."""
    with db._driver.session() as session:  # noqa: SLF001 - internal reuse
        result = session.run(LINEAGE_QUERY, exec_id=exec_id)
        nodes: dict[str, dict] = {}
        edges: set[tuple[str, str]] = set()
        root_exec_id = None

        def add_node(proc):
            nonlocal root_exec_id
            eid = proc.get("exec_id")
            if eid is None:
                return None
            if eid not in nodes:
                binary = (proc.get("binary") or "?").split("/")[-1]
                nodes[eid] = {
                    "exec_id": eid,
                    "pid": proc.get("pid"),
                    "uid": proc.get("uid"),
                    "binary": binary,
                    "full_binary": proc.get("binary"),
                    "arguments": proc.get("arguments"),
                    "start_time": proc.get("start_time"),
                    "status": proc.get("status"),
                }
            return eid

        def walk_path(path):
            if path is None:
                return
            nodes_in_path = path.nodes
            for i, node in enumerate(nodes_in_path):
                add_node(node)
                if i > 0:
                    prev_eid = nodes_in_path[i - 1].get("exec_id")
                    cur_eid = node.get("exec_id")
                    if prev_eid and cur_eid:
                        edges.add((prev_eid, cur_eid))

        for record in result:
            focus_eid = add_node(record["focus"])
            walk_path(record["anc"])
            walk_path(record["desc"])

    # root = any node in the set with no incoming edge captured here
    has_incoming = {b for (_, b) in edges}
    roots = [eid for eid in nodes if eid not in has_incoming]
    root_exec_id = roots[0] if roots else focus_eid

    return {
        "nodes": list(nodes.values()),
        "edges": [{"source": a, "target": b} for a, b in edges],
        "focus_exec_id": focus_eid,
        "root_exec_id": root_exec_id,
    }


def process_by_pid(pid: int) -> dict | None:
    return db.run_one(
        """
        MATCH (p:Process {pid: $pid})
        RETURN p.exec_id AS exec_id, p.pid AS pid, p.binary AS binary,
               p.arguments AS arguments, p.start_time AS start_time
        ORDER BY p.start_time DESC
        LIMIT 1
        """,
        pid=pid,
    )


# ---------------------------------------------------------------------------
# Entity pages

def ip_entity(ip: str) -> dict:
    alerts = db.run(
        """
        MATCH (a:Alert {srcip: $ip})
        RETURN a.alert_id AS alert_id, a.rule_description AS rule_description,
               a.rule_level AS rule_level, a.mitre_technique AS mitre_technique,
               a.timestamp AS timestamp
        ORDER BY a.timestamp DESC
        """,
        ip=ip,
    )
    for a in alerts:
        a["severity"] = severity_bucket(a["rule_level"])

    remediations = db.run(
        """
        MATCH (r:Remediation)
        WHERE r.ip = $ip
        RETURN r { .* } AS r
        ORDER BY r.applied_at DESC
        """,
        ip=ip,
    )
    remediations = [row["r"] for row in remediations]

    import audit

    blocks = audit.active_blocks()
    return {
        "ip": ip,
        "alerts": alerts,
        "remediations": remediations,
        "active_block": blocks.get(ip),
    }


def uid_entity(uid: str) -> dict:
    processes = db.run(
        """
        MATCH (p:Process {uid: $uid})
        RETURN p.exec_id AS exec_id, p.pid AS pid, p.binary AS binary,
               p.arguments AS arguments, p.start_time AS start_time,
               p.status AS status
        ORDER BY p.start_time DESC
        LIMIT 200
        """,
        uid=uid,
    )
    return {"uid": uid, "processes": processes}


# ---------------------------------------------------------------------------
# MITRE coverage map — small, curated catalog. Live-detected techniques are
# cross-checked against real Alert data; graph-only ones are hand-flagged
# since Wazuh never tags them.

MITRE_CATALOG = [
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "status": "detected-siem"},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "status": "detected-siem"},
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "status": "detected-siem"},
    {"id": "T1505.003", "name": "Web Shell", "tactic": "Persistence", "status": "detected-graph-only"},
    {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution", "status": "detected-graph-only"},
    {"id": "T1095", "name": "Non-Application Layer Protocol", "tactic": "Command and Control", "status": "detected-graph-only"},
    {"id": "T1548.003", "name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation", "status": "not-covered"},
    {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "status": "not-covered"},
    {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "status": "not-covered"},
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "status": "not-covered"},
    {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion", "status": "not-covered"},
]


def mitre_coverage() -> list[dict]:
    detected = {
        row["mitre_technique"]
        for row in db.run(
            "MATCH (a:Alert) WHERE a.mitre_technique IS NOT NULL RETURN DISTINCT a.mitre_technique AS mitre_technique"
        )
    }
    catalog = []
    for entry in MITRE_CATALOG:
        e = dict(entry)
        if e["status"] == "detected-siem" and not any(
            e["id"] in (d or "") for d in detected
        ):
            e["status"] = "not-covered"
        catalog.append(e)
    return catalog


# ---------------------------------------------------------------------------
# Metrics

def mttd_mttr() -> dict:
    """Mean time to detect / respond, computed honestly from the timestamps
    actually present in the graph:

      MTTD = Alert.timestamp - the correlated Process's start_time.
             This reflects Wazuh-alert-to-pipeline-correlation latency
             (bounded by the 5s correlation window), NOT true adversary
             dwell time — there's no ground-truth "attack started" marker
             in the data to measure against.

      MTTR = Remediation.applied_at - the thing it remediates
             (Alert.timestamp when REMEDIATES points at an Alert target,
             Process.start_time when it points at a Process — the
             reverse-shell playbook has no Alert in the loop at all).
    """
    import db as _db

    mttd_rows = db.run(
        """
        MATCH (a:Alert)-[:CORRELATES_WITH]->(p:Process)
        RETURN a.timestamp AS alert_ts, p.start_time AS proc_ts
        """
    )
    mttd_deltas = []
    for r in mttd_rows:
        a = _db.to_epoch(r["alert_ts"])
        p = _db.to_epoch(r["proc_ts"])
        if a is not None and p is not None and a >= p:
            mttd_deltas.append(a - p)

    mttr_rows = db.run(
        """
        MATCH (r:Remediation)-[:REMEDIATES]->(target)
        OPTIONAL MATCH (target)<-[:CORRELATES_WITH]-(a:Alert)
        RETURN r.applied_at AS applied_at, target.timestamp AS alert_ts,
               target.start_time AS proc_ts, labels(target) AS labels,
               a.timestamp AS via_alert_ts
        """
    )
    mttr_deltas = {"ssh_bruteforce": [], "reverse_shell": []}
    for r in mttr_rows:
        applied = _db.to_epoch(r["applied_at"])
        if applied is None:
            continue
        if "Alert" in (r["labels"] or []):
            base = _db.to_epoch(r["alert_ts"])
            bucket = "ssh_bruteforce"
        else:
            base = _db.to_epoch(r["via_alert_ts"]) or _db.to_epoch(r["proc_ts"])
            bucket = "reverse_shell"
        if base is not None and applied >= base:
            mttr_deltas[bucket].append(applied - base)

    def avg(lst):
        return round(sum(lst) / len(lst), 2) if lst else None

    all_mttr = mttr_deltas["ssh_bruteforce"] + mttr_deltas["reverse_shell"]
    return {
        "mttd_seconds_avg": avg(mttd_deltas),
        "mttd_sample_size": len(mttd_deltas),
        "mttr_seconds_avg": avg(all_mttr),
        "mttr_sample_size": len(all_mttr),
        "mttr_by_playbook": {
            "ssh_bruteforce": {"avg_seconds": avg(mttr_deltas["ssh_bruteforce"]), "n": len(mttr_deltas["ssh_bruteforce"])},
            "reverse_shell": {"avg_seconds": avg(mttr_deltas["reverse_shell"]), "n": len(mttr_deltas["reverse_shell"])},
        },
    }
