"""
config.py — connection + path settings for the AutoForensic-X SOC console.

Env-var driven, same pattern as the ingest scripts and the old Flask
dashboard. Nothing sensitive hardcoded.
"""

import os

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme")

DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "8000"))

# Where the SOAR playbooks write their JSON-lines audit trail. Both
# playbooks are run from ~/provenance-graph, so that's the default.
SOAR_AUDIT_LOG = os.environ.get(
    "SOAR_AUDIT_LOG", os.path.expanduser("~/provenance-graph/soar_audit.log")
)

# Correlation window used by ingest_wazuh.py — kept here too so the
# metrics page can label what MTTD actually measures.
CORRELATION_WINDOW_SECONDS = int(os.environ.get("CORRELATION_WINDOW_SECONDS", "5"))

# Cap on how many processes a lineage/graph query will return before
# truncating — keeps a runaway ancestry walk from rendering a 5,000-node
# Cytoscape graph.
GRAPH_NODE_LIMIT = int(os.environ.get("GRAPH_NODE_LIMIT", "300"))

# iptables chains the two playbooks use — reverse_shell blocks the C2
# egress (OUTPUT), ssh_bruteforce blocks the inbound source (INPUT). The
# audit log doesn't record which chain per row, so "unblock" tries both,
# best-effort, and ignores whichever one doesn't match. A manual "Block"
# from the dashboard (not tied to a specific playbook's pattern) uses both
# chains too, to fully quarantine the IP rather than guess a direction.
IPTABLES_CHAINS = ("INPUT", "OUTPUT")

# Where the real SOAR playbook scripts live, and which Python interpreter
# to run them with — the "Trigger Playbook" action shells out to the
# actual soar_ssh_bruteforce.py / soar_reverse_shell.py rather than
# reimplementing their detection logic here. Both were set up in a
# dedicated venv (see build_progress.md), not the system python3.
PLAYBOOK_DIR = os.environ.get("PLAYBOOK_DIR", os.path.expanduser("~/provenance-graph"))
PLAYBOOK_PYTHON = os.environ.get("PLAYBOOK_PYTHON", os.path.expanduser("~/afx-venv/bin/python3"))

# Local (non-graph) state for the incident triage workflow — status +
# analyst notes. Deliberately NOT written into Neo4j: Alert/Process/
# Remediation nodes stay the untouched record of what the collectors and
# SOAR actually saw and did; triage state is a separate, dashboard-only
# concern.
INCIDENT_STATE_PATH = os.environ.get(
    "INCIDENT_STATE_PATH", os.path.expanduser("~/soc-dashboard/incident_status.json")
)
