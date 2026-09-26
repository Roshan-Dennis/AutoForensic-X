"""
config.py — single place for connection settings.

Reads from environment variables with sane defaults for the Target VM,
so nothing sensitive (like the Neo4j password) needs to be hardcoded or
committed. Override with:  export NEO4J_PASSWORD=...   before running.
"""

import os

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme")

HOST_NAME = os.environ.get("AFX_HOST_NAME", "target")

TETRAGON_SOCKET = os.environ.get(
    "TETRAGON_SOCKET", "unix:///var/run/tetragon/tetragon.sock"
)
WAZUH_ALERTS_JSON = os.environ.get(
    "WAZUH_ALERTS_JSON", "/var/ossec/logs/alerts/alerts.json"
)

CORRELATION_WINDOW_SECONDS = int(os.environ.get("AFX_CORRELATION_WINDOW", "5"))
