"""
db.py — Neo4j driver singleton + a couple of small helpers shared by every
router. Read-only: nothing in this app writes to the graph.
"""

from neo4j import GraphDatabase, Record
from neo4j.time import DateTime as Neo4jDateTime

import config

_driver = GraphDatabase.driver(
    config.NEO4J_URI, auth=(config.NEO4J_USER, config.NEO4J_PASSWORD)
)


def close():
    _driver.close()


def run(query: str, **params):
    """Run a read query, return a list of plain dicts (neo4j Node/Record
    objects converted so Jinja/JSON don't choke on them)."""
    with _driver.session() as session:
        return [_to_plain(r) for r in session.run(query, **params)]


def run_one(query: str, **params):
    rows = run(query, **params)
    return rows[0] if rows else None


def _to_plain(value):
    if isinstance(value, Record):
        return {k: _to_plain(v) for k, v in value.items()}
    if isinstance(value, Neo4jDateTime):
        return value.iso_format()
    if hasattr(value, "items") and hasattr(value, "labels"):
        # a neo4j Node
        d = dict(value)
        return {k: _to_plain(v) for k, v in d.items()} | {
            "_labels": list(value.labels),
            "_element_id": value.element_id,
        }
    if isinstance(value, dict):
        return {k: _to_plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_plain(v) for v in value]
    return value


def to_epoch(ts) -> float | None:
    """Best-effort: turn whatever timestamp shape Neo4j/Wazuh/Tetragon gave
    us into a unix epoch float, or None if it can't be parsed. Timestamps
    in this project show up as neo4j DateTime objects (already ISO strings
    by the time they reach here via _to_plain), plain ISO-8601 strings, or
    already-numeric epoch/millis values."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts) / 1000.0 if ts > 10_000_000_000 else float(ts)
    if isinstance(ts, str):
        from datetime import datetime
        from dateutil.parser import isoparse

        s = ts.strip()
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return isoparse(s).timestamp()
        except ValueError:
            return None
    return None
