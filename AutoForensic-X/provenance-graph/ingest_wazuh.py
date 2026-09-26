"""
ingest_wazuh.py — tails Wazuh's alerts.json and feeds each new alert into
the provenance graph, then immediately tries to correlate it against
recent process activity.

Wazuh appends one JSON object per line to alerts.json as alerts fire, so
this is a simple "tail -f" style follower rather than a real API client —
no Wazuh API credentials needed, and it works even before agent
enrollment (you're reading the manager's own alert log directly).
"""

import json
import logging
import sys
import time

import config
from graph_writer import GraphWriter

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [wazuh] %(levelname)s %(message)s"
)
log = logging.getLogger("ingest_wazuh")


def follow(path: str):
    """Generator that yields new lines appended to `path`, like `tail -f`.
    Starts at the end of the file so a restart doesn't replay history."""
    with open(path, "r") as f:
        f.seek(0, 2)  # seek to EOF
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield line


def main():
    writer = GraphWriter(
        config.NEO4J_URI, config.NEO4J_USER, config.NEO4J_PASSWORD, config.HOST_NAME
    )
    log.info("Tailing %s", config.WAZUH_ALERTS_JSON)

    try:
        for line in follow(config.WAZUH_ALERTS_JSON):
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Skipping unparseable line: %.200s", line)
                continue

            alert_id = writer.upsert_alert(alert)
            if not alert_id:
                continue

            edges = writer.correlate_alert_to_processes(
                alert_id, window_seconds=config.CORRELATION_WINDOW_SECONDS
            )
            rule_desc = alert.get("rule", {}).get("description", "")
            log.info(
                "alert %s (%s) -> correlated to %d process(es)",
                alert_id,
                rule_desc[:60],
                edges,
            )
    except KeyboardInterrupt:
        log.info("Stopping Wazuh ingest.")
    finally:
        writer.close()


if __name__ == "__main__":
    sys.exit(main())
