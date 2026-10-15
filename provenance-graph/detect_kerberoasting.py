"""
detect_kerberoasting.py - tails Wazuh's raw archives.log (not alerts.json) and
flags Kerberoasting attempts directly from the raw Windows Security 4769 event
stream.

Wazuh's default/custom ruleset never generates a native alert for a real
user's own Kerberos service-ticket request (confirmed via extensive testing
documented in build_progress.md), so alerts.json never contains this signal.
This script reads the same raw events ingest_wazuh.py cannot see, and
synthesizes an Alert node in Neo4j when the Kerberoasting signature is
present:
  - eventID 4769 (Kerberos service ticket requested)
  - ticketEncryptionType 0x17 (RC4 - the downgrade attackers force to get a
    crackable hash; legitimate modern tickets use 0x12/AES256)
  - serviceName does not end in '$' (excludes routine machine-account
    ticket requests)

This mirrors the "graph-detected, no Wazuh alert" pattern already used for
the web-shell and reverse-shell attacks in this project.
"""

import json
import logging
import sys
import time
import uuid

import config
from graph_writer import GraphWriter

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [kerberoast] %(levelname)s %(message)s"
)
log = logging.getLogger("detect_kerberoasting")

ARCHIVES_LOG = "/var/ossec/logs/archives/archives.log"


def follow(path: str):
    """Yields new lines appended to `path`, like `tail -f`. Starts at EOF
    so a restart doesn't replay history."""
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            yield line


def extract_json(line: str):
    """Wazuh's archives.log prefixes each JSON event with plain-text
    metadata (date, agent name, routing). Strip everything before the
    first '{' and parse the rest."""
    idx = line.find("{")
    if idx == -1:
        return None
    try:
        return json.loads(line[idx:])
    except json.JSONDecodeError:
        return None


def is_kerberoasting(event: dict) -> bool:
    win = event.get("win", {})
    system = win.get("system", {})
    eventdata = win.get("eventdata", {})

    if system.get("eventID") != "4769":
        return False
    if eventdata.get("ticketEncryptionType") != "0x17":
        return False
    service_name = eventdata.get("serviceName", "")
    return not service_name.endswith("$")


def build_synthetic_alert(event: dict) -> dict:
    win = event.get("win", {})
    system = win.get("system", {})
    eventdata = win.get("eventdata", {})

    alert_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_DNS,
            f"kerberoast-{system.get('eventRecordID')}-{system.get('systemTime')}",
        )
    )

    description = (
        "Possible Kerberoasting (graph-detected, no Wazuh alert): RC4 "
        f"(0x17) service ticket requested for account "
        f"{eventdata.get('serviceName')} by {eventdata.get('targetUserName')}"
    )

    return {
        "id": alert_id,
        "timestamp": system.get("systemTime"),
        "rule": {
            "id": "synthetic-kerberoast",
            "description": description,
            "level": 12,
            "mitre": {
                "id": ["T1558.003"],
                "tactic": ["Credential Access"],
            },
        },
        "agent": {"name": system.get("computer", config.HOST_NAME)},
        "data": {"srcip": eventdata.get("ipAddress")},
    }


def main():
    writer = GraphWriter(
        config.NEO4J_URI, config.NEO4J_USER, config.NEO4J_PASSWORD, config.HOST_NAME
    )
    log.info("Tailing %s for Kerberoasting signatures", ARCHIVES_LOG)

    try:
        for line in follow(ARCHIVES_LOG):
            event = extract_json(line)
            if not event:
                continue
            if not is_kerberoasting(event):
                continue

            alert = build_synthetic_alert(event)
            alert_id = writer.upsert_alert(alert)
            if not alert_id:
                continue

            edges = writer.correlate_alert_to_processes(
                alert_id, window_seconds=config.CORRELATION_WINDOW_SECONDS
            )
            log.info(
                "Kerberoasting detected: %s -> correlated to %d process(es)",
                alert["rule"]["description"][:80],
                edges,
            )
    except KeyboardInterrupt:
        log.info("Stopping Kerberoasting detector.")
    finally:
        writer.close()


if __name__ == "__main__":
    sys.exit(main())
