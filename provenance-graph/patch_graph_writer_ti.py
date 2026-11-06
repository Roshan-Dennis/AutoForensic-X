"""
patch_graph_writer_ti.py - ONE-TIME patch script, run once against the
live ~/provenance-graph/graph_writer.py, adding IoC-node support for
ti_enricher.py (Alert.srcip -> free-tier TI enrichment).

Appends four new GraphWriter methods (nothing existing is touched):
  - get_alert_srcips(): distinct non-null Alert.srcip values currently
    in the graph.
  - get_ioc_status(): existing IoC nodes' verdict/checked_at, so
    ti_enricher.py can skip anything already fresh or permanently
    'internal' without re-querying external APIs.
  - upsert_ioc(ip, data): writes one IoC node from ti_enricher.py's
    composite-verdict dict.
  - link_iocs_to_alerts(): cheap idempotent MERGE pass attaching
    INVOLVES_IOC edges from every Alert to the IoC node matching its
    srcip - covers alerts that arrive after their IP was already
    enriched, without re-checking anything.

Same safety discipline as the other patch scripts in this project:
exact-match-count assertion on the anchor, abort-with-no-changes on any
mismatch, timestamped backup + py_compile verification before the live
file is touched.

Usage (from ~/provenance-graph):
    python3 patch_graph_writer_ti.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

TARGET = pathlib.Path("graph_writer.py")

ANCHOR = '''        log.warning(
            "upsert_file_hash: no Process node found for exec_id=%s after "
            "%d retries - dropping (sha256=%s)",
            exec_id, retries, sha256,
        )
'''

NEW_METHODS = '''

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
'''


def _replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        print(
            f"FAILED: anchor matched {count} times (expected exactly 1) - "
            f"aborting with NO changes written.\\nLooking for:\\n{old!r}",
            file=sys.stderr,
        )
        sys.exit(1)
    return text.replace(old, new)


def main() -> None:
    if not TARGET.exists():
        print(f"FAILED: {TARGET} not found in the current directory.", file=sys.stderr)
        sys.exit(1)

    text = TARGET.read_text()
    original = text

    text = _replace_once(text, ANCHOR, ANCHOR + NEW_METHODS)

    if text == original:
        print("FAILED: no changes were actually produced - aborting.", file=sys.stderr)
        sys.exit(1)

    backup_path = TARGET.with_suffix(f".py.bak-{int(datetime.datetime.now().timestamp())}")
    backup_path.write_text(original)
    TARGET.write_text(text)

    try:
        py_compile.compile(str(TARGET), doraise=True)
    except py_compile.PyCompileError as e:
        print(f"FAILED: patched {TARGET} does not compile: {e}", file=sys.stderr)
        print(f"Backup is at {backup_path} - restore it if needed.", file=sys.stderr)
        sys.exit(1)

    print(f"OK: patched {TARGET}. Backup at {backup_path}. Compiles clean.")


if __name__ == "__main__":
    main()
