"""
ti_enricher.py - periodic batch TI enrichment for Alert.srcip values.

Run by afx-ti-enricher.timer (every 15 min, see afx-ti-enricher.service),
NOT inline with alert ingestion - per explicit user decision, keeping
network-call latency and TI rate-limit management out of ingest_wazuh.py's
and detect_kerberoasting.py's real-time hot path. One pass does:

  1. Collect every distinct Alert.srcip currently in the graph.
  2. Skip any IP that already has a fresh (< TTL_HOURS old) IoC node, or
     is permanently marked 'internal' (private/RFC1918 addresses never
     get re-checked - that status never changes).
  3. For everything else: private/loopback/link-local/reserved addresses
     are marked 'internal' with no API calls at all (lab caveat from
     roadmap.md: RFC1918 attack IPs never hit public TI feeds anyway -
     attack sims that want visible TI hits need to route C2 through a
     real flagged external IP). Public IPs get checked against four
     free-tier sources: AbuseIPDB, AlienVault OTX, VirusTotal, and
     abuse.ch's ThreatFox (GreyNoise explicitly out of scope - its
     Community API key requires a non-free-email address, which isn't
     available here; see build_progress.md).
  4. Each IP's results are folded into one composite verdict/confidence
     and written to a single IoC node via GraphWriter.upsert_ioc().
  5. Every IoC node is (re-)linked to every Alert sharing its value via
     GraphWriter.link_iocs_to_alerts() - cheap MERGE, covers alerts that
     arrived after their IP was already enriched.

A source that errors (bad/missing key, timeout, rate limit, network
blip) is recorded as unchecked rather than failing the whole run - one
flaky API should never block enrichment from the other three.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import requests

import config
from graph_writer import GraphWriter

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [ti_enricher] %(levelname)s %(message)s"
)
log = logging.getLogger("ti_enricher")

TTL_HOURS = 24
REQUEST_TIMEOUT = 10
INTER_REQUEST_DELAY = 1.0  # politeness gap between external API calls

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.environ.get("OTX_API_KEY")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY")


def is_public_ip(ip: str) -> bool:
    """False for private/loopback/link-local/reserved/multicast addresses
    (and for anything that doesn't even parse as an IP) - those never get
    sent to a public TI feed."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def check_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"ok": False, "error": "no API key configured"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        return {
            "ok": True,
            "flagged": score >= 25 and reports > 0,
            "score": score,
            "reports": reports,
            "detail": f"AbuseIPDB {score}/100 ({reports} reports)",
        }
    except requests.RequestException as e:
        log.warning("AbuseIPDB check failed for %s: %s", ip, e)
        return {"ok": False, "error": str(e)}


def check_otx(ip: str) -> dict:
    if not OTX_API_KEY:
        return {"ok": False, "error": "no API key configured"}
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        pulse_count = resp.json().get("pulse_info", {}).get("count", 0)
        return {
            "ok": True,
            "flagged": pulse_count > 0,
            "pulse_count": pulse_count,
            "detail": f"OTX ({pulse_count} pulses)",
        }
    except requests.RequestException as e:
        log.warning("OTX check failed for %s: %s", ip, e)
        return {"ok": False, "error": str(e)}


def check_virustotal(ip: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {"ok": False, "error": "no API key configured"}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        stats = (
            resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        return {
            "ok": True,
            "flagged": malicious > 0,
            "malicious": malicious,
            "suspicious": suspicious,
            "detail": f"VirusTotal {malicious} malicious/{suspicious} suspicious",
        }
    except requests.RequestException as e:
        log.warning("VirusTotal check failed for %s: %s", ip, e)
        return {"ok": False, "error": str(e)}


def check_threatfox(ip: str) -> dict:
    """abuse.ch now requires a free Auth-Key on every request (the
    2026-10-15 roadmap note calling these feeds 'unkeyed' is stale -
    verified live against threatfox.abuse.ch/api/ during this build).
    MalwareBazaar/URLhaus don't support IP lookups (hash-only /
    login-gated respectively) so only ThreatFox is used here."""
    if not ABUSECH_AUTH_KEY:
        return {"ok": False, "error": "no API key configured"}
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": ABUSECH_AUTH_KEY},
            json={"query": "search_ioc", "search_term": ip, "exact_match": True},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
        entries = payload.get("data") or []
        if payload.get("query_status") != "ok" or not entries:
            return {"ok": True, "flagged": False, "malware": None, "detail": "ThreatFox: no match"}
        top = entries[0]
        malware = top.get("malware_printable") or top.get("malware")
        confidence = top.get("confidence_level")
        return {
            "ok": True,
            "flagged": True,
            "malware": malware,
            "confidence_level": confidence,
            "detail": f"ThreatFox: {malware} (confidence {confidence})",
        }
    except requests.RequestException as e:
        log.warning("ThreatFox check failed for %s: %s", ip, e)
        return {"ok": False, "error": str(e)}


def build_composite(results: dict) -> dict:
    """results: {"abuseipdb": {...}, "otx": {...}, "virustotal": {...},
    "threatfox": {...}}, each as returned by the check_* functions above.
    Returns the flattened dict GraphWriter.upsert_ioc() writes onto the
    IoC node - corroboration across sources, not a single feed's label,
    per the roadmap's "Confirmed malicious per OTX (3 pulses) + AbuseIPDB
    95/100" design goal."""
    checked = [name for name, r in results.items() if r.get("ok")]
    flagged = [name for name, r in results.items() if r.get("ok") and r.get("flagged")]

    if len(flagged) >= 2:
        verdict, confidence = "malicious", min(100, 50 + 15 * len(flagged))
    elif len(flagged) == 1:
        verdict, confidence = "suspicious", 40
    elif checked:
        verdict, confidence = "clean", 10
    else:
        verdict, confidence = "unknown", 0

    if flagged:
        summary = "; ".join(results[name]["detail"] for name in flagged)
    elif checked:
        summary = f"No malicious indicators across {len(checked)} source(s) checked."
    else:
        summary = "All TI sources unreachable or unconfigured."

    ab = results.get("abuseipdb", {})
    otx = results.get("otx", {})
    vt = results.get("virustotal", {})
    tf = results.get("threatfox", {})

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "sources_checked": checked,
        "sources_flagged": flagged,
        "abuseipdb_score": ab.get("score"),
        "abuseipdb_reports": ab.get("reports"),
        "otx_pulse_count": otx.get("pulse_count"),
        "virustotal_malicious": vt.get("malicious"),
        "virustotal_suspicious": vt.get("suspicious"),
        "threatfox_malware": tf.get("malware"),
        "threatfox_confidence": tf.get("confidence_level"),
        "checked_at": datetime.now(timezone.utc),
    }


def enrich_ip(ip: str) -> dict:
    if not is_public_ip(ip):
        return {
            "verdict": "internal",
            "confidence": None,
            "summary": "Private/internal address - not checked against public TI feeds.",
            "sources_checked": [],
            "sources_flagged": [],
            "abuseipdb_score": None,
            "abuseipdb_reports": None,
            "otx_pulse_count": None,
            "virustotal_malicious": None,
            "virustotal_suspicious": None,
            "threatfox_malware": None,
            "threatfox_confidence": None,
            "checked_at": datetime.now(timezone.utc),
        }

    results = {}
    checks = (
        ("abuseipdb", check_abuseipdb),
        ("otx", check_otx),
        ("virustotal", check_virustotal),
        ("threatfox", check_threatfox),
    )
    for name, fn in checks:
        results[name] = fn(ip)
        time.sleep(INTER_REQUEST_DELAY)
    return build_composite(results)


def main() -> None:
    writer = GraphWriter(
        config.NEO4J_URI, config.NEO4J_USER, config.NEO4J_PASSWORD, config.HOST_NAME
    )
    try:
        srcips = writer.get_alert_srcips()
        existing = writer.get_ioc_status()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=TTL_HOURS)

        to_enrich = []
        for ip in srcips:
            entry = existing.get(ip)
            if entry is None:
                to_enrich.append(ip)
            elif entry["verdict"] != "internal" and (
                entry["checked_at"] is None or entry["checked_at"] < cutoff
            ):
                to_enrich.append(ip)

        log.info(
            "%d distinct alert srcip(s), %d need (re-)enrichment",
            len(srcips),
            len(to_enrich),
        )

        for ip in to_enrich:
            data = enrich_ip(ip)
            writer.upsert_ioc(ip, data)
            log.info(
                "%s -> %s (confidence=%s): %s", ip, data["verdict"], data["confidence"], data["summary"]
            )

        linked = writer.link_iocs_to_alerts()
        log.info("Linked/confirmed %d Alert-IoC edge(s)", linked)
    finally:
        writer.close()


if __name__ == "__main__":
    main()
