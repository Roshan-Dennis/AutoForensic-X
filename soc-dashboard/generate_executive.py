#!/usr/bin/env python3
"""
generate_executive.py — takes an AutoForensic-X incident package (built by
incident_packager.py) and generates a non-technical executive summary
executive_summary.md via a local Ollama model (AutoForensic-X Ollama/Sigma
phase, step 5: fifth and final of the five per-incident outputs).

Audience is a non-technical stakeholder (manager, exec), not a security
engineer, so this generator trusts the model even less for specifics than
the narrative/hardening generators: the prompt forces plain-English
business framing (what happened, how bad, is it handled, what's next) and
explicitly bans low-level technical detail creeping in, on top of the
already-banked lesson that a 3B model will confidently invent exact
technical specifics (commands, config values, permissions) it doesn't
actually know - see generate_hardening.py's banked fabrication bug. An
executive summary with an invented technical claim is just as bad as a
hardening recommendation with one, so the same explicit "don't invent
specifics, describe at the right level instead" instruction applies here,
adapted for a business audience: describe impact/risk/status in plain
terms rather than any technical mechanism at all.

Usage (from inside soc-dashboard/, same venv as incident_packager.py):
    python3 generate_executive.py <incident_id>

Writes <SAVE_DIR>/<incident_id>/executive_summary.md and prints it.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

from incident_packager import SAVE_DIR, build_package

# Model name read from config/env, same pattern as the other generators.
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://192.168.56.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

PROMPT_TEMPLATE = """You are a security analyst writing a short executive \
summary of a security incident for a non-technical audience (a manager or \
executive, not an engineer). Write 3-5 short sentences as plain prose, no \
markdown headers, no bullet list, no jargon, no technical field names, no \
acronyms without first explaining them in plain words. Cover, in this \
order: (1) what happened, described in terms a non-technical reader would \
understand (what kind of attack, roughly how it got in - not technical \
mechanism), (2) how serious it was (based on the severity/impact facts \
below - was anything actually compromised or was it caught/contained), \
(3) what has already been done about it, (4) what, if anything, still \
needs attention.

CRITICAL FACTS - every sentence must be consistent with these exact \
details from the real incident, not a generic description of this attack \
category in the abstract:
- Severity: {severity}
- MITRE technique: {mitre_technique} ({mitre_tactic}) - translate ONLY \
this specific technique/tactic pair to plain English. Base the wording on \
what {mitre_tactic} actually means (e.g. a tactic of "Execution" or \
"Command and Control" is about running commands or talking to an outside \
system, NOT a login attempt; a tactic of "Credential Access" or "Initial \
Access" IS about logins/credentials). Never state the MITRE ID or tactic \
name itself in the summary, and never describe this as a "login attempt" \
unless the tactic given is actually about credentials or authentication.
- Detection source: {source_plain}
- Remediation already attempted for this incident: {remediation_summary}
- Current status: {status}

DO NOT invent or guess at any technical specific not given above or in \
the incident data below - no exact commands, file names, IP addresses, \
usernames, permission values, or similar low-level detail, even if it \
would make the summary read more convincingly. An executive summary with \
a specific-sounding but wrong detail is worse than one that stays general. \
If you are not certain a detail is correct from the data given, describe \
it at the plain-impact level instead (e.g. "the attacker attempted to run \
commands on the server" rather than naming the exact command; "the issue \
was addressed" rather than naming an unverified specific fix).

DO NOT claim the attacker achieved persistence, installed a backdoor, \
exfiltrated data, or accessed sensitive information unless the facts \
above explicitly say so - a command-execution or command-and-control \
technique is not by itself proof that any of those things happened. If \
the facts only establish that the attacker ran commands or communicated \
with an external system, describe exactly that ("the attacker was able \
to run commands on the server" / "the server attempted to communicate \
with an external system"), not an escalated claim like "gained full \
control" or "installed a backdoor" that the facts do not support.

Full incident data (JSON), for context only - do not quote raw field \
names or JSON syntax in your summary, translate everything to plain \
English:
{incident_json}

Write only the summary paragraph, nothing else - no title, no "Executive \
Summary:" label, no closing remarks.
"""


def _source_plain(package: dict) -> str:
    source = package.get("source")
    if source == "wazuh":
        return "automatically detected and flagged by the monitoring system (Wazuh)"
    if source == "graph":
        return (
            "identified through process-activity correlation analysis, not by an "
            "automatic alert rule - no existing detection rule caught this at the time"
        )
    return f"source: {source}"


def _remediation_summary(package: dict) -> str:
    # Plain-English, not a raw "playbook -> action (status)" string: testing
    # showed the model misreading the playbook name ("dashboard", the name
    # of the AutoForensic-X console that issued the command) as if it were
    # the name of a process that got killed ("taking down a dashboard
    # process") - a fabricated-sounding but wrong technical claim. Spell
    # out what "dashboard" and "kill_failed" actually mean instead of
    # handing the model an ambiguous label to interpret on its own.
    events = package.get("remediation_history") or []
    if not events:
        return "none recorded for this incident"
    parts = []
    for e in events:
        action = e.get("action")
        status = e.get("status")
        if action == "kill_failed":
            parts.append(
                f"the security console attempted to automatically stop the "
                f"malicious process, which {status}"
            )
        else:
            parts.append(
                f"the security console attempted an automated response "
                f"(action: {action}), which {status}"
            )
    return "; ".join(parts)


def _status(package: dict) -> str:
    # Distinguish an actual known failure from a genuinely unconfirmed
    # outcome - collapsing "failed" into "not confirmed successful" throws
    # away information the model needs and was the root cause of a garbled,
    # self-contradicting sentence in testing ("addressed by attempting to
    # kill a failed process, but the outcome is not yet confirmed" - the
    # outcome WAS known, it was a failure).
    events = package.get("remediation_history") or []
    if any(e.get("status") == "success" for e in events):
        return "contained - remediation action completed successfully"
    if any(e.get("status") == "failed" for e in events):
        return (
            "remediation was attempted but failed (the automated response "
            "action did not succeed) - this incident is still open and may "
            "need manual follow-up"
        )
    if events:
        return "remediation attempted, outcome not yet confirmed either way"
    return "no remediation action recorded yet - still open"


def generate_executive(incident_id: str) -> str:
    package = build_package(incident_id)

    prompt = PROMPT_TEMPLATE.format(
        severity=package.get("severity"),
        mitre_technique=package.get("mitre_technique"),
        mitre_tactic=package.get("mitre_tactic"),
        source_plain=_source_plain(package),
        remediation_summary=_remediation_summary(package),
        status=_status(package),
        incident_json=json.dumps(package, indent=2, default=str),
    )

    payload = json.dumps(
        {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
    ).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        result = json.loads(resp.read().decode("utf-8"))

    return result.get("response", "").strip()


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    incident_id = sys.argv[1]
    summary = generate_executive(incident_id)
    print(summary)

    folder = SAVE_DIR / incident_id.replace("/", "_")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "executive_summary.md").write_text(summary)
    print(f"\nSaved to {folder / 'executive_summary.md'}", file=sys.stderr)


if __name__ == "__main__":
    main()
