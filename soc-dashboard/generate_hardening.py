#!/usr/bin/env python3
"""
generate_hardening.py — takes an AutoForensic-X incident package (built by
incident_packager.py) and generates a hardening-recommendations hardening.md
via a local Ollama model (AutoForensic-X Ollama/Sigma phase, step 4: fourth
of the five per-incident outputs).

Like generate_narrative.py, this trusts the model for prose but not for
facts it could get wrong by inference: the prompt states the incident's
concrete specifics (entry-point binary, process chain, detection source)
as explicit instructions rather than leaving the model to read them out of
the raw JSON, per the lesson banked from the narrative generator's
Wazuh-rule-fired bug and the Sigma generator's string/list bugs - a small
model is unreliable at picking the right fact out of a JSON blob on its
own, and recommendations grounded in a hallucinated detail are actively
worse than no recommendation.

Usage (from inside soc-dashboard/, same venv as incident_packager.py):
    python3 generate_hardening.py <incident_id>

Writes <SAVE_DIR>/<incident_id>/hardening.md and prints it to stdout.
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

PROMPT_TEMPLATE = """You are a security engineer writing hardening \
recommendations for a report, aimed at the team that owns the affected \
system. Write in clear plain English, no markdown headers, no numbered \
preamble - just 3-6 short, specific, actionable recommendations as a \
markdown bullet list (using "- " for each bullet), ordered from most to \
least important.

CRITICAL FACTS - every recommendation must be grounded in these exact \
details from the real incident below, not generic best-practice advice \
for this attack category in the abstract. Do not recommend anything that \
contradicts these facts, and do not invent details (file paths, package \
names, config settings) that are not present in the incident data:
- This incident's "source" field is "{source}". If "wazuh", a native \
Wazuh rule already detects this activity - do not recommend "add \
detection for this", recommend reducing the underlying exposure instead. \
If "graph", no native Wazuh rule ever fired on this - one reasonable \
recommendation is deploying the Sigma rule already generated for this \
incident (do not describe writing a NEW detection rule from scratch, one \
already exists and is referenced separately in this report).
- Host OS: {host_os}
- MITRE technique: {mitre_technique} ({mitre_tactic})
- Entry point: {entry_point}
{process_chain_facts}
- Remediation already attempted for this incident: {remediation_summary}

Base every recommendation on what actually happened in THIS incident \
(the specific binary, the specific entry point, the specific gap that let \
it happen) rather than a textbook list of hardening steps for this attack \
category. If the incident data does not support a specific recommendation \
in some area, do not pad the list with generic filler - a shorter, \
grounded list is better than a longer generic one.

DO NOT invent an exact command, file permission value, sysctl parameter, \
config line, or similar low-level technical detail unless that exact \
detail is stated in the incident data below. You do not actually know \
the real file permissions, kernel parameters, or config of this system - \
inventing a plausible-sounding but unverified command (like a specific \
chmod value or sysctl setting) is worse than omitting it, because it \
states something false as fact. Instead, describe the concept or control \
category (e.g. "restrict the php-fpm process from spawning shell \
processes, for example via a seccomp or AppArmor profile" rather than a \
specific chmod command; "disable or restrict the bash /dev/tcp feature \
on this host" rather than inventing a sysctl parameter that does not \
actually control it - /dev/tcp is a bash shell builtin, not a kernel \
socket, so no sysctl setting restricts it). When unsure whether a \
specific technical detail is accurate, state the recommendation at the \
conceptual level instead of guessing at exact syntax.

Incident data (JSON), for context:
{incident_json}

Write only the bullet list, nothing else - no preamble, no "Here are the \
recommendations", no closing summary.
"""


def _process_chain_facts(package: dict) -> str:
    chain = package.get("root_cause_process_chain") or []
    if not chain:
        return "- No process chain available for this incident (alert-only detection).\n"
    lines = ["- Root-cause process chain (root first):"]
    for proc in chain:
        lines.append(
            f"  - binary: {proc.get('full_binary')!r}, arguments: {proc.get('arguments')!r}"
        )
    return "\n".join(lines) + "\n"


def _remediation_summary(package: dict) -> str:
    events = package.get("remediation_history") or []
    if not events:
        return "none recorded for this incident"
    parts = []
    for e in events:
        parts.append(f"{e.get('playbook')} -> {e.get('action')} ({e.get('status')})")
    return "; ".join(parts)


def generate_hardening(incident_id: str) -> str:
    package = build_package(incident_id)

    prompt = PROMPT_TEMPLATE.format(
        source=package.get("source"),
        host_os="linux" if package.get("root_cause_process_chain") else "unknown",
        mitre_technique=package.get("mitre_technique"),
        mitre_tactic=package.get("mitre_tactic"),
        entry_point=package.get("entry_point"),
        process_chain_facts=_process_chain_facts(package),
        remediation_summary=_remediation_summary(package),
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
    hardening = generate_hardening(incident_id)
    print(hardening)

    folder = SAVE_DIR / incident_id.replace("/", "_")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "hardening.md").write_text(hardening)
    print(f"\nSaved to {folder / 'hardening.md'}", file=sys.stderr)


if __name__ == "__main__":
    main()
