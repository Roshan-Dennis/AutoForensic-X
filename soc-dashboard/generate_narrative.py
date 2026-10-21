#!/usr/bin/env python3
"""
generate_narrative.py — takes an AutoForensic-X incident package (built by
incident_packager.py) and generates a plain-English narrative.md via a
local Ollama model, running on the Windows host and reachable over the
host-only network (AutoForensic-X Ollama/Sigma phase, step 2: first of the
five per-incident outputs).

Usage (from inside soc-dashboard/, same venv as incident_packager.py):
    python3 generate_narrative.py <incident_id>

Writes <SAVE_DIR>/<incident_id>/narrative.md and prints it to stdout.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request

from incident_packager import SAVE_DIR, build_package

# Model name read from config/env rather than hardcoded, per the 2026-10-16
# decision — switching to a bigger model later is then just one env var
# plus `ollama pull`, no code change.
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://192.168.56.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

PROMPT_TEMPLATE = """You are a SOC analyst writing the incident narrative \
section of a report, for a colleague who did not work this incident. \
Write in clear plain English, past tense, factual - no speculation beyond \
what the data supports, no markdown headers, 3-5 short paragraphs.

CRITICAL FACT - get this exactly right, it is the single most important \
detail in the report: this incident's "source" field is "{source}".
- If source is "wazuh": a native Wazuh detection rule fired on this \
activity. Say so plainly.
- If source is "graph": Wazuh's own ruleset did NOT fire on this \
activity - no native Wazuh alert was ever generated for it. This was \
caught ONLY by the custom graph-correlation/process-provenance layer, a \
gap native Wazuh missed entirely. Say this plainly and do not claim a \
Wazuh rule fired - that would be factually wrong and contradicts the \
data below.

Cover, in order: (1) what was detected and how, per the CRITICAL FACT \
above, (2) the root-cause process chain showing how the attacker got \
from entry point to the malicious action, (3) what remediation was \
attempted and whether it succeeded, (4) a one-line bottom-line risk \
assessment.

Incident data (JSON):
{incident_json}

Write only the narrative text, nothing else - no preamble, no "Here is \
the narrative", no markdown formatting.
"""


def generate_narrative(incident_id: str) -> str:
    package = build_package(incident_id)
    prompt = PROMPT_TEMPLATE.format(
        source=package.get("source"),
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
    narrative = generate_narrative(incident_id)
    print(narrative)

    folder = SAVE_DIR / incident_id.replace("/", "_")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "narrative.md").write_text(narrative)
    print(f"\nSaved to {folder / 'narrative.md'}", file=sys.stderr)


if __name__ == "__main__":
    main()
