#!/usr/bin/env python3
"""
generate_sigma.py — takes an AutoForensic-X incident package (built by
incident_packager.py) and generates a Sigma detection rule via a local
Ollama model, then validates it against pySigma's schema before accepting
it (AutoForensic-X Ollama/Sigma phase, step 3: Sigma rule generation +
validation - second of the five per-incident outputs).

A 3B model's raw YAML is not trusted blindly: this script always
overwrites whatever "id" the model produced with a real uuid4 (LLMs are
unreliable at emitting schema-valid UUIDs), strips markdown code fences if
present, and runs the result through SigmaCollection.from_yaml(). Output
is saved either way, with a PASSED/FAILED validation note, so a failure is
visible rather than silently producing a broken rule file - matching the
roadmap's "pysigma schema check -> human approval queue" design, not full
autonomy.

Usage (from inside soc-dashboard/, same venv as incident_packager.py):
    python3 generate_sigma.py <incident_id>

Writes <SAVE_DIR>/<incident_id>/detection.sigma.yml and prints it.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
import uuid
from datetime import date

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from incident_packager import SAVE_DIR, build_package

# Model name read from config/env, same pattern as generate_narrative.py.
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://192.168.56.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

PROMPT_TEMPLATE = """You are a detection engineer writing a Sigma rule \
(https://sigmahq.io) to catch recurrences of a specific real incident. \
Output ONLY valid YAML, nothing else - no markdown code fences, no \
explanation before or after.

The YAML must have exactly these top-level keys: title (short, specific \
to this attack pattern - not generic), id (any placeholder UUID string - \
it will be replaced automatically, so its exact value does not matter), \
status (use "experimental"), description (1-2 sentences), references \
(a YAML list, can be empty: []), author (use "AutoForensic-X"), date \
(use exactly this value: "{today}"), tags (a YAML list including the \
MITRE technique id below, formatted like "attack.t1059.004"), logsource \
(a mapping), detection (a mapping - see the REQUIRED FORMAT below), \
falsepositives (a YAML list), level (one of: informational, low, \
medium, high, critical - pick based on the incident's severity below).

REQUIRED FORMAT for "detection" - follow this exact structure, do not \
write boolean expressions or pseudocode as a string value anywhere. \
Each selection is a YAML mapping of field names to the values to match, \
using a pipe modifier like |contains or |endswith on the field name \
itself (never inside the value). "condition" only ever names the \
selection(s) by key, joined with "and"/"or"/"not" - it never repeats \
field names or comparisons. Example of the CORRECT shape (illustrative \
values only, use your own fields/values for this incident):

detection:
  selection_parent:
    ParentImage|endswith: '/php-fpm8.1'
  selection_shell:
    Image|endswith: '/sh'
    CommandLine|contains: '/dev/tcp'
  condition: selection_parent and selection_shell

Do NOT write something like "selection: SomeField.contains('x') or \
OtherField.contains('y')" - that is not valid Sigma syntax, even though \
it may parse as YAML; a plain string under a selection key is \
interpreted as a literal full-text keyword search, not as logic, and \
would never match real field-structured log data.

CRITICAL FACTS - base the detection logic on these exact values from the \
real incident, not on a generic/textbook version of this attack type:
- MITRE technique: {mitre_technique}
- MITRE tactic: {mitre_tactic}
- Severity: {severity}
- Host OS: {host_os}
{process_chain_facts}
Use logsource category "process_creation" and product "linux" if this \
incident involves a Linux process chain (fields: Image for the full \
binary path, ParentImage for the parent process, CommandLine for the \
arguments). Only diverge from this if the incident is clearly not a \
Linux process-execution event (e.g. a Windows Kerberos ticket request \
has no process chain at all - use category "security", a product of \
"windows", and reference the real EventID/fields instead).

Write a detection that would generically catch this specific attack \
pattern recurring (e.g. matching the entry-point binary spawning a shell \
with the kind of suspicious argument seen below), not one so narrow it \
only matches this exact timestamp, and not so broad it matches unrelated \
legitimate activity.

Full incident data (JSON), for context:
{incident_json}
"""


def _process_chain_facts(package: dict) -> str:
    chain = package.get("root_cause_process_chain") or []
    if not chain:
        return "- No process chain available for this incident (alert-only detection, e.g. Windows auth event).\n"
    lines = ["- Root-cause process chain (root first):"]
    for proc in chain:
        lines.append(
            f"  - binary: {proc.get('full_binary')!r}, arguments: {proc.get('arguments')!r}"
        )
    return "\n".join(lines) + "\n"


def _find_pseudocode_selections(detection: dict) -> list[str]:
    """pySigma's schema check accepts a plain string under a selection key
    (it's valid Sigma - a literal full-text keyword search), so it does
    NOT catch the specific failure mode seen in testing: the model writing
    something like "Image.contains('/bin/sh') or CommandLine.contains(...)"
    as a string, which parses fine but would never match real
    field-structured logs. Flag any selection whose value looks like code
    (a bare string containing both parentheses and a dot-method call
    pattern) rather than a proper field:value mapping or list."""
    suspicious: list[str] = []
    if not isinstance(detection, dict):
        return suspicious
    code_pattern = re.compile(r"\w+\s*\.\s*\w+\s*\(")
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, str) and code_pattern.search(value):
            suspicious.append(key)
    return suspicious


def _strip_code_fence(text: str) -> str:
    text = text.strip()
    match = re.match(r"^```(?:ya?ml)?\s*\n(.*?)\n```$", text, re.DOTALL)
    return match.group(1).strip() if match else text


def _call_ollama(prompt: str) -> str:
    payload = json.dumps(
        {"model": OLLAMA_MODEL, "prompt": prompt, "stream": False}
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    return result.get("response", "").strip()


# A 3B model's YAML formatting is sampling noise as much as anything else -
# the same prompt can produce clean YAML on one call and an indentation
# mistake that breaks the parser on the next. Every failure mode below
# (unparseable YAML, a misplaced top-level key, a pseudocode selection, a
# pySigma schema rejection) is worth a fresh roll of the dice rather than
# giving up after a single unlucky generation.
MAX_ATTEMPTS = 3


def _attempt_generate(prompt: str) -> tuple[str, bool, str | None]:
    """One generate-and-validate attempt. Returns (yaml_text, valid, error)."""
    raw = _call_ollama(prompt)
    text = _strip_code_fence(raw)

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as e:
        return text, False, f"YAML parse error: {e}"

    if not isinstance(parsed, dict):
        return text, False, "Model output is not a YAML mapping"

    # A small model will sometimes indent one or more top-level keys (most
    # often logsource/detection/falsepositives/level) one level too deep,
    # nesting them as children of whatever key precedes them (commonly
    # "tags") instead of as siblings. The YAML still parses fine at this
    # point - it's structurally valid, just structured wrong - so this has
    # to be caught here with an explicit top-level-key check; left alone it
    # surfaces later as a cryptic parse/schema error from pySigma itself,
    # or as missing-field errors, with no indication of the real cause.
    required_top_level = (
        "title", "id", "status", "description", "references", "author",
        "date", "tags", "logsource", "detection", "falsepositives", "level",
    )
    missing = [k for k in required_top_level if k not in parsed]
    if missing:
        return (
            text,
            False,
            "Model output is missing required top-level key(s), most likely "
            "because they got indented under another key by mistake instead "
            f"of staying at the top level: {', '.join(missing)}",
        )

    # Always overwrite "id" with a real UUID - never trust the model's.
    parsed["id"] = str(uuid.uuid4())

    # Sigma requires tags/references/falsepositives to be lists, but a small
    # model will sometimes emit a bare string (e.g. "tags: attack.t1059.004"
    # instead of "tags: [attack.t1059.004]") even when explicitly told to use
    # a list - pySigma then rejects it outright. Normalize rather than trust
    # the model to always get the list syntax right.
    for list_key in ("tags", "references", "falsepositives"):
        value = parsed.get(list_key)
        if isinstance(value, str):
            parsed[list_key] = [value]
        elif value is None:
            parsed[list_key] = []

    text = yaml.dump(parsed, sort_keys=False, default_flow_style=False)

    # Catch the pseudocode-as-keyword-string failure mode before it ever
    # reaches pySigma, since schema validation alone accepts it silently.
    suspicious = _find_pseudocode_selections(parsed.get("detection", {}))
    if suspicious:
        return (
            text,
            False,
            "Selection(s) look like pseudocode/expressions rather than "
            f"field:value mappings, so they would match nothing in real "
            f"logs even though the YAML is schema-valid: {', '.join(suspicious)}",
        )

    try:
        SigmaCollection.from_yaml(text)
    except SigmaError as e:
        return text, False, str(e)

    return text, True, None


def generate_sigma(incident_id: str) -> tuple[str, bool, str | None]:
    """Returns (yaml_text, valid, error_message). Retries up to MAX_ATTEMPTS
    times on any failure - see the MAX_ATTEMPTS comment above."""
    package = build_package(incident_id)
    host_os = "linux" if package.get("root_cause_process_chain") else "unknown"

    prompt = PROMPT_TEMPLATE.format(
        today=date.today().isoformat(),
        mitre_technique=package.get("mitre_technique"),
        mitre_tactic=package.get("mitre_tactic"),
        severity=package.get("severity"),
        host_os=host_os,
        process_chain_facts=_process_chain_facts(package),
        incident_json=json.dumps(package, indent=2, default=str),
    )

    last_result: tuple[str, bool, str | None] = ("", False, "No attempts made")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        text, valid, error = _attempt_generate(prompt)
        if valid:
            return text, True, None
        last_result = (
            text,
            False,
            f"[attempt {attempt}/{MAX_ATTEMPTS}] {error}",
        )

    return last_result


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    incident_id = sys.argv[1]
    text, valid, error = generate_sigma(incident_id)

    print(text)
    if valid:
        print("\n[pySigma validation: PASSED]", file=sys.stderr)
    else:
        print(f"\n[pySigma validation: FAILED] {error}", file=sys.stderr)

    folder = SAVE_DIR / incident_id.replace("/", "_")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "detection.sigma.yml").write_text(text)
    (folder / "detection.sigma.valid").write_text(
        "true" if valid else f"false: {error}"
    )
    print(f"Saved to {folder / 'detection.sigma.yml'}", file=sys.stderr)


if __name__ == "__main__":
    main()
