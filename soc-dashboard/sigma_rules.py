#!/usr/bin/env python3
"""
sigma_rules.py - AutoForensic-X Sigma validate->approve->deploy loop
(Ollama/Sigma phase, step 6: human approval queue + deployment into Wazuh).

Scope and an honest limitation, stated up front: incidents whose Sigma rule
was generated for a source=="graph" detection (Tetragon->Neo4j correlation,
no native Wazuh rule involved at all) describe fields like Image,
ParentImage, CommandLine that Wazuh has NO DECODER for yet - the
Tetragon->Wazuh bridge is a separate, not-yet-built roadmap item. So this
module does NOT attempt field-level matching against decoded event data
(e.g. <field name="win.eventdata.image">). Instead it compiles each Sigma
selection into a pcre2 regex checked against Wazuh's always-present
"full_log" field (a substring/lookahead check, not a structured field
match). This means: (1) a deployed rule only fires once something actually
delivers matching log TEXT to Wazuh in the first place - for graph-only
incidents that still requires the Tetragon bridge to exist; the approval
queue, schema validation, rule generation, and deployment mechanics are all
real and working today regardless, (2) matching is coarser than a real
field match (no regard for which structured field held the value), which
is explicitly surfaced in both the generated rule's <description> and the
console UI rather than hidden.

Condition support is intentionally narrow, matching exactly what
generate_sigma.py's prompt asks the model to produce: a flat "and"/"or" of
named selections, optionally parenthesised, no "not". A condition using
"not" is refused rather than silently mis-converted - see _eval_condition.

State (queue status, assigned Wazuh rule IDs) lives in its own local JSON
file, same pattern as notes.py's incident_status.json: deliberately NOT in
Neo4j (the graph stays the untouched record of what collectors/SOAR saw),
and deliberately NOT inside incident_packager's package (this is
console-only triage state).

Actual deployment shells out to a root-owned helper script via
`sudo -n /usr/local/bin/afx-deploy-sigma-rule <fragment-path>` - same
"shell out, don't reimplement privileged logic here" rule audit.py's
docstring states for remote actions. Requires a one-time NOPASSWD sudoers
entry for that exact script (see the README note this module's docstring
links to in build_progress.md) - same actually-missing-right-now gap the
iptables block/unblock actions have, discovered while building this.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import yaml

import audit
from incident_packager import SAVE_DIR

SIGMA_STATE_PATH = os.environ.get(
    "SIGMA_STATE_PATH", os.path.expanduser("~/soc-dashboard/sigma_status.json")
)
AFX_RULES_PATH = os.environ.get("AFX_RULES_PATH", "/var/ossec/etc/rules/afx_rules.xml")
DEPLOY_SCRIPT = os.environ.get(
    "AFX_DEPLOY_SCRIPT", "/usr/local/bin/afx-deploy-sigma-rule"
)

# Wazuh custom rule IDs 100000-109999 are the user-defined range; afx_rules.xml
# already uses 100100-100102 for other things (see cat output), so start
# comfortably clear of those and anything else hand-added later.
RULE_ID_RANGE_START = 100200
RULE_ID_RANGE_END = 100999

LEVEL_MAP = {
    "informational": 3,
    "low": 5,
    "medium": 8,
    "high": 10,
    "critical": 12,
}

STATUSES = ("pending", "approved", "rejected")

_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# Local state (queue status / assigned rule id), same pattern as notes.py
# --------------------------------------------------------------------------

def _load() -> dict:
    if not os.path.exists(SIGMA_STATE_PATH):
        return {}
    try:
        with open(SIGMA_STATE_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(data: dict) -> None:
    directory = os.path.dirname(SIGMA_STATE_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp_path = SIGMA_STATE_PATH + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, SIGMA_STATE_PATH)


def get_state(incident_id: str) -> dict:
    return _load().get(incident_id, {"status": "pending", "history": []})


def all_state() -> dict:
    return _load()


def _next_rule_id(data: dict) -> int:
    # Avoid colliding with (a) ids this state file already handed out and
    # (b) ids already present in afx_rules.xml itself (in case a rule was
    # added by hand outside this tool). Belt and suspenders - a colliding
    # id would make Wazuh refuse to load the rules file at all, taking down
    # every other AFX rule with it, not just the new one.
    used = {
        entry["wazuh_rule_id"]
        for entry in data.values()
        if entry.get("wazuh_rule_id") is not None
    }
    if os.path.exists(AFX_RULES_PATH):
        try:
            text = Path(AFX_RULES_PATH).read_text()
            used.update(int(m) for m in re.findall(r'<rule id="(\d+)"', text))
        except OSError:
            pass
    for candidate in range(RULE_ID_RANGE_START, RULE_ID_RANGE_END + 1):
        if candidate not in used:
            return candidate
    raise RuntimeError("Sigma-generated rule ID range exhausted (100200-100999).")


# --------------------------------------------------------------------------
# Sigma YAML -> pcre2-against-full_log compilation
# --------------------------------------------------------------------------

class SigmaConversionError(Exception):
    """Raised when a Sigma rule can't be honestly converted - never produce
    a rule that doesn't actually enforce what the Sigma logic says."""


def _value_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _selection_lookaheads(selection: dict) -> list[str]:
    """One pcre2 lookahead per field:value(s) pair in a selection mapping.
    Every modifier (|contains, |endswith, |startswith, or none) collapses
    to the same thing here: "this literal text appears somewhere in
    full_log" - see the module docstring for why a stronger, modifier-exact
    check isn't honestly possible without a real decoder for these fields.
    Multiple values under one field key are OR'd (per the Sigma spec)."""
    lookaheads = []
    for raw_key, raw_value in selection.items():
        values = _value_list(raw_value)
        escaped = [re.escape(v) for v in values if v != ""]
        if not escaped:
            continue
        if len(escaped) == 1:
            lookaheads.append(f"(?=.*{escaped[0]})")
        else:
            alternation = "|".join(escaped)
            lookaheads.append(f"(?=.*(?:{alternation}))")
    if not lookaheads:
        raise SigmaConversionError(
            "A selection had no usable field:value pairs to match on."
        )
    return lookaheads


_TOKEN_RE = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_]+")


def _eval_condition(condition: str, selections: dict[str, list[str]]) -> str:
    """Compile a Sigma 'condition' string into a single pcre2 pattern.
    Supports: a bare selection name, "A and B", "A or B", parentheses, any
    nesting of those. Does NOT support "not" - raises rather than guess at
    a De Morgan rewrite that could silently invert the intended logic.

    Every parse_* function below returns a plain str (the compiled pattern
    for that subtree) - never a list - so string concatenation can't be
    mistaken for list concatenation and accidentally explode a pattern
    string into individual characters."""
    if re.search(r"\bnot\b", condition):
        raise SigmaConversionError(
            "This rule's condition uses 'not', which this converter "
            "deliberately does not support (see sigma_rules.py docstring) - "
            "deploy this one manually or extend _eval_condition first."
        )

    tokens = _TOKEN_RE.findall(condition)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def parse_atom() -> str:
        nonlocal pos
        tok = peek()
        if tok == "(":
            pos += 1
            inner = parse_or()
            if peek() != ")":
                raise SigmaConversionError(f"Unbalanced parentheses in condition: {condition!r}")
            pos += 1
            return inner
        if tok is None:
            raise SigmaConversionError(f"Could not parse condition: {condition!r}")
        pos += 1
        if tok not in selections:
            raise SigmaConversionError(
                f"Condition references unknown selection {tok!r} (have: {list(selections)})"
            )
        return "".join(selections[tok])

    def parse_and() -> str:
        nonlocal pos
        result = parse_atom()
        while peek() == "and":
            pos += 1
            result += parse_atom()
        return result

    def parse_or() -> str:
        nonlocal pos
        parts = [parse_and()]
        while peek() == "or":
            pos += 1
            parts.append(parse_and())
        if len(parts) == 1:
            return parts[0]
        return "(?:" + "|".join(parts) + ")"

    result = parse_or()
    if peek() is not None:
        raise SigmaConversionError(f"Unexpected trailing tokens in condition: {condition!r}")
    return result


def compile_sigma_to_pattern(detection: dict) -> str:
    condition = detection.get("condition")
    if not condition or not isinstance(condition, str):
        raise SigmaConversionError("detection.condition is missing or not a string.")

    selections: dict[str, list[str]] = {}
    for key, value in detection.items():
        if key == "condition":
            continue
        if not isinstance(value, dict):
            raise SigmaConversionError(
                f"Selection {key!r} is not a field:value mapping - refusing to "
                "guess at its meaning (this should have been caught by "
                "generate_sigma.py's pseudocode check already)."
            )
        selections[key] = _selection_lookaheads(value)

    if not selections:
        raise SigmaConversionError("No selections found in detection block.")

    return _eval_condition(condition, selections)


def _mitre_id(tags: list) -> str | None:
    for tag in tags or []:
        m = re.match(r"attack\.(t\d+(?:\.\d+)?)", str(tag), re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


def build_rule_xml(sigma_yaml_text: str, rule_id: int, incident_id: str) -> tuple[str, dict]:
    """Returns (xml_fragment, meta) where meta carries title/level/mitre_id
    for display, without re-parsing the XML back out later."""
    try:
        parsed = yaml.safe_load(sigma_yaml_text)
    except yaml.YAMLError as e:
        raise SigmaConversionError(f"Sigma YAML failed to parse: {e}") from e
    if not isinstance(parsed, dict):
        raise SigmaConversionError("Sigma YAML is not a mapping.")

    detection = parsed.get("detection")
    if not isinstance(detection, dict):
        raise SigmaConversionError("Sigma rule has no usable 'detection' mapping.")

    pattern = compile_sigma_to_pattern(detection)

    title = str(parsed.get("title") or "Untitled Sigma rule")
    level_word = str(parsed.get("level") or "medium").lower()
    level = LEVEL_MAP.get(level_word, 8)
    mitre_id = _mitre_id(parsed.get("tags"))
    description = (
        f"[AutoForensic-X / Sigma] {title} "
        f"(auto-generated from incident {incident_id}; matches as a "
        f"best-effort substring check against full_log, not a decoded "
        f"field - see sigma_rules.py)"
    )

    def esc(s: str) -> str:
        return (
            s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    lines = [
        f'  <rule id="{rule_id}" level="{level}">',
        f'    <field name="full_log" type="pcre2">{esc(pattern)}</field>',
        f"    <description>{esc(description)}</description>",
    ]
    if mitre_id:
        lines.append("    <mitre>")
        lines.append(f"      <id>{esc(mitre_id)}</id>")
        lines.append("    </mitre>")
    lines.append("    <group>afx,sigma_generated,</group>")
    lines.append("  </rule>")
    fragment = "\n".join(lines) + "\n"

    meta = {"title": title, "level": level, "mitre_id": mitre_id, "pattern": pattern}
    return fragment, meta


# --------------------------------------------------------------------------
# Approve / reject
# --------------------------------------------------------------------------

class DeployError(Exception):
    pass


def approve_and_deploy(incident_id: str, sigma_yaml_text: str, actor: str = "analyst") -> dict:
    """Compiles the rule, writes the fragment to a tmp file, shells out to
    the root-owned deploy helper via `sudo -n`, and records the outcome
    either way - a failed deploy still gets logged, same "don't lose the
    real-world outcome just because a step after it failed" principle as
    audit.py's _log_best_effort."""
    with _LOCK:
        data = _load()
        entry = data.get(incident_id, {"status": "pending", "history": []})

        try:
            if entry.get("wazuh_rule_id"):
                rule_id = entry["wazuh_rule_id"]
            else:
                rule_id = _next_rule_id(data)
            fragment, meta = build_rule_xml(sigma_yaml_text, rule_id, incident_id)
        except SigmaConversionError as e:
            entry["status"] = "pending"
            entry["history"].append(
                {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "action": "approve_failed",
                    "actor": actor,
                    "note": f"Could not convert rule: {e}",
                }
            )
            data[incident_id] = entry
            _save(data)
            raise DeployError(str(e)) from e

        tmp_path = f"/tmp/afx-sigma-{incident_id.replace('/', '_')}-{uuid.uuid4().hex[:8]}.xml"
        Path(tmp_path).write_text(fragment)

        try:
            proc = subprocess.run(
                ["sudo", "-n", DEPLOY_SCRIPT, tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            succeeded = proc.returncode == 0
            output = (proc.stdout or "") + (proc.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as e:
            succeeded = False
            output = str(e)
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

        entry["wazuh_rule_id"] = rule_id
        entry["title"] = meta["title"]
        entry["level"] = meta["level"]
        entry["mitre_id"] = meta["mitre_id"]
        entry["pattern"] = meta["pattern"]
        entry["status"] = "approved" if succeeded else "pending"
        entry["history"].append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": "deployed" if succeeded else "deploy_failed",
                "actor": actor,
                "rule_id": rule_id,
                "note": output.strip()[:2000],
            }
        )
        data[incident_id] = entry
        _save(data)

    # Audit-log trail, same shape/location as every other SOAR action, so
    # this shows up on the Automation History page alongside kills/blocks.
    try:
        audit.append_event(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "playbook": "dashboard",
                "action": "sigma_deployed" if succeeded else "sigma_deploy_failed",
                "incident_id": incident_id,
                "actor": actor,
                "dry_run": False,
                "approved": True,
                "note": f"Wazuh rule {rule_id}: {output.strip()[:500]}",
            }
        )
    except audit.AuditLogWriteError:
        pass  # best-effort, same as everywhere else in this app

    if not succeeded:
        raise DeployError(
            f"Deploy script failed (rule compiled fine, but writing it into "
            f"Wazuh did not succeed): {output.strip() or 'no output captured'}"
        )
    return entry


def reject(incident_id: str, actor: str = "analyst", note: str = "") -> dict:
    with _LOCK:
        data = _load()
        entry = data.get(incident_id, {"status": "pending", "history": []})
        entry["status"] = "rejected"
        entry["history"].append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": "rejected",
                "actor": actor,
                "note": note or None,
            }
        )
        data[incident_id] = entry
        _save(data)
        return entry


def reset_to_pending(incident_id: str, actor: str = "analyst") -> dict:
    """Lets an analyst re-open a rejected item for another look, without
    losing its history."""
    with _LOCK:
        data = _load()
        entry = data.get(incident_id, {"status": "pending", "history": []})
        entry["status"] = "pending"
        entry["history"].append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": "reopened",
                "actor": actor,
                "note": None,
            }
        )
        data[incident_id] = entry
        _save(data)
        return entry


# --------------------------------------------------------------------------
# Queue listing - scans SAVE_DIR for incidents with a validated Sigma rule
# --------------------------------------------------------------------------

def list_queue() -> list[dict]:
    """Every incident folder under incident_packager.SAVE_DIR that has a
    detection.sigma.yml + a PASSED detection.sigma.valid, joined with this
    module's local approval state. A FAILED-validation rule never shows up
    here at all - it was never accepted in the first place, so there's
    nothing to approve (see generate_sigma.py)."""
    save_dir = Path(SAVE_DIR)
    if not save_dir.exists():
        return []

    state = _load()
    rows = []
    for folder in sorted(save_dir.iterdir()):
        if not folder.is_dir():
            continue
        sigma_path = folder / "detection.sigma.yml"
        valid_path = folder / "detection.sigma.valid"
        if not sigma_path.exists() or not valid_path.exists():
            continue
        if valid_path.read_text().strip() != "true":
            continue
        incident_id = folder.name
        entry = state.get(incident_id, {"status": "pending", "history": []})
        rows.append(
            {
                "incident_id": incident_id,
                "sigma_text": sigma_path.read_text(),
                "status": entry.get("status", "pending"),
                "wazuh_rule_id": entry.get("wazuh_rule_id"),
                "title": entry.get("title"),
                "history": entry.get("history", []),
            }
        )
    return rows
