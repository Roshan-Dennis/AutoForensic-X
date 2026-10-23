#!/usr/bin/env python3
"""
afx-deploy-sigma-rule - root-owned helper, installed at
/usr/local/bin/afx-deploy-sigma-rule, invoked ONLY via:

    sudo -n /usr/local/bin/afx-deploy-sigma-rule <path-to-rule-fragment.xml>

by soc-dashboard/sigma_rules.py (running unprivileged as the autoforensic
user). This is the one piece of the Sigma approve/deploy loop that
actually needs root: /var/ossec/etc/rules/ is owned by wazuh:wazuh and a
manager reload needs root. Kept as small and narrowly scoped as possible -
it does exactly one thing (insert one validated <rule> fragment into
afx_rules.xml, then reload Wazuh) and refuses anything that doesn't look
exactly like that, same spirit as audit.py's refusal to reimplement
corroboration/safety logic outside its one job.

Install (one-time, as root):
    sudo cp afx-deploy-sigma-rule.py /usr/local/bin/afx-deploy-sigma-rule
    sudo chown root:root /usr/local/bin/afx-deploy-sigma-rule
    sudo chmod 755 /usr/local/bin/afx-deploy-sigma-rule

Then grant the dashboard's unprivileged user NOPASSWD rights to run only
this exact binary, nothing else:
    echo 'autoforensic ALL=(root) NOPASSWD: /usr/local/bin/afx-deploy-sigma-rule' \
        | sudo tee /etc/sudoers.d/afx-sigma-deploy
    sudo chmod 440 /etc/sudoers.d/afx-sigma-deploy
    sudo visudo -c   # verify the sudoers syntax before trusting it
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RULES_PATH = Path("/var/ossec/etc/rules/afx_rules.xml")
RULES_OWNER = "wazuh:wazuh"
RULES_MODE = 0o660


def fail(msg: str) -> None:
    print(f"afx-deploy-sigma-rule: FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: afx-deploy-sigma-rule <path-to-rule-fragment.xml>")

    fragment_path = Path(sys.argv[1])
    # Refuse anything outside /tmp - this is a root-run script, so it must
    # not trust an arbitrary caller-supplied path into somewhere sensitive.
    try:
        fragment_path.resolve().relative_to("/tmp")
    except ValueError:
        fail(f"refusing to read a fragment path outside /tmp: {fragment_path}")

    if not fragment_path.exists():
        fail(f"fragment file does not exist: {fragment_path}")

    fragment_text = fragment_path.read_text().strip()

    # Validate the fragment is exactly one well-formed <rule id="..."> block
    # - never trust it just because the caller claims it already validated.
    try:
        rule_el = ET.fromstring(fragment_text)
    except ET.ParseError as e:
        fail(f"fragment is not well-formed XML: {e}")
    if rule_el.tag != "rule":
        fail(f"fragment's root element is <{rule_el.tag}>, expected <rule>")
    rule_id = rule_el.get("id")
    if not rule_id or not rule_id.isdigit():
        fail(f"fragment's <rule> has no numeric id attribute: {rule_id!r}")

    if not RULES_PATH.exists():
        fail(f"{RULES_PATH} does not exist")
    original_text = RULES_PATH.read_text()

    # Refuse a duplicate id outright - Wazuh fails to load the whole rules
    # file (taking every AFX rule down, not just the new one) on an id
    # collision, so this has to be caught here rather than discovered at
    # reload time.
    if re.search(rf'<rule id="{re.escape(rule_id)}"', original_text):
        fail(f"rule id {rule_id} already present in {RULES_PATH} - refusing to add a duplicate")

    # Insert right before the closing </group> of the single top-level
    # <group name="afx,"> block (matches this file's existing structure -
    # see its own contents). A plain string insert, not a full
    # parse-and-reserialize, to avoid reformatting/losing the human-authored
    # comments and layout already in the file.
    marker = "</group>"
    idx = original_text.rfind(marker)
    if idx == -1:
        fail(f"could not find a closing {marker} tag in {RULES_PATH} to insert before")

    new_text = original_text[:idx] + fragment_text + "\n" + original_text[idx:]

    # Safety check: the whole resulting file must still parse as valid XML
    # before it's written anywhere near the real file.
    try:
        ET.fromstring(new_text)
    except ET.ParseError as e:
        fail(f"inserting this fragment would make {RULES_PATH} invalid XML: {e}")

    tmp_path = RULES_PATH.with_suffix(".xml.afxtmp")
    tmp_path.write_text(new_text)
    shutil.chown(tmp_path, *RULES_OWNER.split(":"))
    tmp_path.chmod(RULES_MODE)
    tmp_path.replace(RULES_PATH)  # atomic on the same filesystem

    reload = subprocess.run(
        ["/var/ossec/bin/wazuh-control", "restart"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if reload.returncode != 0:
        fail(
            f"rule {rule_id} was written to {RULES_PATH}, but the Wazuh "
            f"manager restart failed (rc={reload.returncode}): "
            f"{reload.stdout.strip()} {reload.stderr.strip()}"
        )

    print(f"OK: rule {rule_id} added to {RULES_PATH} and Wazuh manager restarted cleanly.")


if __name__ == "__main__":
    main()
