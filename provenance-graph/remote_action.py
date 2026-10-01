"""remote_action.py - AutoForensic-X: run a response action on the sensor host.

Sends `afx-response <action> <args> rid=<id>` to the Target through the Wazuh
manager API (active response), then waits for the Target's own result to come
back as a Wazuh alert (rule 100100) carrying the same request id. The return
value is what the Target actually did, not an assumption that it worked.
"""
import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.request
import uuid

API = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
AGENT_ID = os.environ.get("AFX_AGENT_ID", "001")
ALERTS = os.environ.get("WAZUH_ALERTS_JSON", "/var/ossec/logs/alerts/alerts.json")
WAIT = float(os.environ.get("AFX_RESULT_WAIT", "20"))

# The manager API listens on localhost with a self-signed certificate.
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_token = {"value": None, "at": 0.0}


class RemoteActionError(RuntimeError):
    """The request could not be sent, or no result came back in time."""


def _call(method, path, body=None, headers=None):
    req = urllib.request.Request(API + path, method=method, headers=headers or {})
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, context=_CTX, timeout=15) as r:
            return r.read().decode()
    except urllib.error.URLError as e:
        raise RemoteActionError(f"Wazuh API call failed: {e}") from e


def _get_token():
    if _token["value"] and time.time() - _token["at"] < 600:
        return _token["value"]
    if not API_PASSWORD:
        raise RemoteActionError("WAZUH_API_PASSWORD is not set")
    basic = base64.b64encode(f"{API_USER}:{API_PASSWORD}".encode()).decode()
    tok = _call("POST", "/security/user/authenticate?raw=true",
                headers={"Authorization": "Basic " + basic}).strip()
    _token.update(value=tok, at=time.time())
    return tok


def run(*args, wait=None):
    """run("block", ip) | run("unblock", ip) | run("kill", pid, expected_binary).

    Returns the result dict the Target wrote (with `ok` as a real bool), or
    raises RemoteActionError if the command could not be sent or no result
    arrived in time (outcome unknown).
    """
    wait = WAIT if wait is None else wait
    rid = uuid.uuid4().hex[:12]
    try:
        start = os.path.getsize(ALERTS)
    except OSError as e:
        raise RemoteActionError(f"cannot read {ALERTS}: {e}") from e

    body = {
        "command": "!afx-response",
        "arguments": [str(a) for a in args] + ["rid=" + rid],
        "alert": {"data": {"rid": rid}},
    }
    resp = json.loads(_call("PUT", f"/active-response?agents_list={AGENT_ID}", body,
                            {"Authorization": "Bearer " + _get_token()}))
    if resp.get("error") or resp.get("data", {}).get("total_failed_items"):
        raise RemoteActionError(f"Wazuh refused to send the command: {resp}")

    deadline = time.time() + wait
    buf = ""
    with open(ALERTS, "r", errors="replace") as f:
        f.seek(start)
        while time.time() < deadline:
            chunk = f.read()
            if chunk:
                buf += chunk
                *lines, buf = buf.split("\n")
                for line in lines:
                    if rid not in line:
                        continue
                    try:
                        alert = json.loads(line)
                    except ValueError:
                        continue
                    data = alert.get("data", {})
                    if data.get("rid") == rid:
                        data["ok"] = str(data.get("ok")).lower() == "true"
                        return data
            time.sleep(0.3)
    raise RemoteActionError(
        f"no result from the sensor within {wait:.0f}s (request {rid} was sent; outcome unknown)")
