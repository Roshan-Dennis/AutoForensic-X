# AutoForensic-X SOC Console (v2)

A from-scratch FastAPI + Jinja2 + Chart.js + Cytoscape.js SOC dashboard,
replacing the earlier Flask/vis-network dashboard. Reads from the Neo4j
provenance graph and `soar_audit.log`, and gives an analyst real actions
to take from the browser instead of a read-only view:

- **Unblock / Block an IP** (`audit.unblock_ip` / `audit.block_ip`) — shells
  out to `iptables` the same way the SOAR playbooks do. A manual Block
  quarantines both directions (INPUT + OUTPUT), not tied to either
  playbook's narrower single-direction rule.
- **Kill a live process** (`audit.kill_process`) — same `/proc` PID-reuse
  guard as `soar_reverse_shell.py`, callable on any process, not just ones
  matching that playbook's detection pattern.
- **Trigger a real playbook run** (`playbooks.run_playbook`) — runs the
  actual `soar_ssh_bruteforce.py` / `soar_reverse_shell.py` scripts, dry-run
  or live, and shows their real stdout/stderr. Nothing about their
  corroboration or safety logic is reimplemented here — this shells out to
  the same code path you'd run by hand over SSH.
- **Incident triage workflow** (`notes.py`) — status (new / acknowledged /
  investigating / resolved / false positive) + analyst notes per incident,
  stored in a small local JSON file rather than mutated into Neo4j, so the
  Metrics page's timestamps stay untouched.

Every write path degrades gracefully instead of 500ing: if `sudo` denies a
command or the audit log can't be written, the dashboard shows a clear
banner explaining why rather than crashing.

## Pages

1. **Overview** (`/`) — KPI tiles (alerts by severity, MITRE techniques
   detected, SOAR actions taken, active blocks) + a Tetragon exec-event
   timeline chart.
2. **Incidents** (`/incidents`) — every Alert in the graph, plus
   *graph-detected* incidents Wazuh never alerted on (reverse shell,
   web-shell command execution — found by walking `PARENT_OF` chains for
   the same patterns `soar_reverse_shell.py` looks for). Filterable by
   severity / MITRE technique / source.
3. **Incident graph view** (`/incidents/{id}`) — the incident's actual
   process ancestry chain as a Cytoscape.js graph, root entry point
   highlighted green, the incident's focus process highlighted red.
4. **Entity pages** — `/entity/process/{exec_id}`, `/entity/ip/{ip}`,
   `/entity/uid/{uid}`: full lineage for a process, alerts + block
   history for an IP, all processes spawned by a uid.
5. **Hunting console** (`/hunting`) — three parameterized lookups: trace
   root cause from an alert ID, lineage from a PID, or all activity from
   an IP.
6. **Automation History** (`/automation`) — live-parsed `soar_audit.log`,
   normalized across both playbooks' differing JSON shapes, with Block /
   Unblock controls, and a **Run a Playbook** panel that triggers the real
   `soar_ssh_bruteforce.py` / `soar_reverse_shell.py` scripts (dry-run or
   live) and shows their actual output.
7. **MITRE Coverage** (`/mitre`) — a curated technique heatmap; the three
   currently-proven techniques (T1110, T1505.003, T1059.004/T1095) plus a
   few more for context, auto-cross-checked against live Alert data.
8. **Metrics** (`/metrics`) — MTTD/MTTR computed from real timestamps,
   honestly labeled (MTTD reflects correlation-pipeline latency, not
   ground-truth attacker dwell time — there's no independent "attack
   started" marker in the data to measure against).

## Schema this app actually depends on

Verified against `provenance-graph/schema.cypher` and the ingest code —
**not** assumed:

```
(:Host {name})
(:Process {exec_id, pid, uid, binary, arguments, start_time, exit_time, status, node_name})
(:Alert {alert_id, timestamp, rule_id, rule_description, rule_level, mitre_technique, mitre_tactic, srcip, agent_name, raw})
(:Remediation {...})   # shape differs per playbook — see audit.py

(:Process)-[:PARENT_OF]->(:Process)
(:Process)-[:RAN_ON]->(:Host)
(:Alert)-[:SEEN_ON]->(:Host)
(:Alert)-[:CORRELATES_WITH {method, confidence}]->(:Process)
```

There is **no** `severity` property on Alert (this app uses Wazuh's own
`rule_level`, bucketed: 12+ = critical, 9-11 = high, 5-8 = medium, else
low) and **no** `cwd`, `auid`, or `parent_exec_id` property on Process
(ancestry is only ever the `PARENT_OF` edge; `uid` is the numeric Linux
uid Tetragon captured).

## Running

```bash
cd ~/soc-dashboard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export NEO4J_URI=bolt://192.168.56.101:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=<your password>
export SOAR_AUDIT_LOG=~/provenance-graph/soar_audit.log

python3 main.py
```

Then browse to `http://192.168.56.101:8000`.

This replaces the old `~/dashboard` Flask app on port 5050 — stop that
process (`Ctrl+C` in its terminal, or `pkill -f dashboard/app.py`) once
this one is confirmed working, so the two aren't fighting over the same
Neo4j read load.

### Enabling the Unblock action

`audit.unblock_ip()` runs `sudo iptables -D INPUT/OUTPUT -s/-d <ip> -j
DROP`, the same command shape the playbooks themselves use. It needs the
same passwordless-sudo-for-iptables setup already required to run the
playbooks. Without it, the Unblock button will still log the attempt to
`soar_audit.log` but the underlying rule won't actually be removed —
check `sudo iptables -L -n` if an "unblocked" IP is still dropping
traffic.

## What's intentionally out of scope for v1

- No auth (matches the spec — local lab use only).
- The MITRE coverage catalog is a curated ~11-technique set that matches
  this lab's actual detections plus a few adjacent ones for narrative
  completeness, not the full ATT&CK matrix.
- Web-shell detection is a structural heuristic (nginx/php-fpm parent →
  shell child running `-c <cmd>`), same spirit as `soar_reverse_shell.py`
  but there's no dedicated SOAR playbook acting on it yet — it only shows
  up as a graph-detected incident, nothing is auto-remediated.
- Unblock is best-effort across both iptables chains since the audit log
  doesn't record which chain the original block used.
