# AutoForensic-X — Provenance Graph Engine (V1)

Ties Tetragon's kernel-level process events and Wazuh's log-based alerts
into a single Neo4j graph, so an incident can be traced back through
process ancestry to its entry point. This is roadmap phase 3
("Provenance Graph"), built on the Tetragon + Wazuh collectors validated
in Phase 1/2.

## Where this runs

Everything here runs **on the Target VM** — same box as Tetragon and
Wazuh — matching the "V1 single-host MVP" scope. Nothing here touches
the Windows host or the Kali VM.

## 1. Install Neo4j on the Target VM

```bash
# Add the Neo4j apt repo (Debian/Ubuntu)
curl -fsSL https://debian.neo4j.com/neotechnology.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/neo4j.gpg
echo "deb [signed-by=/usr/share/keyrings/neo4j.gpg] https://debian.neo4j.com stable 5" | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt update
sudo apt install -y neo4j

sudo systemctl enable neo4j --now
sudo systemctl status neo4j --no-pager
```

Set the initial password (Neo4j forces a change from the `neo4j`/`neo4j`
default on first login):

```bash
cypher-shell -u neo4j -p neo4j
# it will prompt you to set a new password — pick one and remember it
```

Neo4j's browser UI is on port 7474 — if you want to view the graph
visually from Windows, either forward that port or just SSH-tunnel it:

```powershell
# from Windows PowerShell
ssh -L 7474:localhost:7474 -L 7687:localhost:7687 autoforensic@<target-ip>
```

then open `http://localhost:7474` in a Windows browser.

## 2. Load the schema

```bash
cypher-shell -u neo4j -p <your-password> -f schema.cypher
```

## 3. Install Python dependencies

```bash
python3 -m venv ~/afx-venv
source ~/afx-venv/bin/activate
pip install -r requirements.txt
```

## 4. Copy these files to the Target VM

From Windows PowerShell, e.g.:

```powershell
scp -r .\provenance-graph autoforensic@<target-ip>:~/
```

## 5. Run both ingestion feeds

Two long-running processes, same pattern as watching Tetragon events by
hand — run each in its own terminal, or as systemd services once you're
happy with it:

```bash
source ~/afx-venv/bin/activate
export NEO4J_PASSWORD=<your-password>

# terminal A
sudo -E $(which python3) ingest_tetragon.py

# terminal B
sudo -E $(which python3) ingest_wazuh.py
```

(`sudo -E` because reading the Tetragon socket needs root, same as
`tetra getevents` did before — `-E` preserves the `NEO4J_PASSWORD` env
var through sudo.)

## 6. Generate a fresh incident and check the graph

Re-run the Hydra brute-force from Kali like before, then in
`cypher-shell` or the Neo4j browser:

```cypher
MATCH (a:Alert)-[:CORRELATES_WITH]->(p:Process)
RETURN a.rule_description, a.mitre_technique, p.binary, p.pid, p.start_time
ORDER BY a.timestamp DESC
LIMIT 25;
```

You should see your SSH brute-force alerts linked to the `sshd` process
nodes Tetragon captured — the same two data sources you validated
separately, now in one graph.

## What's deliberately NOT here yet

- **Root-cause backward trace** (roadmap phase 4) — walking the graph
  from an alert back to the true entry point. This phase only builds
  the graph; the trace query comes next once there's a richer graph to
  trace through (ideally after running the web-shell/reverse-shell
  runbooks too, since brute-force alone doesn't have much of a chain to
  walk).
- **Network events** — Suricata is V2 scope, so there's no network-layer
  node type yet.
- **Real causal inference** — the alert-to-process correlation is a
  timestamp-window join (`correlate_alert_to_processes` in
  `graph_writer.py`), not the graph-based causal reasoning research
  systems like ORTHRUS attempt. Honest V1 scope, matches the roadmap's
  positioning.
