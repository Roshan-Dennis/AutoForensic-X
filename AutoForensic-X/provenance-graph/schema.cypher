// AutoForensic-X provenance graph schema
// Run once against a fresh Neo4j database (cypher-shell -f schema.cypher)

// --- Constraints (also create the backing indexes) ---
CREATE CONSTRAINT process_exec_id IF NOT EXISTS
FOR (p:Process) REQUIRE p.exec_id IS UNIQUE;

CREATE CONSTRAINT alert_id IF NOT EXISTS
FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE;

CREATE CONSTRAINT host_name IF NOT EXISTS
FOR (h:Host) REQUIRE h.name IS UNIQUE;

// --- Extra lookup indexes (correlation runs a lot of time-range scans) ---
CREATE INDEX process_start_time IF NOT EXISTS
FOR (p:Process) ON (p.start_time);

CREATE INDEX process_pid IF NOT EXISTS
FOR (p:Process) ON (p.pid);

CREATE INDEX alert_time IF NOT EXISTS
FOR (a:Alert) ON (a.timestamp);

CREATE INDEX alert_srcip IF NOT EXISTS
FOR (a:Alert) ON (a.srcip);

/*
Node types
----------
(:Host {name})
(:Process {exec_id, pid, uid, binary, arguments, start_time, exit_time, status, node_name})
(:Alert {alert_id, timestamp, rule_id, rule_description, rule_level, mitre_technique, mitre_tactic, srcip, agent_name, raw})

Relationship types
-------------------
(:Process)-[:PARENT_OF]->(:Process)          -- process ancestry, from Tetragon's parent_exec_id
(:Process)-[:RAN_ON]->(:Host)
(:Alert)-[:SEEN_ON]->(:Host)
(:Alert)-[:CORRELATES_WITH {method, confidence}]->(:Process)   -- time-window join, see correlate.py
*/
