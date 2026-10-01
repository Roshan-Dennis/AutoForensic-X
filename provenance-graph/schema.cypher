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
