// trace_root_cause.cypher — AutoForensic-X Phase 4: root-cause backward trace
//
// Given the graph populated by ingest_tetragon.py + ingest_wazuh.py, this walks
// backward from the most recent *security-relevant* alert (one with a MITRE
// ATT&CK technique attached — this excludes routine housekeeping alerts like
// package-manager or disk-space notices) through PARENT_OF process-ancestry
// edges to the true entry point: the oldest ancestor process with no captured
// parent.
//
// This is deliberately scoped as "trace the most recent tagged alert." For an
// investigation you'd usually swap the WHERE clause below to target a specific
// alert_id instead of always taking the latest one.

MATCH (a:Alert)-[:CORRELATES_WITH]->(p:Process)
WHERE a.mitre_technique IS NOT NULL
WITH a, p ORDER BY a.timestamp DESC LIMIT 1
MATCH path = (root:Process)-[:PARENT_OF*0..]->(p)
WHERE NOT (()-[:PARENT_OF]->(root))
RETURN a.rule_description AS alert,
       a.mitre_technique AS mitre,
       a.mitre_tactic AS tactic,
       [n IN nodes(path) | n.binary + ' (pid ' + toString(n.pid) + ')'] AS root_cause_chain,
       root.binary AS entry_point;


// --- Variant: trace a SPECIFIC alert by id, rather than "most recent tagged" ---
// MATCH (a:Alert {alert_id: $alert_id})-[:CORRELATES_WITH]->(p:Process)
// WITH a, p LIMIT 1
// MATCH path = (root:Process)-[:PARENT_OF*0..]->(p)
// WHERE NOT (()-[:PARENT_OF]->(root))
// RETURN a.rule_description AS alert,
//        a.mitre_technique AS mitre,
//        [n IN nodes(path) | n.binary + ' (pid ' + toString(n.pid) + ')'] AS root_cause_chain,
//        root.binary AS entry_point;


// --- Variant: trace FORWARD from a known entry-point process (e.g. nginx/php-fpm)
//     to see everything it spawned, downstream — useful for the web-shell chain
//     since Wazuh currently generates no MITRE-tagged alert for it. ---
// MATCH (entry:Process {binary: '/usr/sbin/php-fpm8.1'})
// MATCH path = (entry)-[:PARENT_OF*1..]->(descendant:Process)
// RETURN [n IN nodes(path) | n.binary + ' (pid ' + toString(n.pid) + ')'] AS chain
// ORDER BY length(path) DESC
// LIMIT 10;
