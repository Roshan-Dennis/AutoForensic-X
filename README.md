# AutoForensic-X

**A free, self-hosted alternative to paid "agentic SOC" platforms** — combining SIEM detection, kernel-level provenance tracing, causal root-cause reconstruction, Active Directory/Kerberos attack telemetry, and safety-gated auto-remediation (SOAR) in one open architecture.

> Built as a hands-on home lab / portfolio project by [Roshan](https://github.com/) while working toward a SOC Analyst / cloud security role. Every capability below has been built *and validated against real, live attacks* run in an isolated VirtualBox lab — nothing here is theoretical.

---

## The problem this project is answering

Commercial "agentic SOC" platforms (Dropzone AI, Prophet Security, Radiant Security, Microsoft Security Copilot, and similar) combine detection, root-cause analysis, and auto-remediation — but they're all paid enterprise SaaS. No free, self-hosted tool today combines SIEM + SOAR + endpoint/kernel tracing + MITRE ATT&CK mapping + real causal provenance tracing in one package. Wazuh is the closest free building block, but on its own it still misses entire classes of attacks — this project exists specifically to show, with real evidence, where those gaps are and how to close them.

**AutoForensic-X's goal:** be the first free, self-hosted alternative to that category — with a genuine causal-graph root-cause reconstruction engine (not just log correlation), real Active Directory/Kerberos attack coverage, and safety-first auto-remediation, not just alerting.

---

## Architecture

The lab is split across four VMs, isolated from the analyst's own machine on a host-only network:

- **AutoForensic-SOC** — Wazuh manager/indexer/dashboard, Neo4j provenance graph, ingest pipeline, FastAPI SOC console, and SOAR playbooks. The brain of the operation; the only VM with the tools an attacker would actually want.
- **AutoForensic-Target** — Ubuntu sensor host: Tetragon (eBPF kernel process tracing) + Wazuh agent + a one-way, restricted SSH pull (no SOC credentials ever stored here) + Wazuh active-response for remote remediation. Intentionally vulnerable services (nginx/php-fpm upload endpoint) live here for attack simulation.
- **AutoForensic-DC** — Windows Server 2022 Active Directory domain controller (`autoforensic.local`), providing real Kerberos/AD telemetry (Sysmon + Advanced Audit Policy) for domain-attack simulation.
- **AutoForensic-Kali** — the attacker box, used to run real attack techniques (Hydra, web shell upload, reverse shells, Impacket/hashcat Kerberoasting) against Target and the DC.

A fifth, intentional boundary: **Ollama (local LLM)** is planned to run on the analyst's own Windows host (for GPU access), with read-only access *from* the lab — it will never be able to act back into it.

### The 7-layer design (per the full architecture spec)

| # | Layer | Status |
|---|-------|--------|
| 1 | **Collection** — Tetragon (eBPF) + Wazuh (SIEM/log analysis) on Linux; Wazuh agent + Sysmon + Advanced Audit Policy on the AD DC. Suricata (network IDS/IPS) is V2 scope | ✅ Done |
| 2 | **Correlation & Provenance Graph** — Neo4j, joins kernel process events to SIEM alerts, including synthetic alerts for detections Wazuh's own ruleset misses | ✅ Done |
| 3 | **Root-Cause Backward Trace** — walks the graph from an alert back to the true entry point | ✅ Done |
| 4 | **SOAR / Remediation** — tiered-autonomy playbooks, human-approval-gated for destructive actions, now executed remotely via Wazuh active-response | ✅ Done (2 of N playbooks) |
| 5 | **Deterministic MITRE ATT&CK Mapping** — via Wazuh's rule engine + custom rules + the graph-detection layer | ✅ Done |
| 6 | **Local LLM Documentation** — Ollama-generated incident narrative + hardening recommendations | ☐ Not started |
| 7 | **Dual Interface** — live monitoring pipeline separate from the SIEM case dashboard | ☐ Not started (V2 scope) |

---

## Where things stand right now

### ✅ Fully built and validated against real attacks

**Lab foundation** — Four VMs on an isolated host-only network: `AutoForensic-SOC`, `AutoForensic-Target` (Ubuntu 22.04.5 LTS), `AutoForensic-DC` (Windows Server 2022, AD domain controller for `autoforensic.local`), and `AutoForensic-Kali` (Kali Linux, attacker box) — all fully isolated from the analyst's own Windows host.

**SOC/Target split** — Detection, correlation, and remediation tooling (Wazuh manager, Neo4j, the console, SOAR) run entirely on a dedicated SOC VM. The monitored/attacked host (Target) carries only sensors and a one-way, restricted log pull — it holds no credentials or tooling an attacker could pivot with. Remediation actions reach Target through Wazuh's own active-response channel, not direct SSH/sudo from the SOC.

**Collectors** — [Tetragon](https://github.com/cilium/tetragon) (eBPF-based kernel process tracing, CNCF project) and [Wazuh](https://wazuh.com/) (SIEM/log analysis), both running as systemd services, validated with live process/alert capture on both the Linux Target and the Windows DC (via Sysmon + Wazuh agent).

**Active Directory domain** — `autoforensic.local` (NetBIOS `AUTOFORENSIC`), a real AD forest with a domain controller, a domain-joined Linux client (via SSSD/Kerberos, not just a Windows client), Advanced Audit Policy and Sysmon tuned for Kerberos/AD-relevant telemetry.

**Provenance Graph Engine** (`/provenance-graph`) — A Neo4j graph database that ingests Tetragon process events and Wazuh alerts in real time, correlating them via a timestamp-window join. Also ingests *synthetic* alerts for attacks Wazuh's own ruleset misses entirely (see Kerberoasting, below) — same schema, clearly labeled "graph-detected, no Wazuh alert."

**Root-Cause Backward Trace** (`trace_root_cause.cypher`) — Given any alert or process, walks backward through the kernel-confirmed process-ancestry chain to the true entry point — turning "a login happened" into "here's the exact chain that caused it."

**SOAR / Auto-Remediation** (`/soar`) — Two playbooks so far, both following the same safety template (2-source corroboration required before acting, hard-coded allowlist, input validation before any subprocess call, human-approval-gated confirmation for every destructive action, full JSON audit trail, a `Remediation` node written back into the graph for traceability, remote execution via Wazuh active-response):

- `soar_ssh_bruteforce.py` — detects a source IP with a cluster of Wazuh auth-failure alerts *and* a Tetragon-confirmed `sshd` process behind them, proposes an `iptables` block, and — after operator approval — blocks it. Verified end-to-end: block took effect (SSH connections hung/dropped), then `--unblock` cleanly restored access.
- `soar_reverse_shell.py` — detects a live `/dev/tcp/...` reverse-shell command that is a Tetragon-confirmed descendant of a network-facing service, then — after approval — kills the process (re-verifying against the live system's `/proc` first, to guard against PID reuse) and blocks the attacker's listener IP. **Verified against a genuinely live attacker session**: killed an actual open reverse shell and confirmed it was dead by testing for a response on the attacker side.

### Validated against 4 real, live attack techniques

| Technique | MITRE ID | Tetragon caught it | Wazuh alerted | Detection path |
|---|---|---|---|---|
| SSH brute-force | T1110 | ✅ | ✅ | Native Wazuh rule → SOAR blocks source IP |
| Web shell upload + RCE | T1505.003 | ✅ | ❌ (detection gap) | Graph-only: Tetragon ancestry capture, no native alert |
| Reverse shell | T1059.004 / T1095 | ✅ | ❌ (same gap) | Graph-only: SOAR kills process + blocks listener |
| Kerberoasting (AD) | T1558.003 | N/A (Windows host) | ❌ (detection gap, root-caused) | **New custom pipeline**: `archives.log` tailer → synthetic graph alert |

**A genuinely useful finding, not a bug:** Wazuh's default ruleset generates **zero alerts** for three of these four real techniques — it has no log source for "a PHP-FPM worker spawned a shell that opened an outbound socket" without added `auditd` rules, and, after extensive investigation (see below), it never alerts on a real user's own Kerberos service-ticket request either, only on routine DC-internal machine-account tickets. This is the core argument for AutoForensic-X's multi-collector, graph-native design: Tetragon's kernel-level eBPF tracing and the project's own Neo4j correlation layer caught every one of these attack chains with zero blind spots, where a log-based SIEM alone would have missed most of them completely.

### 🔍 Deep dive: the Kerberoasting investigation

This was the most involved piece of work in the project so far, and the clearest demonstration of the "Wazuh has real blind spots" thesis.

**Attack**: stood up a deliberately weak Kerberoastable service account (`svc-sql`, SPN `MSSQLSvc/...`, weak password) on the DC, plus a low-privilege foothold account representing an attacker with initial access. From Kali, used `impacket-GetUserSPNs` to request the SPN's service ticket (classic T1558.003) and got a crackable `$krb5tgs$` hash — confirmed real-world crackability via `hashcat -m 13100`.

**Investigation**: confirmed via direct indexer queries, live re-triggered attacks, and `wazuh-logtest` ground-truth checks that Wazuh's default ruleset *never* alerts on a real user's own Kerberos service-ticket request (Windows Event 4769 with an RC4-downgraded `0x17` encryption type) — only on routine DC-internal machine-account ticket requests, which always use AES256 (`0x12`). Three different custom-rule strategies were tried and all failed to fire, including chaining to a rule that turned out to be scoped specifically to machine accounts — a genuinely non-obvious root cause that took real debugging effort to isolate.

**Resolution**: rather than keep fighting Wazuh's rule engine, built `detect_kerberoasting.py` — a new pipeline component that tails Wazuh's raw `archives.log` (every event the agent sees, not just the ones that matched a rule) and performs the detection itself, synthesizing an `Alert` node directly into the same Neo4j schema the rest of the pipeline uses. Verified live end-to-end: a real re-triggered attack was detected and written to the graph with the correct account, requester, and MITRE technique within ~9 seconds. Deployed as a permanent systemd service.

This is now the project's *third* concrete example of its core thesis — and a stronger one than a working native Wazuh rule would have been, since it's backed by genuine root-cause investigation into *why* the vendor ruleset misses it, not just an assumption that it would.

### 🐛 Along the way

Real bugs were found and fixed during the build (documented in code comments/commit history where relevant):

- A timestamp-parsing bug that silently broke 100% of alert-to-process correlation (Python's strict `datetime.fromisoformat()` couldn't handle Wazuh's `+0000`-style offsets or Tetragon's nanosecond timestamps) — fixed by switching to `dateutil.parser.isoparse()`.
- An LVM disk-allocation issue that caused a mid-session disk-exhaustion crisis — fixed live, with zero data loss, and the crisis itself was *caught and correctly correlated* by the running pipeline, a nice unplanned proof that the collectors work.
- A Wazuh rule-schema quirk where `<if_sid>` chaining to a seemingly-matching parent rule silently never fired, because that parent rule turned out to be scoped more narrowly than its description suggested — root-caused via `wazuh-logtest` and direct `archives.log` comparison rather than assumed away.

---

## What's next

1. A third SOAR playbook for the web-shell upload/RCE stage itself.
2. Local LLM documentation (Ollama) — feed the root-cause trace + remediation history into a locally-run model to auto-generate a plain-English incident report.
3. Live dashboard — a single operational view separate from Wazuh's own dashboard, showing the provenance graph and remediation history together, with authentication/roles.
4. Metrics / benchmarking — mean-time-to-detect, mean-time-to-remediate, false-positive rate, measured against the scripted attack runbooks.
5. Network layer (Suricata) — V2 scope; adds inline network IDS/IPS, deepens the provenance graph with network-level nodes.
6. Packaging & open-source release — once the core loop (detect → correlate → trace → remediate) is fully proven, package for others to stand up their own instance.

---

## Repo structure

```
AutoForensic-X/
├── README.md                    ← you are here
├── provenance-graph/
│   ├── SETUP.md                 ← install/run instructions (Neo4j, venv, ingesters)
│   ├── schema.cypher            ← graph schema (constraints + indexes)
│   ├── config.py                ← env-var-driven connection config
│   ├── graph_writer.py          ← Neo4j driver wrapper (upsert + correlation logic)
│   ├── ingest_tetragon.py       ← streams live Tetragon events into the graph
│   ├── ingest_wazuh.py          ← tails Wazuh's alerts.json into the graph
│   ├── detect_kerberoasting.py  ← tails archives.log, detects Kerberoasting Wazuh misses
│   ├── trace_root_cause.cypher  ← root-cause backward-trace query
│   └── requirements.txt
├── soc/
│   └── afx_rules.xml            ← custom Wazuh manager rules
├── soar/
│   ├── soar_ssh_bruteforce.py   ← SSH brute-force detection + IP block
│   └── soar_reverse_shell.py    ← reverse-shell detection + process kill + IP block
└── target/
    ├── afx-response             ← Wazuh active-response script (reference copy; lives on Target)
    └── README.md
```

---

## Stack

Tetragon (eBPF/CNCF) · Wazuh (SIEM) · Active Directory / Kerberos (Windows Server 2022) · SSSD (Linux AD integration) · Sysmon · Neo4j (graph database) · Python 3 · Cypher · VirtualBox (host-only isolated lab network) · Ubuntu 22.04 LTS · Kali Linux (attack simulation, incl. Impacket + hashcat)
