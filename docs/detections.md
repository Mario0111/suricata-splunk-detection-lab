# Detections

## Signatures observed in the environment

Snapshot from the Detection Inventory dashboard over a 24 hour window. The live state comes from:

```spl
index=suricata sourcetype=suricata:eve event_type=alert
| stats count min(_time) AS FirstSeen max(_time) AS LastSeen BY alert.signature_id alert.signature alert.category alert.severity
| convert ctime(FirstSeen) ctime(LastSeen)
| sort -count
```

| SID | Signature | Source | Category | Sev | Volume | Notes |
|---|---|---|---|---|---|---|
| 2221036 | SURICATA HTTP Response excessive header repetition | Suricata HTTP parser | Generic Protocol Command Decode | 3 | 5,162 | Benign. Caused by interaction with Splunk Web. Tuning candidate, see [tuning.md](tuning.md) |
| 2069969 | ET WEB_SPECIFIC_APPS Splunk Enterprise Server Information Disclosure via REST API (CVE-2018-11409) | ET Open | Web Application Attack | 1 | 170 | Expected. Fires on Splunk REST API interaction |
| 2221050 | SURICATA HTTP too many warnings | Suricata HTTP parser | Generic Protocol Command Decode | | 2 | Still open, no tuning applied. See [investigations.md](investigations.md) |
| 1000002 | LOCAL WEB SQL Injection Attempt, UNION SELECT in URI | Custom | web-application-attack | | low | [DET-001](../detections/DET-001-sql-injection.md) |
| 1000003 | LOCAL WEB Command Injection, shell metacharacter with command in URI | Custom | web-application-attack | | low | [DET-002](../detections/DET-002-command-injection.md) |
| 1000004 | LOCAL WEB Directory Traversal, sensitive file access via URI | Custom | web-application-attack | | low | [DET-003](../detections/DET-003-directory-traversal.md) |
| 1000005 | LOCAL WEB Suspicious User-Agent, known attack tool | Custom | web-application-attack | | low | [DET-004](../detections/DET-004-suspicious-user-agent.md) |
| 1000006 | LOCAL WEB Reverse Shell Payload in HTTP Request | Custom | trojan-activity | | low | [DET-005](../detections/DET-005-reverse-shell.md) |
| 1000007 | LOCAL WEB Web Shell Access | Custom | trojan-activity | | low | [DET-006](../detections/DET-006-web-shell.md) |
| 1000008 | LOCAL WEB Login Brute Force Attempt | Custom | attempted-user | | low | [DET-007](../detections/DET-007-brute-force.md) |
| 1000001 | LAB Suricata ICMP Detection Pipeline Test | Custom | none | | on demand | Pipeline test rule, not a threat detection |
| various | SURICATA STREAM anomaly signatures | Suricata stream engine | Generic Protocol Command Decode | 3 | low | Normal TCP stream engine noise in a VM lab. Monitored, not tuned |

## Custom detections

My rules live in `/var/lib/suricata/rules/local.rules` with SIDs starting at 1000001, kept separate from vendor content so ruleset updates cannot clobber them. A repo copy is in [detections/rules/local.rules](../detections/rules/local.rules).

| ID | Detection | SID | ATT&CK | Tactic | Status |
|---|---|---|---|---|---|
| [DET-001](../detections/DET-001-sql-injection.md) | SQL injection, UNION SELECT in URI | 1000002 | T1190 | Initial Access | Deployed and validated |
| [DET-002](../detections/DET-002-command-injection.md) | Command injection, shell metacharacter in URI | 1000003 | T1059 | Execution | Deployed and validated |
| [DET-003](../detections/DET-003-directory-traversal.md) | Directory traversal and LFI | 1000004 | T1083 | Discovery | Deployed and validated |
| [DET-004](../detections/DET-004-suspicious-user-agent.md) | Suspicious user agent | 1000005 | T1595.002 | Reconnaissance | Deployed and validated |
| [DET-005](../detections/DET-005-reverse-shell.md) | Reverse shell payload in HTTP | 1000006 | T1059 / T1071 | Execution / C2 | Deployed and validated |
| [DET-006](../detections/DET-006-web-shell.md) | Web shell access | 1000007 | T1505.003 | Persistence | Deployed and validated |
| [DET-007](../detections/DET-007-brute-force.md) | Login brute force | 1000008 | T1110 | Credential Access | Deployed and validated |

Each one was confirmed end to end: rule loaded cleanly, attack simulated from Kali, alert indexed and queried in Splunk.

The seven detections span seven ATT&CK tactics, from reconnaissance through to credential access. DET-007 is the only rate based one, using a `detection_filter` to fire on a threshold rather than a single request. DET-005 is the only one that overlaps another on purpose, since a reverse shell is also a command injection and tripping both is a stronger signal than either alone.

## Correlation

Individual detections fire in isolation. Correlation is what turns them into an incident.

| ID | Correlation | Inputs | Status |
|---|---|---|---|
| [COR-001](../detections/COR-001-recon-to-exploit-chain.md) | Risk scored notable when one source IP progresses across two or more attack stages, Critical if it reaches C2 or persistence | SIDs 1000002 to 1000008 | Deployed as a scheduled search |

## How I work through a detection

Every rule follows the same path: research, design, write the rule, validate with `suricata -T`, simulate the attack, confirm in Splunk, map to ATT&CK, decide on tuning.

Two parts of that are non negotiable for me. A rule that has never fired against real traffic is a hypothesis rather than a detection, so attack simulation happens before I call anything finished. And any suppression or threshold gets written down with its reasoning, because a filter with no recorded rationale is indistinguishable from a coverage gap six months later.
