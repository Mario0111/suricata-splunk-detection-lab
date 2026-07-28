# MITRE ATT&CK Mapping

Coverage scoped to what this lab actually detects, with the gaps left visible. A coverage map that only shows strengths is not much use to anyone.

## Current coverage

| Detection | SID | Technique | Tactic |
|---|---|---|---|
| [DET-004 Suspicious user agent](../detections/DET-004-suspicious-user-agent.md) | 1000005 | [T1595.002 Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | Reconnaissance |
| [DET-001 SQL injection](../detections/DET-001-sql-injection.md) | 1000002 | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access |
| [DET-002 Command injection](../detections/DET-002-command-injection.md) | 1000003 | [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | Execution |
| [DET-003 Directory traversal](../detections/DET-003-directory-traversal.md) | 1000004 | [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) | Discovery |
| ET Splunk REST API info disclosure (CVE-2018-11409) | 2069969 | [T1190](https://attack.mitre.org/techniques/T1190/) | Initial Access |

I mapped each detection to what it observes on the wire rather than the broadest technique it could plausibly relate to. SQL injection touches later stage data access sub techniques in a full attack, but a UNION SELECT probe in a URI is T1190 and nothing more. The user agent rule is reconnaissance rather than command and control, because it fires on scanning tools rather than an established channel.

## As an attack chain

The four detections line up in the order an attacker would actually trip them.

```
T1595.002 Reconnaissance  ->  T1190 Initial Access  ->  T1059 Execution
                                                    ->  T1083 Discovery
```

A single source scanning and then exploiting will hit DET-004 followed by one or more of DET-001, DET-002 and DET-003. That sequence is what [COR-001](../detections/COR-001-recon-to-exploit-chain.md) watches for, and it is the reason the correlation search scores stage progression rather than alert count.

## Not covered yet

| Detection | Likely mapping | Tactic |
|---|---|---|
| Reverse shell | [T1059](https://attack.mitre.org/techniques/T1059/) with [T1071](https://attack.mitre.org/techniques/T1071/) | Execution, Command and Control |
| Web shell access | [T1505.003](https://attack.mitre.org/techniques/T1505/003/) | Persistence |
| Brute force | [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Access |

## Summary

Coverage spans four tactics rather than going deep on one. That shape was intentional: a network sensor watching web traffic against a public facing victim is best demonstrated by following an attacker through the stages it can actually see. The remaining three detections would extend into command and control, persistence and credential access.
