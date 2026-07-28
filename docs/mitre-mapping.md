# MITRE ATT&CK Mapping

Coverage scoped to what this lab actually detects, with the gaps left visible. A coverage map that only shows strengths is not much use to anyone.

## Current coverage

| Detection | SID | Technique | Tactic |
|---|---|---|---|
| [DET-004 Suspicious user agent](../detections/DET-004-suspicious-user-agent.md) | 1000005 | [T1595.002 Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | Reconnaissance |
| [DET-001 SQL injection](../detections/DET-001-sql-injection.md) | 1000002 | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access |
| [DET-007 Login brute force](../detections/DET-007-brute-force.md) | 1000008 | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) | Credential Access |
| [DET-002 Command injection](../detections/DET-002-command-injection.md) | 1000003 | [T1059 Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) | Execution |
| [DET-005 Reverse shell](../detections/DET-005-reverse-shell.md) | 1000006 | [T1059](https://attack.mitre.org/techniques/T1059/) with [T1071 Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) | Execution and Command and Control |
| [DET-003 Directory traversal](../detections/DET-003-directory-traversal.md) | 1000004 | [T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) | Discovery |
| [DET-006 Web shell access](../detections/DET-006-web-shell.md) | 1000007 | [T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/) | Persistence |
| ET Splunk REST API info disclosure (CVE-2018-11409) | 2069969 | [T1190](https://attack.mitre.org/techniques/T1190/) | Initial Access |

I mapped each detection to what it observes on the wire rather than the broadest technique it could plausibly relate to. SQL injection touches later stage data access sub techniques in a full attack, but a UNION SELECT probe in a URI is T1190 and nothing more. The user agent rule is reconnaissance rather than command and control, because it fires on scanning tools rather than an established channel.

## As an attack chain

The seven custom detections line up along the path an attacker actually takes, from first contact to a foothold they can return to.

```
T1595.002 Recon  ->  T1190 Initial Access  ->  T1059 Execution  ->  T1083 Discovery
              \-> T1110 Credential Access       \-> T1071 C2 (reverse shell)
                                                 \-> T1505.003 Persistence (web shell)
```

A single source scanning and then exploiting will hit DET-004 followed by one or more of the exploitation and post exploitation rules. That sequence is what [COR-001](../detections/COR-001-recon-to-exploit-chain.md) watches for, and it is the reason the correlation search scores stage progression rather than alert count. COR-001 correlates all seven stages: a source crossing two or more is raised as a notable, ranked by risk and escalated to Critical the moment it reaches command and control or persistence. A partial chain still surfaces as High, so the search covers the short recon to exploit path and the full path to a dropped backdoor in one place.

## Summary

Coverage now spans seven ATT&CK tactics: reconnaissance, initial access, credential access, execution, command and control, discovery, and persistence. The shape is deliberate. A network sensor watching web traffic against a public facing victim is best demonstrated by following an attacker the whole way through the stages it can see, from the first scan to the shell they drop to keep access.
