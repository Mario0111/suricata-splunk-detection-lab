# OBS-005: First Custom Detection

Dashboards were done, so I moved on to writing detections. This was the first real one.

Some conventions I set here and kept for everything after:

Vendor rules stay in `suricata.rules`, mine go in `local.rules`. A ruleset update should never be able to touch my detections, and keeping the custom set in one small file means I can read all of it at once.

Local SIDs start at 1000001, which keeps them clearly separate from vendor space.

Nothing deploys without `suricata -T` passing first.

Two rules at this point. 1000001 is an ICMP rule I used to prove the pipeline end to end, not a threat detection. 1000002 is the SQL injection rule.

Attack from Kali against Metasploitable:

```bash
curl "http://10.10.10.20/?id=1%20UNION%20SELECT%201"
```

The server returned its default landing page, confirming the request crossed the monitored segment, and the URI payload tripped 1000002. Configuration validated, service restarted, rule load confirmed, alert generated and visible in Splunk within the usual few seconds.

That completes a full cycle for the first time: research, design, write, validate, simulate, confirm, map to ATT&CK, decide on tuning. Writeup in [DET-001](../detections/DET-001-sql-injection.md).
