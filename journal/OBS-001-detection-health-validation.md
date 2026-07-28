# OBS-001: Detection Health Dashboard Validation

Goal was to confirm the Suricata to forwarder to Splunk pipeline actually worked before building anything operational on top of it.

I built the Detection Health Overview dashboard in Splunk Dashboard Studio, absolute layout and dark theme. The first KPI panel confirmed alerts were being generated, forwarded, indexed and returned by search, which is the whole pipeline in one panel. At that point I had roughly 2,600 alerts, 3 unique signatures, 2 source IPs and a highest severity of 1.

The signature count was the problem. I had only ever seen 2 unique signatures in this environment, and the panel was showing 3.

That is either a broken panel or a real change, and I could not carry on building on a dashboard I did not trust, so I stopped and checked against the raw data.

```spl
index=suricata sourcetype=suricata:eve event_type=alert
| stats count by alert.signature_id alert.signature
| sort -count
```

| SID | Signature | Count |
|---|---|---:|
| 2221036 | SURICATA HTTP Response excessive header repetition | 2,559 |
| 2069969 | ET WEB_SPECIFIC_APPS Splunk Enterprise Server Information Disclosure via REST API (CVE-2018-11409) | 97 |
| 2221050 | SURICATA HTTP too many warnings | 2 |

The new one was SID 2221050 at two occurrences, and it comes from Suricata's own HTTP parser rather than the ET ruleset. So it reflects how the parser is handling traffic rather than a signature matching an attacker payload.

I left it alone. Two events is not enough to base a tuning decision on, and the dashboard is supposed to show me what the sensor sees. It stays visible until I understand it.

The KPI was right, which is what let me keep building. Full writeup in [investigations.md](../docs/investigations.md).
