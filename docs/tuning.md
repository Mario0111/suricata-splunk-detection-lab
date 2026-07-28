# Tuning

How I approach this: a suppression is an engineering decision, not a reflex. Everything below has its source attributed and its reasoning recorded, and the default is to keep visibility until there is a reason to remove it.

## Decisions so far

| SID | Signature | Volume | Cause | Decision |
|---|---|---:|---|---|
| 2221036 | SURICATA HTTP Response excessive header repetition | 5,000+ | Benign Splunk Web self traffic | Tuning candidate, proposal below, not yet applied |
| 2221050 | SURICATA HTTP too many warnings | 2 | Suricata HTTP parser, still under investigation | No tuning. Not enough evidence to act on |
| 2069969 | ET Splunk REST API info disclosure (CVE-2018-11409) | 170 | Expected match on Splunk REST API interaction | Keep. Legitimate coverage and useful as a known good signal |
| 1000002 to 1000005 | My custom detections | low | Attack simulation | No tuning. High signal, no false positives observed |

## Proposal for SID 2221036

It is loud and it is benign here, but disabling the SID outright is the wrong instinct. That would blind the sensor to the same signature firing against a real target, which is a much worse outcome than some noise on a dashboard. Three options, least to most aggressive:

**Filter at the dashboard.** Exclude the known benign Splunk self traffic from noise sensitive panels while leaving every event indexed.

```spl
index=suricata sourcetype=suricata:eve event_type=alert
NOT (alert.signature_id=2221036 AND dest_ip=10.10.10.40)
```

Nothing is lost, only presentation changes, and it is reversible in seconds.

**Suppress at the sensor, scoped to the host.** Cuts sensor side noise while keeping the signature live for every other destination.

```
suppress gen_id 1, sig_id 2221036, track by_dst, ip 10.10.10.40
```

**Disable the rule.** Rejected. It removes the detection everywhere rather than just for the traffic that is actually benign, which is out of proportion to the problem.

I would apply the first option, since it costs nothing and loses no data, and only move to the second if sensor side alert volume started affecting performance. When I apply one I will record it here with before and after counts.

## Principles I stuck to

Attribute before suppressing. Every decision above names the traffic responsible for the volume, because you cannot judge a rule you have not traced.

Prefer narrow and reversible. Presentation filters and host scoped suppressions over global rule disables.

Keep the raw data. Tuning should change what an analyst sees by default, not destroy the underlying telemetry.

Write it down. A suppression with no recorded reasoning looks identical to a coverage gap once you have forgotten the context.
