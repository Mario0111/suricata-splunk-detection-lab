# Tuning

How I approach this: a suppression is an engineering decision, not a reflex. Everything below has its source attributed and its reasoning recorded, and the default is to keep visibility until there is a reason to remove it.

## Decisions so far

| SID | Signature | Volume | Cause | Decision |
|---|---|---:|---|---|
| 2221036 | SURICATA HTTP Response excessive header repetition | 5,000+ | Benign Splunk Web self traffic | Tuning candidate, proposal below, not yet applied |
| 2221050 | SURICATA HTTP too many warnings | 2 | Suricata HTTP parser, still under investigation | No tuning. Not enough evidence to act on |
| 2069969 | ET Splunk REST API info disclosure (CVE-2018-11409) | 170 | Expected match on Splunk REST API interaction | Keep. Legitimate coverage and useful as a known good signal |
| 1000003 | LOCAL WEB Command Injection | 8 FPs | `&id=` in Splunk URLs matched as "& id" | Rule corrected, `&` dropped from the class, rev:2. Section below |
| 1000002, 1000004, 1000005, 1000006, 1000007 | My other pattern matching detections | low | Attack simulation | No tuning. High signal, no false positives observed |
| 1000008 | LOCAL WEB Login Brute Force | low | Attack simulation | No tuning applied, but the threshold is the tuning surface. Count 20 in 60 seconds is a lab default rather than a baselined figure. See [DET-007](../detections/DET-007-brute-force.md#tuning) |

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

## SID 1000003: fixing the rule rather than suppressing it

My own command injection rule produced false positives on legitimate Splunk traffic. Splunk's search API calls URLs like `...&id=<jobid>`, and the rule read the `&id=` as a backgrounded `id` command. Eight alerts against the Splunk server, all from my browser, none of them attacks. Full trace in [investigations.md](investigations.md#a-false-positive-the-correlation-search-forced-into-view).

The decision here is different from SID 2221036 above, and the difference is the point. SID 2221036 is a correct rule firing on benign traffic, so the answer is a scoped suppression that leaves the rule intact for real targets. SID 1000003 was a wrong rule: `&id=` is a false positive on any host, not just my Splunk server, because `&` is a URL parameter separator and not a usable shell operator in a GET request. Suppressing it per host would have left the bad pattern in place everywhere else.

So the fix was to correct the pattern, dropping `&` from the character class and bumping the rule to rev:2, not to suppress its output. Re-validated both ways: the real `;id` attack still fires, and Splunk searches no longer generate the alert. The detail is in [DET-002](../detections/DET-002-command-injection.md#tuning-removing-a-false-positive).

The general rule I took from it: suppression is for benign traffic on a good rule, a pattern fix is for a bad rule. Reaching for suppression on a broken rule just hides the symptom.

## Principles I stuck to

Attribute before suppressing. Every decision above names the traffic responsible for the volume, because you cannot judge a rule you have not traced.

Prefer narrow and reversible. Presentation filters and host scoped suppressions over global rule disables.

Keep the raw data. Tuning should change what an analyst sees by default, not destroy the underlying telemetry.

Write it down. A suppression with no recorded reasoning looks identical to a coverage gap once you have forgotten the context.
