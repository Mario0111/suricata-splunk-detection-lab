# Investigations

Three occasions where the environment did something I did not expect and I stopped building to find out why.

## The signature count that did not match

While validating the Detection Health dashboard, the unique signatures KPI showed 3. I had only ever seen 2 in this environment. That meant either the panel was wrong or something had changed, and I could not trust the dashboard until I knew which.

I paused dashboard work and went to the raw data.

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

The new one was SID 2221050, at two occurrences. It comes from Suricata's internal HTTP parser rather than the ET ruleset, so it reflects how the parser is handling traffic rather than a match on an attacker payload. Different thing entirely from a threat signature firing.

I did not suppress or filter it. Two events is not enough to justify a tuning decision, and the whole point of the dashboard is visibility into what the sensor sees. It stays visible and stays open.

The reason I care about this one is that the instinct with a low volume unexplained signature is to make it go away. But signature diversity changing can mean new techniques, a ruleset or software update, a protocol parsing anomaly, or a genuine false positive worth tuning. Suppressing before understanding removes the exact visibility the sensor exists to provide. The KPI turned out to be right, which is what let me carry on building.

The Detection Inventory dashboard's "recently introduced detections" panel came out of this. Now first seen and last seen are tracked per signature, so a new arrival is something the dashboard tells me rather than something I trip over during validation.

SID 2221050 is still open. No tuning applied.

## Attributing the loudest signature

One signature dominates everything else in this environment: SURICATA HTTP Response excessive header repetition, over 5,000 events against 170 for the next most common. Volume like that makes a rule an obvious tuning candidate, but only once you know what is generating it.

Checking the volume and endpoints against raw events showed it fires on interaction with Splunk Web, with the Splunk server rather than the victim host on the relevant side of the connection. The monitoring stack is watching its own management traffic and alerting on it.

So it is benign, and a fairly ordinary lab artifact once you think about where the sensor sits. I recorded it as a tuning candidate rather than suppressing it on the spot. The proposed approach and the reasoning for not simply disabling the rule are in [tuning.md](tuning.md).

## A false positive the correlation search forced into view

This one I did not go looking for. It surfaced on its own while I was validating the correlation search [COR-001](../detections/COR-001-recon-to-exploit-chain.md), which raises a notable when one source IP crosses two or more attack stages.

I ran a negative test that was supposed to stay quiet: fire only reconnaissance from one source, confirm the search does not fire on a single stage. It fired anyway, Critical, on two stages. The second stage was command injection, and I had not sent any.

Tracing where those command injection alerts came from:

```spl
index=suricata sourcetype=suricata:eve event_type=alert alert.signature_id=1000003 dest_ip=10.10.10.40 earliest=-2h
| table _time src_ip dest_ip http.url http.http_user_agent
```

Eight of them, all from my own browser, all against the Splunk server, all on URLs like this:

```
/en-US/splunkd/__raw/services/search/jobs?output_mode=json&id=root__root__search__RMD5...
```

My command injection rule had `&` in its character class, and Splunk's search API puts `&id=<jobid>` in its URLs. The rule read `&id=` as a backgrounded `id` command and fired. Every search I ran to do the validation was generating a false positive against one of the detections being validated.

The rule was wrong, not the traffic, so I fixed the pattern rather than suppressing the output. The reasoning and the fix are in [tuning.md](tuning.md#sid-1000003-fixing-the-rule-rather-than-suppressing-it) and [DET-002](../detections/DET-002-command-injection.md#tuning-removing-a-false-positive).

Two things I took from this. First, `&` is a URL parameter separator, so it is a bad shell metacharacter to match in a URI and a reliable source of false positives, which is a lesson that generalises to any web attack rule. Second, and more interesting, the false positive was invisible while I looked at the command injection rule on its own, because eight alerts among thousands is nothing. It only became visible when the correlation search combined it with other activity and forced it to the surface. Correlation does not just prioritise real incidents, it also exposes noisy inputs that individually look harmless. That is a real argument for building correlation searches even in a small environment.
