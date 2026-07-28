# Investigations

Two occasions where the environment did something I did not expect and I stopped building to find out why.

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
