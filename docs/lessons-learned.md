# Lessons Learned

Things this project taught me, roughly in the order they came up.

## Nested JSON fields need their full path

Suricata EVE events index as nested objects, so `alert.signature_id` works and `signature_id` simply does not exist. Checking field extraction against raw `eve.json` before building anything saved me from a set of dashboard panels that would have quietly returned nothing at all. The same applies inside `eval` and `case`, where dotted field names need single quotes or they get parsed as an object path.

## A dashboard KPI is a claim, not a fact

The unique signatures panel said 3 when I knew about 2. Treating that as a signal rather than a rounding quirk turned up a genuinely new signature. Cross checking aggregates against raw SPL is not busywork, it is how you find out whether the dashboard is worth trusting at all.

## One bad rule is a total outage, not a missing detection

My first command injection rule failed to parse, and Suricata's response was `Loading signatures failed`. Not "skipping rule 1000003". The entire ruleset. Had I pushed that and restarted without checking, the sensor would have come up with no detections running while systemd still reported the service healthy, which is about the worst failure mode available: silent and complete.

This is the whole argument for validating before restart, and I would rather have learned it from `suricata -T` than from a gap in the alert timeline.

## Know which layer is failing

The same failure taught me something more specific. Suricata tokenises rule options on `;` before PCRE ever compiles the pattern, so a literal semicolon inside a perfectly valid regex character class truncates the option. The fix was to write it as `\x3b`. The regex engine was never the problem. Reading a rule error means working out whether the rule parser or the pattern engine is complaining, because they fail differently and get fixed differently.

## An IDS alert proves attempt, not impact

My first round of validation attacks all returned the same default page, because Metasploitable's web root ignores the parameters I was injecting. Every rule fired anyway, and that is correct. Suricata inspects the request as it crosses the wire, so an alert means the attack was seen, not that the target was vulnerable or that anything succeeded.

I proved the other half of that later, by aiming the traversal rule at Mutillidae's `page` parameter instead of the web root. That one is genuinely vulnerable, and the response came back with Metasploitable's real `/etc/passwd` in it. Same rule, same alert, completely different outcome on the victim. The two runs side by side are in [DET-003](../detections/DET-003-directory-traversal.md).

That pair is the actual lesson. The rule output was identical whether the attack landed or not, so the alert cannot be telling you about impact, only about intent. The practical consequence is that you validate a detection by confirming the alert in Splunk, never by reading the HTTP response. Working out whether an attempt actually landed is analyst work that needs response context, and it is a separate question from whether the rule works.

## Your monitoring stack will monitor itself

The single loudest signature in the environment, by an order of magnitude, was Splunk Web talking to itself. Not an attack. In any real environment infrastructure self traffic will show up in the top few signatures, and the useful habit is attributing noise to its source before reaching for a suppression.

## Split dashboards by audience

Four dashboards over one index, each answering one question for one group of people, turned out far more usable than a single large one. Same reasoning SOCs use when they separate engineering tooling from analyst tooling.

## Correlate on progression, not volume

When I got to the correlation search, the obvious design would have been to alert on alert count per source. That would have been useless here, because the loudest thing in the environment is benign. Scoring distinct attack stages instead means the search ignores a thousand repeats of one signature and fires on four requests that walk through recon, access and execution.

## Write it down while you remember why

I recorded decisions as I made them rather than reconstructing them later. The what is recoverable from the data afterwards. The why is the part that evaporates, and it is the part that matters.

## What I would do next

Watch COR-001 over a longer window now that it is running on a schedule, and see whether a 60 minute rolling window is the right size once there is more than test traffic in it. Close out SID 2221050. Apply one of the tuning options for 2221036 so the decision log has a real before and after in it rather than a proposal. And extend the detection set past what a request side signature can see, since every rule here inspects the URI, which leaves POST bodies and anything after the shell connects out entirely uncovered.
