# OBS-004: Investigation Summary KPI Row

Built the KPI row for the triage dashboard. Alert volume, unique source assets, unique destination assets and unique detections, all inside the selected time range.

These are the questions an analyst asks in the first thirty seconds of opening an investigation. How many alerts, how many systems, how many different detections fired. Answering those before showing any charts means you can size the problem before deciding how much attention it deserves.

Counting assets and detection types rather than just events was the point of the design. A small number of alerts spread across several hosts and several signature types is a broader problem than a few thousand repeats of one rule against one target, and an event count on its own hides that difference completely.

Built with `stats`, `count` and `dc()`. I checked each KPI returns a single value, that they update correctly when the time range changes, that the numbers match equivalent ad hoc searches, and that nothing renders with search warnings.
