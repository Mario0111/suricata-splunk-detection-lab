# OBS-003: SOC Analyst Triage Dashboard

Second dashboard, aimed at investigations rather than infrastructure. The Detection Health dashboard answers whether the pipeline is healthy. This one answers what is happening and where to start.

I laid the panels out in the order an analyst asks questions. Summary metrics first to establish scope, then a timeline to place the activity in time, then detection, source, destination and protocol breakdowns to characterise it, and finally a detailed recent alerts table that works as the investigation queue.

Splitting this away from the health dashboard was the main decision. One dashboard trying to do both jobs makes each panel compete for attention with something unrelated, and it mirrors how SOCs are usually organised anyway, with engineering watching sensor health and analysts working from investigation views.

Validation: every panel populates from the suricata index, protocol and source and destination and signature counts match the raw events, the recent alerts table sorts newest first, and the visualisations stay accurate across several different time ranges.

The two dashboards cover different stages of the same lifecycle. One says the sensor is trustworthy, the other assumes that and gets on with the investigation.
