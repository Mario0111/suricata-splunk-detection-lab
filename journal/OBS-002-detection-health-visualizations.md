# OBS-002: First Detection Health Visualisations

Added the first two visualisations to the Detection Health dashboard, once the KPI row had confirmed the pipeline was working.

**Alerts over time**, as an area chart. Volume over time is what shows spikes in activity, and just as usefully, gaps where ingestion stopped.

```spl
index=suricata sourcetype=suricata:eve event_type=alert
| timechart span=5m count AS Alerts
```

**Top alert signatures**, as a horizontal bar chart, to see which detections dominate a given window.

```spl
index=suricata sourcetype=suricata:eve event_type=alert
| top limit=10 alert.signature
```

Between them these answer the two questions I actually want answered at a glance: is the sensor still sending, and what is it mostly sending. The signature distribution doubles as a first look at tuning candidates, since anything dominating the chart is worth explaining.

Both populated correctly, and the signature distribution matched the alerts I had already validated by hand.
