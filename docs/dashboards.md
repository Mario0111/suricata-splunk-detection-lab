# Dashboards

Three dashboards built in Splunk Dashboard Studio, dark theme, absolute layout. Each one targets a single audience and a single question.

I split them deliberately. One dashboard trying to serve both engineers and analysts ends up serving neither well, and SOCs generally separate the two anyway: engineering watches sensor and pipeline health, analysts work from investigation views. Keeping them apart also means each panel earns its place against one clear purpose.

All panels run off a global time range input over `index=suricata sourcetype=suricata:eve event_type=alert`.

## Detection Health Overview

![Detection Health Overview](../screenshots/detection-health-overview.png)

This was the first dashboard I built, and its first job was proving the pipeline worked end to end rather than looking good. Alert volume, signature activity, severity spread and sensor status.

Panels:

- KPI row: total alerts, unique signatures, source IPs, highest severity.
- Alerts over time, an area chart. Spikes show attack bursts, gaps show ingestion problems.

  ```spl
  index=suricata sourcetype=suricata:eve event_type=alert
  | timechart span=5m count AS Alerts
  ```

- Top alert signatures, which surfaces dominant detections and tuning candidates.

  ```spl
  index=suricata sourcetype=suricata:eve event_type=alert
  | top limit=10 alert.signature
  ```

- Severity distribution, top source IPs, top destination IPs, and a recent alerts table.

I cross checked every KPI against ad hoc SPL and raw events rather than trusting the panel. That is how I found the signature count discrepancy described in [investigations.md](investigations.md), which paused dashboard work for a while.

## SOC Analyst Triage

![SOC Analyst Triage](../screenshots/soc-analyst-triage.png)

Built for the first few minutes of triage. The panel order follows the sequence an analyst actually asks questions in.

1. **Investigation summary KPIs.** How big is this? Total alerts, unique source assets, unique destination assets, unique detections, using `stats` and `dc()`. Asset and detection diversity tells you more than raw count here. A handful of alerts spread across several assets and signature types is a broader problem than a thousand repeats of one rule.
2. **Alert timeline.** When did it happen, and is it still happening?
3. **Detection breakdown and protocol distribution.** What kind of activity is this?
4. **Top source and destination IPs.** Which systems are involved?
5. **Recent alerts table.** Where do I start? Newest first, with `_time`, `src_ip`, `dest_ip`, `proto`, `alert.severity`, `alert.signature`, plus `http.hostname` and `http.url` so web attacks can be triaged without leaving the panel.

I confirmed every panel populated from the index, that counts matched raw events, that the recent alerts table sorted newest first, and that the visualisations held up across several different time ranges.

## Detection Inventory

![Detection Inventory](../screenshots/detection-inventory.png)

An engineering view rather than an analyst one. It inventories every signature seen in the environment so I can review rule activity, spot noisy or high value signatures, and prioritise tuning against real telemetry instead of guesswork.

Panels:

- **Detection catalog.** One row per signature with SID, name, category, severity, count, and first and last seen timestamps. This is the closest thing the lab has to a detection register.
- **Top detection volume.** Effectively the tuning priority queue.
- **Severity distribution** and **detection categories**, which show what kinds of activity are actually being caught.
- **Detection trends** over time.
- **High volume rules**, signatures above a set alert threshold.
- **Recently introduced detections**, ordered by first seen.

That last panel exists because of the investigation in [investigations.md](investigations.md). A new signature appeared unannounced and I had no quick way to tell when it had started firing. Now "has anything new shown up?" is a question the dashboard answers on its own instead of a surprise during validation.
