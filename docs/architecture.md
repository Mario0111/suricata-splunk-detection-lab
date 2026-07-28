# Architecture

## Lab topology

Everything runs on a VirtualBox internal network, `10.10.10.0/24`, with no route to the host or the internet. All addressing is static.

| Host | Role | IP | OS |
|---|---|---|---|
| Kali Linux | Attacker | 10.10.10.10 | Kali Linux |
| Metasploitable 2 | Victim, intentionally vulnerable | 10.10.10.20 | Ubuntu 8.04 |
| suricata-01 | IDS sensor | 10.10.10.30 | Ubuntu 26.04 LTS, kernel 7.0.0-27-generic |
| splunk-server | SIEM | 10.10.10.40 | Ubuntu 26.04 LTS, Splunk Enterprise 10.4.1 |

## Sensor

| Item | Value |
|---|---|
| Suricata version | 8.0.6, RELEASE build |
| Capture method | AF_PACKET |
| Interface | `enp0s3` |
| Output | EVE JSON to `eve.json` |
| Vendor rules | Emerging Threats Open, in `suricata.rules` |
| Custom rules | `/var/lib/suricata/rules/local.rules`, SIDs from 1000001 |

## Pipeline

```
attack traffic -> Suricata (AF_PACKET) -> eve.json -> Universal Forwarder -> Splunk -> index=suricata
```

Four decisions shaped how this fits together.

**A dedicated index.** IDS telemetry goes to `suricata` rather than `main`, which keeps access control, retention and search performance independent of everything else in the SIEM.

**Native JSON ingestion with nested fields preserved.** EVE events index as nested objects, so searches address fields by full path. `alert.signature_id` works, `signature_id` does not exist. I confirmed this against raw `eve.json` before building any dashboard, which saved me from a class of panels that would have silently returned nothing.

**Custom rules isolated from vendor content.** Vendor rules stay in `suricata.rules` and mine go in `local.rules`. Ruleset updates cannot overwrite my detections, and the custom content stays small enough to review in one screen.

**Validation before every restart.** Every rule change gets checked with `sudo suricata -T` before the service restarts, and only deploys on a clean pass. This is not ceremony. A single malformed rule causes Suricata to abort loading the entire ruleset, which is a total detection outage rather than one missing rule, and I hit exactly that case while writing DET-002.

## Measured latency

I validated ingestion end to end before building dashboards or detections, checking timestamps, nested field extraction and event completeness against the raw log. Then I measured how long an attack took to become searchable.

| Metric | Latency |
|---|---|
| Minimum | 5s |
| Average | 7s |
| Maximum | 9s |

That figure sets analyst expectations. An attack is searchable in Splunk inside about ten seconds, which is fine for near real time triage at this scale.

## Configuration

Sanitised configuration exports are in [`config/`](../config/).
