# Screenshots

Everything here is from the lab, captured while validating the thing it shows.

## Dashboards

| File | Dashboard |
|---|---|
| `detection-health-overview.png` | Detection Health Overview |
| `soc-analyst-triage.png` | SOC Analyst Triage |
| `detection-inventory.png` | Detection Inventory |
| `risk-kill-chain.png` | Risk Based Kill Chain |

## Detection validation

| File | What it shows |
|---|---|
| `det-002-fp-splunk.png` | Command injection false positives on Splunk's own search URLs, alongside the real attack. [DET-002](../detections/DET-002-command-injection.md) |
| `det-003-lfi-alert.png` | Directory traversal alert for the Mutillidae LFI. [DET-003](../detections/DET-003-directory-traversal.md) |
| `det-003-lfi-impact.png` | Metasploitable's `/etc/passwd` returned in the response body, the same attack proving impact rather than attempt |
| `det-005-reverse-shell.png` | Reverse shell payload alert, `/dev/tcp/` construction. [DET-005](../detections/DET-005-reverse-shell.md) |
| `det-006-web-shell.png` | Web shell access alert on `c99.php` and `shell.php`. [DET-006](../detections/DET-006-web-shell.md) |
| `det-007-brute-force.png` | Brute force alert after the `detection_filter` threshold was crossed. [DET-007](../detections/DET-007-brute-force.md) |

## Correlation search

All from [COR-001](../detections/COR-001-recon-to-exploit-chain.md).

| File | What it shows |
|---|---|
| `cor-001-negative-no-fire.png` | Negative test, a single stage returning no result |
| `cor-001-positive-critical.png` | Positive test, the recon to exploit chain reassembled into one Critical row |
| `cor-001-full-chain.png` | The full chain through to persistence, Critical at five stages |
| `cor-001-alert-config.png` | Scheduled search and alert configuration |
| `cor-001-triggered.png` | The alert firing and landing in Activity, Triggered Alerts |
