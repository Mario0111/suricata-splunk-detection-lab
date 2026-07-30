# Engineering Journal

Notes written as I worked rather than reconstructed afterwards. I kept them light during implementation and only recorded the decisions that mattered, so the reasoning behind each milestone survives even though the day to day work does not.

These cover the build phase, from validating the pipeline through to the first four detections. After that the per artefact writeups took over as the place I recorded reasoning, because each one had enough in it to stand on its own rather than being a journal note. The decisions from the second half of the project are in [COR-001](../detections/COR-001-recon-to-exploit-chain.md) for the correlation search and its validation, [DET-005](../detections/DET-005-reverse-shell.md) to [DET-007](../detections/DET-007-brute-force.md) for the remaining detections, and [docs/dashboards.md](../docs/dashboards.md#risk-based-kill-chain) for the risk based kill chain view.

| Entry | Milestone |
|---|---|
| [OBS-001](OBS-001-detection-health-validation.md) | Detection Health dashboard validation, and the unexpected signature it turned up |
| [OBS-002](OBS-002-detection-health-visualizations.md) | First Detection Health visualisations |
| [OBS-003](OBS-003-soc-triage-dashboard.md) | SOC Analyst Triage dashboard design |
| [OBS-004](OBS-004-investigation-kpi-row.md) | Investigation summary KPI row |
| [OBS-005](OBS-005-custom-sqli-detection.md) | First custom detection, SQL injection |
| [OBS-006](OBS-006-detection-set-expansion.md) | Detection set expanded to four ATT&CK tactics |
