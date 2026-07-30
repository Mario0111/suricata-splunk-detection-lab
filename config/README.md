# Configuration

Sanitised configuration from the sensor and the Splunk side, so the build is reproducible.

```
config/
  suricata/suricata.yaml    capture, HOME_NET and EVE output, trimmed from the sensor
  splunk-uf/inputs.conf     the eve.json monitor stanza on the forwarder
  splunk-uf/outputs.conf    forwarding to the indexer on 10.10.10.40:9997
  splunk/indexes.conf       suricata index definition on the indexer
  splunk/savedsearches.conf the COR-001 scheduled correlation search
  splunk/dashboards/        Dashboard Studio JSON for all four dashboards
```

The dashboard exports are the full Dashboard Studio definitions, so every panel's exact SPL and layout is in the repo rather than only in the screenshots. They import directly into a Splunk instance that has a `suricata` index. The prose walkthrough of what each panel is for is in [docs/dashboards.md](../docs/dashboards.md).

A couple of other details worth pointing out.

The forwarder input (`splunk-uf/inputs.conf`) routes the EVE log to a dedicated `suricata` index with sourcetype `suricata:eve`. That named sourcetype is what gives the events their JSON field extraction on the indexer.

The sensor sets `EXTERNAL_NET: "!$HOME_NET"`, meaning everything outside `10.10.10.0/24`. Since the attacker at `10.10.10.10` is inside HOME_NET, it is by definition not in EXTERNAL_NET, which is exactly why the custom web rules use `any any -> $HOME_NET any` rather than the conventional `$EXTERNAL_NET -> $HOME_NET`. The conventional form would never match traffic between two hosts on the same subnet.
