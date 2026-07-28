# DET-004: Suspicious User Agent, Known Attack Tooling

| | |
|---|---|
| SID | 1000005 |
| ATT&CK | [T1595.002 Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/), Reconnaissance |
| Status | Deployed and validated |
| Rule file | `/var/lib/suricata/rules/local.rules` |

## Background

Most automated attack and recon tools announce themselves in the HTTP User-Agent header unless someone has bothered to change it. sqlmap, nikto, nmap's HTTP scripts, dirbuster and gobuster, wpscan, hydra, nuclei. Catching them is cheap and it is early: scanning usually happens before the targeted exploitation that the other three detections cover.

This is the rule that tells you someone is trying doors rather than that they got one open.

## Rule design

The pattern matches known tool names in the `http.user_agent` buffer:

```
/(?:sqlmap|nikto|nmap|masscan|metasploit|dirbuster|gobuster|wpscan|hydra|nuclei|zgrab)/i
```

Scoping to the user agent buffer rather than raw content keeps it cheap and stops the rule firing if one of these strings turns up in a URL or a response body for some innocent reason. Case insensitive, since capitalisation varies between versions.

The obvious criticism is that this is trivially evaded. Any of these tools will happily send whatever user agent you tell it to, and a competent attacker changes it. I would not rely on this rule to stop anyone who knows what they are doing.

It earns its place for two reasons. Most scanning traffic that hits an exposed service is low effort and default configured, so it catches a lot in practice. And it works as the cheap outer tripwire in a layered setup: this fires first, the payload level detections behind it fire if the scanning turns into an actual attack. Documenting the limitation is more useful than pretending it is not there.

## The rule

```
alert http any any -> $HOME_NET any (msg:"LOCAL WEB Suspicious User-Agent - Known Attack Tool"; flow:to_server,established; http.user_agent; pcre:"/(?:sqlmap|nikto|nmap|masscan|metasploit|dirbuster|gobuster|wpscan|hydra|nuclei|zgrab)/i"; classtype:web-application-attack; sid:1000005; rev:1;)
```

## Validation

`suricata -T` passed and the rule loaded on restart.

Attack from Kali, spoofing the user agent on a single request:

```bash
curl -A "sqlmap/1.7.2#stable" "http://10.10.10.20/"
```

Confirmed in Splunk:

```spl
index=suricata sourcetype=suricata:eve event_type=alert alert.signature_id=1000005
| stats count values(http.http_user_agent) AS user_agents BY src_ip
```

Grouping by source IP shows immediately which host is scanning and what it is using.

I validated with a spoofed header on one benign request rather than running a full scan. Since the rule only inspects the user agent buffer, a spoofed header exercises exactly the same code path a real sqlmap run would, and it does not flood the index with several thousand events during testing.

## Triage notes

The user agent names the tool and `src_ip` names the source. A scanner user agent coming from an internal host is either sanctioned testing or a machine someone else is already using as a pivot, and telling those apart is the first question worth answering.

Sequence matters more than the alert on its own. A scanner user agent followed by a payload alert from the same source is recon turning into exploitation, and that should escalate. Feeding that pattern into [COR-001](COR-001-recon-to-exploit-chain.md) is exactly why this detection exists.

Volume is the other signal. A burst of requests under one tool user agent is an active scan rather than an incidental hit.

## Tuning

None applied, but there is a decision recorded here.

I left `curl` and `python-requests` out of the pattern on purpose. Both show up in legitimate automation, and `curl` in particular is what I use for my own attack simulations, so including them would have meant flagging my own test traffic and a good deal of harmless activity. The pattern only matches unambiguous offensive tooling.

If sanctioned scanning ever became noisy, for example an authorised nikto baseline running on a schedule, I would suppress by that specific source IP in `threshold.config` rather than removing the tool from the pattern. Same approach I took with the high volume signature in [tuning.md](../docs/tuning.md): scope the exception to the traffic you have explained, leave the detection intact everywhere else.
