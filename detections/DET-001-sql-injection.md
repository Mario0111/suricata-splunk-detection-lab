# DET-001: SQL Injection, UNION SELECT in URI

| | |
|---|---|
| SID | 1000002 |
| ATT&CK | [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), Initial Access |
| Status | Deployed and validated |
| Rule file | `/var/lib/suricata/rules/local.rules` |

## Background

SQL injection through the request URI is one of the more common attacks against anything with a web front end. A `UNION SELECT` payload tries to append attacker chosen columns onto the result set of a legitimate query, and the keyword pair is a strong indicator because it almost never appears in normal request URIs. Metasploitable 2 hosts several applications that accept this kind of input, including Mutillidae, DVWA and phpMyAdmin.

## Rule design

The rule matches `UNION` followed by `SELECT` in the HTTP request URI.

Three decisions went into it.

**Match on `http.uri` rather than raw payload.** Scoping to the HTTP parser's URI buffer means the rule only ever inspects request URIs. It is cheaper than raw content matching and it cannot fire on the keywords appearing somewhere else in a packet.

**Use `pcre` rather than a plain content match.** Attackers vary the separator between the keywords, and the URI may or may not be decoded by the time the rule sees it. One regex covers all of it:

```
/union(?:\s|%20|\+)+(?:all(?:\s|%20|\+)+)?select/i
```

`(?:\s|%20|\+)+` matches a literal space, a percent encoded space or a plus encoded space, so `UNION SELECT`, `UNION%20SELECT` and `UNION+SELECT` all fire. `(?:all(?:\s|%20|\+)+)?` optionally absorbs `UNION ALL SELECT`, a very common variant that an adjacent keyword match would miss entirely. The `/i` flag handles `UnIoN sElEcT` style casing evasion.

**Direction is `any any -> $HOME_NET any`.** Every host in this lab sits inside `10.10.10.0/24`, so both attacker and victim fall within HOME_NET. The textbook `$EXTERNAL_NET -> $HOME_NET` form would never fire here. Using `any` as the source also keeps the rule useful for lateral movement, which is the realistic case once an attacker already has a foothold somewhere internal.

What it does not catch: injection delivered in a POST body, and payloads obfuscated with inline comments or nested encoding. That is a boundary I accepted rather than missed. Broadening the logic would cost precision, so wider coverage belongs in a separate rule with its own SID.

## The rule

```
alert http any any -> $HOME_NET any (msg:"LOCAL WEB SQL Injection Attempt - UNION SELECT in URI"; flow:to_server,established; http.uri; pcre:"/union(?:\s|%20|\+)+(?:all(?:\s|%20|\+)+)?select/i"; classtype:web-application-attack; sid:1000002; rev:1;)
```

## Validation

`sudo suricata -T -c /etc/suricata/suricata.yaml` passed, and the rule loaded after a service restart.

I then ran the attack from Kali against the victim:

```bash
curl "http://10.10.10.20/?id=1%20UNION%20SELECT%201"
```

The server returned its default Metasploitable landing page. The `%20` between the keywords is what the separator group in the regex exists to handle.

Confirmed in Splunk:

```spl
index=suricata sourcetype=suricata:eve event_type=alert alert.signature_id=1000002
| table _time src_ip dest_ip http.hostname http.url alert.signature
```

The alert came through with `src_ip=10.10.10.10`, `dest_ip=10.10.10.20` and the payload visible in `http.url`, inside the usual few seconds of pipeline latency.

## Triage notes

For an analyst picking this up:

The payload is in `http.url`, and a literal `UNION SELECT` against a query parameter is about as unambiguous as web attack indicators get. `src_ip` is the attacker, `dest_ip` is the target.

Pivoting on `src_ip` tells you whether this is an isolated probe or part of a wider attack against the same host, which is usually the more important question. Correlating against the HTTP response and any follow up requests indicates whether the injection actually returned data, since a 200 with an unusually large body is a different situation from a rejected request.

False positive risk is low. The realistic sources would be a security tool or an application that legitimately puts SQL in URLs, and neither exists in this environment.

## Tuning

None applied. The rule is high signal, low volume, and produced no false positives during validation.

If I wanted POST body or obfuscated injection coverage later, that would be a new detection with broader logic and its own SID rather than a change to this one. Keeping this rule narrow is what keeps it precise.
