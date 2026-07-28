# OBS-006: Expanding the Detection Set

One detection is a proof of concept. I wanted a set that follows an attacker through stages, so I added three more.

| SID | Detection | ATT&CK | Tactic |
|---|---|---|---|
| 1000003 | Command injection, shell metacharacter with command in URI | T1059 | Execution |
| 1000004 | Directory traversal and LFI | T1083 | Discovery |
| 1000005 | Suspicious user agent, known attack tooling | T1595.002 | Reconnaissance |

With DET-001 already covering initial access, that gives a chain: recon, initial access, execution, discovery.

All three use `http.*` sticky buffers with `pcre`, which handles the encoding variations that a plain content match would miss, spaces against `%20` against `+`, and case changes. Direction stays `any any -> $HOME_NET any` for the same reason as DET-001, since a flat lab subnet puts the attacker inside HOME_NET.

I favoured precision over recall throughout. The command injection rule uses a word bounded allow list of commands rather than trying to catch everything, and the user agent rule leaves out `curl` and `python-requests` on purpose so it does not flag legitimate automation or my own testing.

## The first validation run failed

`suricata -T` rejected 1000003:

```
E: detect-parse: bad option value formatting (possible missing semicolon) for keyword pcre: '"/['
E: suricata: Loading signatures failed.
```

Suricata tokenises rule options on `;` before PCRE compiles anything, so the literal semicolon in my character class `[;|&`]` cut the `pcre:` option short. Writing it as `\x3b` fixed it.

The detail worth keeping is the second error line. It did not skip the broken rule, it failed to load the ruleset. Deploying that without checking would have left the sensor running with no detections at all while the service still looked healthy. Full writeup in [DET-002](../detections/DET-002-command-injection.md).

## Validation

After the fix, all three confirmed end to end. Rules loaded, attacks run from Kali, alerts indexed and returned by search in Splunk.

All three requests came back with the same default Metasploitable page, because the web root ignores `cmd`, `file` and the user agent entirely. Every rule fired anyway.

That is worth recording because it looks like a failure if you are watching the wrong side. Suricata inspects the request as it crosses the wire, so an alert means the attempt was seen, not that the target was vulnerable or that anything succeeded. Confirming a detection means checking Splunk, not reading the HTTP response. Whether an attempt actually landed is a separate question, and one that belongs to the analyst rather than the rule.

## Next

A correlation search that ties a scanner user agent hit to the payload alerts that follow it from the same source, which is the relationship these four detections were designed around.
