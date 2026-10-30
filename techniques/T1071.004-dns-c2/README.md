# T1071.004 — DNS Command & Control

## What it is
A DNS C2 channel hides data inside name-resolution queries. The implant
encodes data into long, unique subdomains (`<encoded>.c2.example.org`) and reads
commands back from the responses, often TXT records.

## Why attackers use it
DNS is almost never blocked — every network has to allow name resolution to
work. The traffic looks legitimate at the firewall, so the channel blends in.
Detection has to live in the *pattern of the queries*, not at the network
boundary.

## What I executed
In an isolated Hyper-V VM (Windows 11 + Sysmon), I generated the C2 query
pattern: one process (`powershell.exe`) resolving 50 unique 40-character random
subdomains under a single parent domain. No real channel — the goal was the
telemetry. Captured via Sysmon Event ID 22 (DnsQuery). I then tested variations
and an alternate resolver (see `evasion.md`).

## What this exercise turned into
It started as "detect long DNS subdomains" and became a full detection cycle:

1. Built the baseline — normal Event 22 is constant (OneDrive, svchost) but with
   *few repeated* names. A C2 channel never repeats a name.
2. Wrote a detection (v1) for long first-label names and converted the Sigma rule
   to Elastic with `sigma-cli`.
3. Found **two silent conversion failures**: the pipeline emitted ECS field names
   this stack doesn't use (`dns.question.name` is `null` here; the real field is
   `winlog.event_data.QueryName`), and Elastic's regex engine doesn't support
   `^`/`$` anchors and matches the *whole term* — so the converted pattern matched
   nothing, with no error. Caught only by validating against real telemetry.
4. Corrected and validated v1 in ES|QL (50/50 on `LAB1` / `powershell.exe`).
5. Evaded v1 with form variations (shorter labels, hyphens, splitting the data
   across labels). Rewrote it (v2) to key on the *behavior* — many unique names
   under one parent domain from one process — which caught all of them.
6. Found a telemetry blind spot: a resolver that bypasses the Windows DNS client
   produces **no Event 22 at all**. The process was still visible via Event 1
   (process creation). The fix is a second data source (DNS server logs or Zeek),
   not a better rule.

Full detail in `detection.md` and `evasion.md`.

## Key lesson
Detect the behavior, not the form. v1 watched for a specific name shape and was
bypassed by reshaping the name; v2 watches the behavior a C2 channel can't hide.
And a converted rule that throws no error is not a validated rule — it is
validated against a real attack or it is not trusted.

## Environment
- Victim: Windows 11, Sysmon (SwiftOnSecurity config), hostname `LAB1`
- Shipping: Winlogbeat 9.4.3 → Elasticsearch → Kibana
- Network: isolated Hyper-V internal switch

## MITRE reference
https://attack.mitre.org/techniques/T1071/004/
