# Telemetry — DNS Command & Control (T1071.004)

**Tactic:** Command and Control · **ATT&CK:** [T1071.004 — Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)

## What the technique does

A DNS C2 channel hides data inside name-resolution queries. Instead of opening a
direct connection (which a firewall blocks), the implant encodes data into long,
unique subdomains — `a7f3k9d2j...encoded....c2.example.org` — and reads commands
back from the response, often a TXT record. DNS is almost never blocked, so the
traffic looks legitimate at the firewall. Detection therefore lives in the
**pattern of the queries**, not at the network boundary.

## Lab

| Piece | Detail |
|---|---|
| Victim | Windows 11 + Sysmon (SwiftOnSecurity config), hostname `LAB1` |
| Shipping | Winlogbeat 9.4.3 → Elasticsearch / Kibana 9.4.3 (Docker) |
| Network | Isolated Hyper-V internal switch (victim `192.168.100.10`, SIEM host `192.168.100.1`) |

**Isolation note (finding):** the victim initially had a second adapter on the
Hyper-V Default Switch with an internet-facing DNS server, so queries left the VM.
It was isolated by disconnecting that adapter **from Hyper-V** (not from inside
Windows, where an admin-level process could re-enable it). Before isolation a
failed lookup returned `QueryStatus 9003` (NXDOMAIN — a real server answered "no
such name"); after isolation it returned `QueryStatus 1460` (timeout — nothing
answered). This confirmed the isolation held.

## Primary event — Sysmon Event ID 22 (DnsQuery)

Channel: `Microsoft-Windows-Sysmon/Operational`

| Field (real, in this stack) | Meaning |
|---|---|
| `winlog.event_data.QueryName` | The name queried (where the encoded subdomain lives) |
| `winlog.event_data.QueryStatus` | Windows result code: `0` success · `9003` NXDOMAIN · `1460` timeout |
| `winlog.event_data.Image` | The process that made the query |
| `winlog.computer_name` | The host (NOT `event_data.Computer`) |

**Field-mapping finding:** the ECS field `dns.question.name` is `null` in this
stack — Winlogbeat is forwarding Sysmon fields verbatim, without ECS
normalization. Detections must be written against `winlog.event_data.*`, not the
ECS names. This matters for Sigma conversion (see `detection.md`).

## Baseline (what normal looks like)

Over ~15 minutes of an idle host, Event ID 22 is generated constantly by normal
software. The point of a baseline is to know this noise so the rule does not fire
on it:

- `OneDrive.exe` → `ecs.office.com`, `oneclient.sfx.ms` — `QueryStatus 0`
- `svchost.exe` → `msftconnecttest.com`, `wpad` — connectivity / proxy checks
- `spoolsv.exe` → `lab1` (its own host)

The distinguishing feature is **distribution, not volume**: legitimate software
resolves a *small set of repeated names*. `svchost` made 5 queries to only 2
distinct names. A C2 channel never repeats a name — each query carries new
encoded data — so distinct-name count tracks total query count.

## Telemetry generated for this cycle

A controlled, benign generator was run **inside the isolated VM** to produce the
C2 *pattern* (not a real channel): a loop issuing 50 resolutions, each a unique
40-character random alphanumeric subdomain under a single controlled parent
domain, TXT type. With no resolver reachable, every query fails — which is fine:
the goal is the telemetry, not a working channel. Result: 50 Event ID 22 records
from `powershell.exe`, 50 distinct names, all under one parent domain.

## Telemetry limitations (findings)

1. **Query type is not recorded.** Sysmon Event ID 22 does not log whether the
   query was `TXT`, `A`, etc. That field (`qtype`) only exists in DNS **server**
   logs or network monitoring (Zeek `dns.log`).
2. **Only resolutions through the Windows DNS client are seen.** A process that
   resolves names without going through that client service produces **no Event
   ID 22 at all** — not a rule failure, a visibility gap. In this cycle,
   `nslookup.exe` runs were absent from Event ID 22 but fully visible via **Sysmon
   Event ID 1 (process creation)**. The defensive answer is a second data source
   (DNS server query logging or Zeek `dns.log`), covered in `evasion.md`.
