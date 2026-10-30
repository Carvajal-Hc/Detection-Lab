# Evasion & hardening — DNS C2 (T1071.004)

> The point of this step is not to catalog bypasses. It is to find where the
> rule is brittle, harden it, and surface the limits of the data itself.

## v1's assumptions

The v1 rule (long **first label**, counted in a **fixed** 10-minute bucket) rests
on four assumptions. Each is a thing an operator could change:

1. The encoded data is one **long first label** (25+ chars).
2. That label is **unbroken** alphanumeric.
3. The data lives in **one** label.
4. Enough queries land in a **single fixed time bucket**.

## Tested — form variations (caught by v2)

Three variations that keep the *behavior* (one process, many unique names, one
parent domain) but change the *form* of the name were generated in the isolated
VM, each under its own controlled parent domain:

| Variation | Idea | v1 | v2 |
|---|---|:--:|:--:|
| Shorter labels (20 chars) | fall under the 25-char filter | evades | **caught** |
| Hyphen-broken (`xxxxx-xxxxx-...`) | no 25 unbroken chars | evades | **caught** |
| Split across labels (3× short) | no single long label | evades | **caught** |

v2 catches all three because it measures **everything before the registrable
parent domain** and counts **distinct names per parent domain per process** — it
keys on the behavior, not the shape of the name. Confirmed result:

| Parent domain | Distinct names | Chars before domain |
|---|:--:|:--:|
| original simulation | 52 | 47 |
| split-across-labels | 30 | 48 |
| hyphen-broken | 30 | 48 |
| shorter-labels | 30 | 21 |

The shorter-labels case is the tightest (21 vs the 15 threshold) and marks v2's
most sensitive edge — a reason thresholds need a longer baseline before
production use.

## The real gap — telemetry, not logic

One variation resolved names **without going through the Windows DNS client**.
Result: **no Sysmon Event ID 22 at all**. No version of the rule can catch what
produces no event. This is a visibility gap, not a rule weakness — the same class
of finding as the Event 4698 blind spot in the Scheduled Task cycle.

The process was still visible via **Sysmon Event ID 1 (process creation)**: 30
`nslookup.exe` executions on `LAB1`, with the queried names in the command line.
So a *secondary* behavioral detection exists — but relying on it is fragile.

**Recommendation:** do not depend on a single endpoint DNS event. Add a second,
independent source so resolutions that bypass the endpoint client are still seen:

- DNS **server** query logging, or
- Network-level DNS monitoring — Zeek `dns.log` (which also recovers the query
  **type**, the `qtype` field Sysmon 22 omits).

This connects directly to the planned network phase of the lab (the dedicated
attacker/sensor host), where this detection should be re-validated end to end.

## Status

Experimental. Rules fired against *this* environment's telemetry; that is not a
claim of production-readiness or evasion-proofing. Thresholds are tuned on ~30
minutes of one host's baseline.
