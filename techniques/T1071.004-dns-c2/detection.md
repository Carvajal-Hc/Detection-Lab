# Detection — DNS Command & Control (T1071.004)

Detections are written in **ES|QL**, because the robust logic needs to *count*
distinct values — something KQL and Lucene cannot do (they only filter events one
at a time). All queries run against the real field names in this stack
(`winlog.event_data.*`); `dns.question.name` is `null` here (see `telemetry.md`).

## Hunt — distribution of DNS queries

The signal is "one process, one parent domain, many distinct names." This query
makes that visible, baseline and anomaly side by side:

```esql
FROM winlogbeat-*
| WHERE winlog.channel == "Microsoft-Windows-Sysmon/Operational" AND winlog.event_id == "22"
| EVAL nombre = TO_LOWER(winlog.event_data.QueryName)
| EVAL partes = SPLIT(nombre, ".")
| EVAL etiqueta = MV_FIRST(partes), dominio = MV_CONCAT(MV_SLICE(partes, -2, -1), ".")
| EVAL largo = LENGTH(etiqueta)
| STATS consultas = COUNT(*), distintos = COUNT_DISTINCT(nombre), largo_max = MAX(largo) BY winlog.event_data.Image, dominio
| SORT consultas DESC
```

The simulation surfaces at the top: `powershell.exe` / parent domain, 52 queries,
52 distinct, max label length 40. Baseline rows (OneDrive, svchost) sit far below
with few distinct names and short labels.

## Rule v1 and the two conversion findings

The Sigma rule (`rule.yml`) was converted with `sigma-cli` + the `ecs_windows`
pipeline. The conversion produced **no error**, yet the output would have matched
nothing in this stack. Two silent failures:

**Finding 1 — wrong fields.** The pipeline emitted ECS names
(`dns.question.name`, `process.executable.caseless`) and even mis-placed the host
as `winlog.event_data.Computer`. This stack stores the data under
`winlog.event_data.*` / `winlog.computer_name`.

**Finding 2 — regex anchoring differs.** Sigma's `|re` matches a pattern
*anywhere* in the value. Elastic's regex engine does **not** support `^`/`$`
anchors and requires the pattern to match the **entire** term
([Elastic docs](https://www.elastic.co/docs/reference/query-languages/query-dsl/regexp-syntax)).
The converter copied the pattern `^[a-zA-Z0-9]{25,}\.` verbatim; against a full
name like `abc....c2lab.example.org` it matches nothing. Confirmed empirically: 0
results.

> **Lesson for the report:** a converted rule that throws no error is **not** a
> working rule. It is validated against a real attack or it is not trusted.

**Corrected v1** (fields fixed, pattern made whole-term with `.*`):

```esql
FROM winlogbeat-*
| WHERE winlog.channel == "Microsoft-Windows-Sysmon/Operational" AND winlog.event_id == "22"
| WHERE winlog.event_data.QueryName RLIKE "[a-zA-Z0-9]{25,}\\..*"
| EVAL timebucket = DATE_TRUNC(10 minutes, @timestamp)
| STATS value_count = COUNT_DISTINCT(winlog.event_data.QueryName) BY timebucket, winlog.computer_name, winlog.event_data.Image
| WHERE value_count >= 20
```

Validated: one row, `value_count = 50`, `LAB1`, `powershell.exe`. This is v1 —
and it is fragile (see `evasion.md`).

## Rule v2 — detect the behavior, not the form

v1 keys on a single fragile signal: the length of the *first label* in a *fixed*
10-minute bucket. v2 keys on the behavior that a C2 channel cannot hide — one
process generating many unique names under one parent domain — and measures
*everything before the registrable domain*, so breaking the name into shorter or
hyphenated labels does not help:

```esql
FROM winlogbeat-*
| WHERE winlog.channel == "Microsoft-Windows-Sysmon/Operational" AND winlog.event_id == "22"
| EVAL nombre = TO_LOWER(winlog.event_data.QueryName)
| EVAL partes = SPLIT(nombre, ".")
| EVAL dominio = MV_CONCAT(MV_SLICE(partes, -2, -1), ".")
| EVAL antes_del_dominio = LENGTH(nombre) - LENGTH(dominio)
| STATS nombres_distintos = COUNT_DISTINCT(nombre), max_antes = MAX(antes_del_dominio) BY winlog.computer_name, winlog.event_data.Image, dominio
| WHERE nombres_distintos >= 15 AND max_antes >= 15
| SORT nombres_distintos DESC
```

## Why not Sigma for v2?

v2's key improvement — grouping by the **registrable parent domain** — cannot be
expressed in Sigma, which has no way to compute the parent domain from a name.
The portable Sigma rule (`rule.yml`) therefore groups only by host + process; the
parent-domain precision lives in this ES|QL. A real example of a portable format
losing detail in translation.

## Caveats

- Thresholds (`>= 15` distinct, `>= 15` chars; v1 used 25 / 20) are **hypotheses
  tuned on ~30 minutes of one host's baseline.** A production deployment needs a
  multi-day baseline; CDNs and security agents can legitimately use long hashed
  subdomains.
- v1's fixed `DATE_TRUNC` bucket has a boundary weakness: activity split across
  two buckets is undercounted. A production rule should use a rolling look-back
  window (overlapping runs), not fixed buckets.
