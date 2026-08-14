<div align="center">

# 🔬 Detection Lab

**A home SOC lab where I turn attacks into detections — and then try to break them.**

For each MITRE ATT&CK technique: run the real attack, observe its telemetry,
write a detection, evade my own rule, and fix what the evasion exposes.

![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-C7302B)
![Detections](https://img.shields.io/badge/detections-Sigma-008BB7)
![SIEM](https://img.shields.io/badge/SIEM-Elastic-005571?logo=elastic&logoColor=white)
![Telemetry](https://img.shields.io/badge/telemetry-Sysmon-0078D6)
![Status](https://img.shields.io/badge/status-active-brightgreen)

</div>

---

## 🧭 What this is

A personal detection-engineering lab. For each technique I run the real attack in a controlled environment, watch the telemetry it produces, write a detection rule, and then **attack my own rule** to find where it goes blind — the step that separates detecting a *tool* from detecting a *behavior*.

It's a learning lab: rules are `experimental` and tuned for understanding, not production deployment. Every writeup is honest about what its detection does and doesn't catch.

## 🧱 Lab setup

| Component | Tool |
|-----------|------|
| Victim | Windows 11 + **Sysmon** (SwiftOnSecurity config) |
| Shipping | **Winlogbeat** → **Elasticsearch** → **Kibana** |
| Adversary emulation | **Atomic Red Team** |
| Framework | **MITRE ATT&CK** |

Runs across separate machines (victim / SIEM / workstation), mirroring the real-world separation between what is monitored and what does the monitoring.

## 🔁 The cycle (per technique)

1. **Execute** the attack (Atomic Red Team, mapped to ATT&CK).
2. **Observe** the telemetry it generates.
3. **Write** a detection rule (Sigma).
4. **Evade** my own rule — think like the attacker.
5. **Fix** what the evasion exposed, and document the whole thing.

> Steps 4–5 are the point. A rule you haven't tried to break is a rule you don't understand yet.

## 🗂️ Coverage matrix

| Technique | ATT&CK ID | Tactic | Detection | Status |
|-----------|-----------|--------|-----------|:------:|
| [Scheduled Task](techniques/T1053.005-scheduled-task/) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Persistence | Security Event **4698** (behavior-based) | ✅ |

**Next up (planned):** Registry Run keys (T1547.001) · PowerShell execution (T1059.001) · LSASS credential access (T1003).

## 📁 How each technique is documented

Every folder under [`techniques/`](techniques/) follows the same shape:

| File | Contents |
|------|----------|
| `README.md` | What the technique is, what I executed, the key lesson. |
| `telemetry.md` | The telemetry the attack generates — Event IDs and key fields. |
| `rule.yml` | The Sigma detection rule(s), tool-based → behavior-based. |
| `evasion.md` | How I evaded my own rule, and what I changed to fix it. |

## ⚠️ Note

These are **learning-lab detections** at `experimental` status. A rule catching an attack here means the configured logic fired *in this environment* — not that it is production-ready or evasion-proof. Coverage-vs-noise trade-offs are documented per technique.

---

<div align="center"><i>Detect the behavior, not the tool.</i></div>
