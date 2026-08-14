# T1053.005 — Scheduled Task (Persistence)

## What it is
Scheduled Task persistence. An attacker creates a Windows scheduled 
task that runs automatically at logon or at system startup, giving 
them a reliable way back into the machine after a reboot.

## Why attackers use it
Persistence. Once an attacker has access, they want to keep it. A 
scheduled task survives reboots, and when set to run as SYSTEM it 
executes with the highest privilege on the machine, with no user 
interaction required.

## What I executed
Atomic Red Team test T1053.005 #1, which creates two tasks:

- `T1053_005_OnLogon`  — triggers at user logon
- `T1053_005_OnStartup` — triggers at system startup, runs as SYSTEM

Both run `cmd.exe /c calc.exe`. Calculator is the harmless stand-in 
for what would be actual malware in a real attack.

Command:
    Invoke-AtomicTest T1053.005 -TestNumbers 1

## What this exercise turned into
This started as a simple "detect a scheduled task" rule and became a 
full detection-engineering cycle:

1. Wrote a rule (v1) that detected `schtasks.exe` with `/create`.
2. Evaded it by creating the same persistence with PowerShell 
   (`Register-ScheduledTask`) instead of schtasks.exe. v1 was blind to it.
3. Investigated where the evasion *should* have been visible 
   (Security Event ID 4698).
4. Found that 4698 wasn't being generated at all — the audit policy 
   for scheduled-task creation was disabled by default. A real 
   collection blind spot.
5. Enabled the audit subcategory, confirmed 4698 now fires and reaches 
   the SIEM.
6. Rewrote the rule (v2) to detect Event 4698 — the behavior of 
   creating a task — instead of the specific tool used.

Full detail in `evasion.md`.

## Key lesson
Detect the behavior, not the tool. v1 watched for a specific binary 
and was trivially bypassed by using a different one. v2 watches for the 
event Windows generates whenever a task is created, regardless of how. 
The trade-off: v2 is harder to evade but noisier, since legitimate 
software creates tasks too. There is no perfect rule — only balance 
decisions between coverage and false positives.

## Environment
- Victim: Windows 11, Sysmon (SwiftOnSecurity config)
- Shipping: Winlogbeat → Elasticsearch → Kibana
- Attacker tooling: Atomic Red Team

## MITRE reference
https://attack.mitre.org/techniques/T1053/005/