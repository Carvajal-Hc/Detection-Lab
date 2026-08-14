# Telemetry — T1053.005 Scheduled Task

## Environment
- Victim: Windows 11, Sysmon (SwiftOnSecurity config)
- Shipping: Winlogbeat → Elasticsearch
- Data view: winlogbeat-*

## Detection query used
winlog.event_data.Image : *schtasks.exe*

## What the attack generated
- Sysmon Event ID: 1 (process creation)
- Two events, one per created task (OnLogon and OnStartup)

## Key fields observed

CommandLine:
schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"

ParentImage:
C:\Windows\System32\cmd.exe

ParentCommandLine:
"cmd.exe" /c schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe" & schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"

User: LAB1\LAB0

## Fields that give it away
- winlog.event_data.Image ends with schtasks.exe
- winlog.event_data.CommandLine contains "/create"
- ParentCommandLine shows both tasks chained with "&" — sign of automation, not manual admin work

## Observations
- The OnStartup task runs as SYSTEM (/ru system) — highest privilege
- A real admin rarely creates two persistence tasks in a single chained command
- calc.exe is the harmless placeholder; real malware would go there

## V2 Telemetry — Windows Security Event ID 4698

After enabling the audit subcategory (see evasion.md), scheduled-task
creation became visible through **Event ID 4698 — "A scheduled task was
created"**, logged by Microsoft-Windows-Security-Auditing. Unlike Sysmon
Event 1 (which only sees the process that created the task), 4698 fires on
the task creation itself — so it catches the technique regardless of whether
the task was created via schtasks.exe, PowerShell, WMI, or the API.

### Fields recorded by 4698 (reference — Windows Security Auditing)
- SubjectUserSid / SubjectUserName / SubjectDomainName — who created the task
- SubjectLogonId — logon ID, to correlate with the actor's session (Event 4624)
- TaskName — the task's name / path
- TaskContent — the full task definition as XML, which is what makes this
  event valuable. It contains:
    - <Command> / <Arguments>   — what actually runs (the payload)
    - <Principal> <RunLevel>    — as whom (SYSTEM / HighestAvailable = red flag)
    - <Triggers>                — when it fires (logon / boot = classic persistence)
    - <Settings> <Hidden>       — whether the task hides itself

### What I confirmed in this exercise
- 4698 fired for the PowerShell-created task: TaskName = \EvasionTest_PS2
- The event carried the full TaskContent XML (the complete task definition),
  giving more context than the original Sysmon process event.

Reference: MITRE T1053.005 · Microsoft "4698(S) A scheduled task was created".