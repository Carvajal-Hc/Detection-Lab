# Evasion & Detection Improvement — T1053.005

## Starting point: rule v1
My first detection rule looked for the tool:

    Image ends with "\schtasks.exe"
    AND CommandLine contains "/create"

It correctly caught the original Atomic Red Team test, which uses 
schtasks.exe to create the tasks. So far so good.

## Hypothesis (thinking like an attacker)
The rule watches for a specific binary. Windows lets you create 
scheduled tasks in more than one way. If I create the same persistence 
WITHOUT calling schtasks.exe, the rule should go blind.

## The evasion
Instead of schtasks.exe, I created the same persistence using the 
native PowerShell cmdlets:

    $action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c calc.exe"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Register-ScheduledTask -TaskName "EvasionTest_PS" -Action $action -Trigger $trigger -User "SYSTEM"

Same outcome as the original attack — a task that runs at startup as 
SYSTEM — but created through a completely different path.

## Result: v1 was blind
I confirmed the task existed:

    Get-ScheduledTask -TaskName "EvasionTest_PS"   → task found

But my detection query returned nothing:

    winlog.event_data.Image : *schtasks.exe*        → no results

The persistence was in place and my rule never saw it. Evasion 
successful.

## Digging deeper: where SHOULD this be visible?
The right place to catch task creation regardless of tool is Windows 
Security Event ID 4698 ("A scheduled task was created"), which fires 
on the creation itself, not on the process that triggered it.

I checked whether 4698 was being generated at all:

    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4698}
    → "No events found"

## The real finding: a collection blind spot
4698 wasn't just missing from my rule — it wasn't being GENERATED at 
all. The audit subcategory that produces it ("Other Object Access 
Events") is disabled by default on a standard Windows install. My 
endpoint was structurally incapable of seeing this, and I wouldn't 
have known until an attacker used this exact path.

Note: on a Spanish-language Windows, auditpol requires the subcategory 
name in Spanish ("Otros eventos de acceso a objetos") or its 
language-independent GUID. This is why production tooling uses GUIDs.

## The fix
Enabled the audit subcategory:

    auditpol /set /subcategory:"Otros eventos de acceso a objetos" /success:enable /failure:enable

Created a new test task and confirmed 4698 now fires:

    Get-WinEvent ... ID=4698 → event found, TaskName \EvasionTest_PS2

And confirmed it reaches the SIEM:

    event.code : "4698" → event present in Kibana, with full TaskContent XML

Interesting bonus: 4698 gives MORE context than the original process 
event — it includes the full task definition (name, user, the complete 
XML), not just the command that created it.

## Rule v2
Rewrote the detection to watch the behavior instead of the tool: 
Event ID 4698. This fires whenever a task is created — via schtasks, 
PowerShell, WMI, or direct API — so the tool-swap evasion no longer 
works. See rule.yml.

## Trade-off (honest limitation)
v2 is broader and therefore noisier. Legitimate installers and admin 
scripts create scheduled tasks constantly, so v2 will produce more 
false positives than v1. A v3 refinement would add context — e.g. 
alert only when the task runs as SYSTEM, or when the task action 
contains cmd.exe / powershell.exe. Not implemented yet.

## Takeaway
- Detecting a tool is not the same as detecting a behavior.
- You cannot detect what you are not collecting. The most dangerous 
  gap wasn't a weak rule — it was telemetry that didn't exist.
- Every detection is a balance between coverage and noise. There is 
  no perfect rule, only deliberate trade-offs.