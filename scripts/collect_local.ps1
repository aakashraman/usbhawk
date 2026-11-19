<#
.SYNOPSIS
  Collect the USB artifacts usbhawk needs from the LOCAL Windows machine into a triage folder.

.DESCRIPTION
  For lab/testing on a machine you own. Run from an elevated PowerShell.
  For real cases use KAPE (targets: RegistryHives, EventLogs, USBDevicesLogs, LnkFilesAndJumpLists)
  or Velociraptor so collection is forensically sound and logged.
  Saves HKCU, the hive of the account running it: run it at the machine, not over Invoke-Command or
  PsExec (that would save your IR account's hive). Many hosts: docs\INTEGRATIONS.md, "Many hosts on an
  Active Directory domain".

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\collect_local.ps1 -Out C:\usbhawk-triage
  usbhawk sessions --triage C:\usbhawk-triage --out .\out      # work-hours tz auto-detected; --tz to override
#>
param([string]$Out = "C:\usbhawk-triage")

$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this from an elevated (Administrator) PowerShell."
}

$cfg  = Join-Path $Out "C\Windows\System32\config"
$logs = Join-Path $Out "C\Windows\System32\winevt\Logs"
$inf  = Join-Path $Out "C\Windows\INF"
$usr  = Join-Path $Out ("C\Users\" + $env:USERNAME)
New-Item -ItemType Directory -Force -Path $cfg, $logs, $inf, $usr | Out-Null

# 'reg save' writes a clean, consistent hive copy (no transaction-log replay needed)
reg save HKLM\SYSTEM   (Join-Path $cfg "SYSTEM")   /y | Out-Null
reg save HKLM\SOFTWARE (Join-Path $cfg "SOFTWARE") /y | Out-Null
reg save HKCU          (Join-Path $usr "NTUSER.DAT") /y | Out-Null

# Export event logs (Partition/Diagnostic is the key one for USB)
wevtutil epl "Microsoft-Windows-Partition/Diagnostic" (Join-Path $logs "Microsoft-Windows-Partition%4Diagnostic.evtx") /ow:true
wevtutil epl Security (Join-Path $logs "Security.evtx") /ow:true
wevtutil epl System   (Join-Path $logs "System.evtx")   /ow:true

# Sysmon, if installed (module #4 lab: `usbhawk detections run --evtx <triage>`).
# Probe with Get-WinEvent, not wevtutil: under ErrorActionPreference=Stop, PowerShell 5.1 turns wevtutil's
# "log not found" stderr into a terminating error and the rest of the collection would be skipped.
$sysmon = "Microsoft-Windows-Sysmon/Operational"
if (Get-WinEvent -ListLog $sysmon -ErrorAction SilentlyContinue) {
    wevtutil epl $sysmon (Join-Path $logs "Microsoft-Windows-Sysmon%4Operational.evtx") /ow:true
} else {
    Write-Host "Sysmon not installed - skipping its log"
}

# setupapi.dev.log plus its rotated archives (setupapi.dev.<date>_<time>.log, Windows 11): first installs that
# happened before the last rotation are only in the archives. Cleanup tools (e.g. USBOblivion) delete the current
# log; its absence is itself evidence, not a reason to stop.
$setupapi = @(Get-ChildItem "C:\Windows\INF" -Filter "setupapi.dev*.log" -File -ErrorAction SilentlyContinue)
$setupapi | Copy-Item -Destination $inf -Force
Write-Host "Copied $($setupapi.Count) setupapi.dev log(s) (the current one and its rotated archives)"
if (-not (Test-Path "C:\Windows\INF\setupapi.dev.log")) {
    Write-Warning "C:\Windows\INF\setupapi.dev.log is missing (deleted by a cleanup tool?) - collected everything else"
}

Write-Host "Collected to $Out"
Write-Host "Next: usbhawk sessions --triage $Out --out .\out"
