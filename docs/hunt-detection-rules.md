# Hunt: detection-as-code for USB threats (`usbhawk detections`, module #4)

> **The question:** *Can we catch USB exfiltration and evidence wiping while it happens, not days later in a triage?*

Modules #2 (`sessions`) and #3 (`tamper`) hunt **after the fact**, in a collected triage folder. Module #4 turns the
same hypotheses into **live detection rules** for your SIEM / EDR. Each hypothesis is written **once**, as a
platform-neutral YAML rule with its own test events, and generated for:

| Target | Output | Runs on |
|---|---|---|
| `sigma` | SigmaHQ-style YAML (+ correlation rules) | Any Sigma backend (`sigma-cli convert`, pySigma) |
| `elastic` | ES\|QL queries over ECS + `usbhawk_rules.ndjson` (Kibana import) | Elastic Security (Elastic Agent / Winlogbeat data) |
| `sentinel` | KQL | Microsoft Sentinel / Defender XDR advanced hunting |

Thresholds and lists (bulk-copy count, archive extensions, work hours, cleanup-tool names) are **not typed into the
rules**: they are read from the same definitions the offline hunts use, so a live alert and an offline finding can
never disagree about what counts as "bulk" or as a "cleanup tool".

## Quick start

```powershell
usbhawk detections list                                   # the 8 hypotheses, 12 detections
usbhawk detections test                                   # validate every rule + run its 59 test events
usbhawk detections build --out build                      # build/sigma, build/elastic, build/sentinel
usbhawk detections --config config\scoring.toml build     # your thresholds, extensions and work hours
usbhawk detections run --evtx D:\triage\C\Windows\System32\winevt\Logs --removable-drives F:
pip install -e ".[sigma]"; pytest tests\hunt_detection_rules   # also validate with pySigma + SigmaHQ validators
```

## How it works

```
 src/usbhawk/detections/rules/H1..H8_*.yml      one hypothesis each: logic + metadata + test events
            │   ${cleanup_tools.high}  ${archive_extensions}  ${thresholds.bulk_files}  ${work_hours}
            │      └── filled from tamper.CLEANUP_TOOLS and the scoring config (same as modules #2 / #3)
            ▼
 core.py      validate · reference evaluator (the rules' meaning) · run the rules' own tests
            ▼
 generators   Sigma (+ correlation) · Elastic ES|QL + Kibana ndjson · Sentinel KQL      → build/
 replay.py    real .evtx (Sysmon, Security, System) → neutral events → every detection    → alerts.jsonl
```

The evaluator in `core.py` *is* the specification: every generator is tested to translate to exactly its behaviour,
and `detections run` uses it to replay real logs.

## The hypotheses

| # | Rule | Detections (level) | Telemetry | ATT&CK (v18) | Offline counterpart |
|---|---|---|---|---|---|
| H1 | USB Storage Device Connected | any USB storage (low) · **not seen in 30 days** (medium) | Security 6416 / MDE `PnpDeviceConnected` | T1052.001, T1200 | `sessions` first_seen_device |
| H2 | USB Storage Connected Outside Work Hours | local-clock work hours (medium) | same | T1052.001 | `sessions` off_hours |
| H3 | Bulk File Copy to Removable Media | **≥ 50 files / 10 min** per user+host (high) | Sysmon 11 / ECS file / MDE `DeviceFileEvents` | T1052.001 | `sessions` bulk_transfer |
| H4 | Archive Written to Removable Media | archive / pst / kdbx … (medium) | same | T1560, T1052.001 | `sessions` archive_written |
| H5 | Disk Formatted or Repartitioned From the Command Line | format.com, diskpart, Format-Volume … (medium) | process creation | T1070, T1561 | `sessions` reformat_or_repartition |
| H6 | USB History Cleanup Tool Executed | USBOblivion (high) · general cleaners (medium) | process creation | T1070, T1685.005 | `tamper` cleanup_tool_execution |
| H7 | Windows Event Log Cleared | 1102 (high) · 104 (medium) · clearing commands (high) | Security / System / process creation | T1685.005 | `tamper` log_cleared |
| H8 | USB Device History Deleted From the Registry | deletes under Enum / MountedDevices / MountPoints2 … (high) | Sysmon 12 / ECS registry / MDE `DeviceRegistryEvents` | T1070, T1112 | `tamper` orphaned_device_reference |

ATT&CK IDs were checked against attack.mitre.org (v18): TA0005 is now **Stealth**, **Defense Impairment** (TA0112)
is new, and Clear Windows Event Logs moved from T1070.001 to **T1685.005**, matching SigmaHQ's current tags.

## Use cases and sample alerts

One fictional insider timeline (host `NW-FIN-WS042`, user `NW\j.doe`, Friday evening) replayed through the rules with
`usbhawk detections run`. Each line is real tool output; the device and file names are invented.

**H1: a USB storage device is connected** (and nobody has seen it in 30 days)
```
2026-10-30 21:14:00  H1  usb_storage_connected      low     device_id=USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP\60A44C413D5FF380E95A0B7D&0; device_description=USB Mass Storage Device
2026-10-30 21:14:00  H1  first_seen_usb_storage     medium  USBSTOR\DISK&VEN_KINGSTON&...\60A44C413D5FF380E95A0B7D&0 first seen at 2026-10-30T21:14:00Z (a live rule looks back 30 days)
```

**H2: it happens outside work hours** (21:14 on a Friday, judged on the configured local clock)
```
2026-10-30 21:14:00  H2  usb_storage_off_hours      medium  device_id=USBSTOR\DISK&VEN_KINGSTON&...\60A44C413D5FF380E95A0B7D&0; device_description=USB Mass Storage Device
```

**H3: dozens of files are copied to the stick in minutes**
```
2026-10-30 21:16:00  H3  bulk_copy_to_usb           high    60 matching events between 21:16:00Z and 21:19:56Z (threshold 50 per 10 min); e.g. F:\Q3\board-pack-00.docx, F:\Q3\board-pack-01.docx, ...
```

**H4: an archive lands on the stick** (one file that can hold thousands of documents)
```
2026-10-30 21:22:00  H4  archive_to_usb             medium  process_name=7zG.exe; file_path=F:\Q3\finance-share.7z; user=NW\j.doe
```

**H5: the stick is reformatted** (hiding what it carried)
```
2026-10-30 21:34:00  H5  format_command             medium  process_name=format.com; command_line=format.com F: /FS:exFAT /Q /Y; user=NW\j.doe
```

**H6: a USB history eraser is started**
```
2026-10-30 21:39:00  H6  usb_cleaner                high    process_name=USBOblivion64.exe; command_line=USBOblivion64.exe -enable -auto; user=NW\j.doe
```

**H8: the stick's registry records are deleted**
```
2026-10-30 21:39:30  H8  usb_registry_trace_deleted high    process_name=USBOblivion64.exe; registry_path=HKLM\System\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Kingston&...\60A44C413D5FF380E95A0B7D&0
```

**H7: the event logs are cleared** (the command, then Windows' own record of it)
```
2026-10-30 21:40:00  H7  clear_command              high    process_name=wevtutil.exe; command_line=wevtutil.exe cl Security; user=NW\j.doe
2026-10-30 21:40:01  H7  security_log_cleared       high    channel=Security; event_id=1102; provider=Microsoft-Windows-Eventlog; user=NW\j.doe
```

Read together, the alerts tell the whole story in order; any one of H6, H7 or H8 on its own is worth an immediate
triage collection, before the evidence is gone.

## Each hypothesis explained

What each alert means, what commonly triggers it innocently, and what to do next. The same text ships inside each
rule (`description`, `false_positives`, `response`), so the Elastic rules carry it as their triage guide.

### H1: USB storage device connected (low; first seen in 30 days: medium)
- **Means:** Windows recognised a USB mass-storage device: a classic stick (`USBSTOR`) or a USB 3 disk using UAS
  (`Enum\SCSI`, which SigmaHQ's 6416 rule misses). The first-seen variant fires only for a device ID not seen in the
  last 30 days: the usual first line of an exfiltration story.
- **Innocent causes:** approved company sticks (allow-list their serials, the same list `usbhawk sessions --allowlist`
  uses); new hardware rollouts.
- **Next:** note the device ID and serial (your pivot); look for H3/H4 on the same host and user while it was
  connected; run `usbhawk devices` on a triage to see its history on this host.

### H2: USB storage connected outside work hours (medium)
- **Means:** the connection happened outside the configured work hours or on a non-workday, judged on the local clock
  from the scoring config (build with `--config` for your organisation's hours and time zone).
- **Innocent causes:** shift and on-call staff; hosts in another time zone than the configured one.
- **Next:** confirm the user's real working pattern, then look at H3/H4 in the following hour.

### H3: bulk file copy to removable media (high)
- **Means:** at least 50 files (`thresholds.bulk_files`) were written to removable media by one user on one host in
  10 minutes. Recycle Bin `$I` metadata and System Volume Information, which Windows writes itself, are not counted;
  files hidden inside the Recycle Bin folder are.
- **Innocent causes:** backups and media copies to approved drives; in Sigma/Elastic, writes to fixed secondary drives
  (they treat D: to Z: as removable; Sentinel knows which drive is USB).
- **Next:** identify the device (the H1 at the same time) and read the sample files; check for archives (H4) and for
  cleanup afterwards (H5 to H8); run `usbhawk sessions` on a triage for the whole scored session.

### H4: archive written to removable media (medium)
- **Means:** a zip, 7z, rar, iso, pst, kdbx or other container landed on removable media. One archive can hold
  thousands of documents that H3 would never count.
- **Innocent causes:** installers and ISO images on approved drives.
- **Next:** note the archive's name and size and whether the same archive was created on C: shortly before; correlate
  with H1 (which device) and H5 to H8 (cleanup).

### H5: disk formatted or repartitioned from the command line (medium)
- **Means:** `format.com`, `diskpart` or the PowerShell storage cmdlets ran. Formatting a stick after copying hides
  what it carried. Formatting from Explorer's dialog starts no process, so only the offline hunt
  (`sessions`, rule `reformat_or_repartition`) sees that case, from the changed volume serial number.
- **Innocent causes:** IT staff preparing or repairing disks; provisioning scripts.
- **Next:** find the targeted drive letter in the command line and whether it was USB (H1); check what was copied to
  it before (H3, H4).

### H6: USB history cleanup tool executed (USBOblivion: high; general cleaners: medium)
- **Means:** a program built to erase USB history, or a cleaner able to wipe USB and log traces, started. In the lab,
  USBOblivion deleted the USB registry keys and silently cleared Security and System within seconds: this process
  start may be the last event the host sends about the device.
- **Innocent causes:** IT resetting kiosks or lab machines; approved CCleaner / BleachBit maintenance (allow-list the
  path).
- **Next:** collect a triage **now** and run `usbhawk tamper` and `usbhawk sessions` on it; check H3/H4 in the hour
  before.

### H7: Windows event log cleared (1102: high; 104: medium; clearing commands: high)
- **Means:** a log was cleared, destroying the record of USB connections and file access. Windows writes 1102 and 104
  itself at the moment of clearing; the command-line detection catches `wevtutil`, PowerShell, .NET and WMI clearing.
- **Innocent causes:** log-agent rollouts, golden-image preparation, rare administrator troubleshooting.
- **Next:** anything older on this host now depends on forwarded copies; look for H6 and H8 in the hour before;
  collect a triage and run `usbhawk tamper` (a `partition_log_gap` shows what was lost).

### H8: USB device history deleted from the registry (high)
- **Means:** a process other than Windows' own Plug and Play services deleted the keys that record USB devices
  (`Enum\USBSTOR`, `Enum\USB`, `Enum\SCSI`, MountedDevices, MountPoints2, Portable Devices, EMDMgmt, DeviceClasses).
  This is what USBOblivion and manual cleanups do.
- **Innocent causes:** device-management or imaging tools that reset USB history by design (allow-list their path).
- **Next:** collect a triage before more is lost; `usbhawk tamper` shows which devices were wiped (orphaned references);
  look for H6 and H7 on the same host.

## Rule format

Sigma-style selections with **neutral field names**, plus options for what one event cannot show:

```yaml
detections:
  - name: clear_command
    title: Log Clearing Command
    level: high
    telemetry: process_creation              # process_creation | event_log | device_connect | file_event | registry_event
    related: [{id: cc36992a-4671-4f21-a91d-6c2b72a2edf5, title: SigmaHQ Suspicious Eventlog Clearing ...}]
    selections:
      wevtutil_img:     {process_name: wevtutil.exe}
      wevtutil_renamed: {original_file_name: wevtutil.exe}
      wevtutil_cmd:     {command_line|contains: ["clear-log ", " cl "]}
      ps_dotnet:        {command_line|contains|all: [Eventing.Reader.EventLogSession, ClearLog]}
    condition: ((wevtutil_img or wevtutil_renamed) and wevtutil_cmd) or ps_dotnet
tests:                                       # every detection needs events that must match AND must not
  - {detection: clear_command, match: true,  event: {process_name: wevtutil.exe, command_line: 'wevtutil cl Security'}}
  - {detection: clear_command, match: false, event: {process_name: wevtutil.exe, command_line: 'wevtutil qe Security'}}
```

| Option | Meaning | Sigma | Elastic (ES\|QL) | Sentinel (KQL) |
|---|---|---|---|---|
| modifiers `contains` `startswith` `endswith`, `\|all` | case-insensitive; a list is any-of (`\|all`: every value) | same modifiers | `TO_LOWER` + `LIKE` / `STARTS_WITH` | `contains` / `startswith` / `in~` |
| `channel: Security\|System` | event_log source | `service:` | `winlog.channel` | `SecurityEvent` / `Event` table |
| `removable_media: true` | file written to USB media | `TargetFilename\|re` D:–Z: *(heuristic)* | drive D:–Z: *(heuristic)* | **join on MDE `UsbDriveMounted`** (exact) |
| `registry_action: delete` | registry key/value deleted | `registry_delete` category | `event.type == "deletion"` | `RegistryKeyDeleted` / `RegistryValueDeleted` |
| `threshold: {count, window_minutes, by}` | N events per group in a fixed bucket | **correlation rule** (`event_count`) | `STATS … BUCKET()` | `summarize … bin()` |
| `first_seen: {by, lookback_days, window_minutes}` | value new within the lookback | *not expressible* → `.unsupported.txt` | earliest sighting in 30 d is in the last 10 min | same, with `ago()` |
| `outside_work_hours: ${work_hours}` | local-clock work hours | *not expressible* → `.unsupported.txt` | fixed standard UTC offset (DST: off by 1 h) | `datetime_utc_to_local()` (real zones) |
| `related` | overlapping SigmaHQ rule | `related: type: similar` | n/a | n/a |

Neutral fields → platform fields:

| Neutral | Sigma | ECS | Microsoft Defender XDR |
|---|---|---|---|
| process_name / image / command_line | `Image\|endswith` / `Image` / `CommandLine` | `process.name` / `.executable` / `.command_line` | `FileName` / `FolderPath` / `ProcessCommandLine` |
| original_file_name | `OriginalFileName` | `process.pe.original_file_name` | `ProcessVersionInfoOriginalFileName` |
| device_id / device_class / device_description | `DeviceId` / `ClassName` / `DeviceDescription` (6416) | `winlog.event_data.*` | `AdditionalFields.DeviceId` / `.ClassName` / `.DeviceDescription` |
| file_path / file_name | `TargetFilename` | `file.path` / `file.name` | `FolderPath` / `FileName` |
| registry_path | `TargetObject` | `registry.path` | `RegistryKey` |
| event_id / provider | `EventID` / `Provider_Name` | `event.code` / `winlog.provider_name` | `EventID` / `EventSourceName`, `Source` |

## Telemetry you need

| Hypotheses | Enable |
|---|---|
| H1, H2 | **Audit PNP Activity**: `auditpol /set /subcategory:"Plug and Play Events" /success:enable` (Security 6416), or MDE |
| H3, H4 | Sysmon FileCreate (11) or Elastic Defend / MDE file events |
| H5, H6, H7 command | Sysmon ProcessCreate (1), Security 4688 with command line, Elastic Defend, or MDE |
| H7 | Security 1102 and System 104: on by default; **forward them**, the point of clearing is that local copies vanish |
| H8 | Sysmon RegistryEvent (12) under the USB keys (see `scripts/lab/sysmon-usbhawk-lab.xml`), or MDE registry events |

Most production Sysmon configs filter registry events: add the eight `TargetObject` rules from the lab config.

## Deploying

* **Sigma:** `build/sigma/*.yml` follow SigmaHQ conventions (file prefixes, Title Case, UUID v4, `related` links to
  overlapping SigmaHQ rules). Convert with `sigma-cli` for any backend; the H3 correlation needs a backend that supports
  Sigma correlations. `*.unsupported.txt` explains the two detections Sigma cannot express.
* **Elastic:** Kibana → Security → Rules → **Import** `build/elastic/usbhawk_rules.ndjson`. Rules arrive **disabled**
  with ATT&CK mapping, severity, risk score and an investigation guide; review, then enable. The index pattern is
  `logs-*, winlogbeat-*`; ES|QL fails on unknown fields, so confirm the Windows/Sysmon integrations populate the ECS
  fields above in your stack before enabling.
* **Sentinel / Defender XDR:** paste `build/sentinel/*.kql` into analytics rules or hunting queries. The removable-media
  rules join on `UsbDriveMounted`, so they need MDE device events.

IDs are deterministic: rebuilding updates rules in place instead of creating duplicates.

## Validation

| Check | Result |
|---|---|
| Each rule's own test events (`usbhawk detections test`) | 59 events, all pass; every detection has must-match **and** must-not-match cases |
| 124 tests in `tests/hunt_detection_rules/` | schema, evaluator, generators per platform, replay, telemetry coverage, the documented sample timeline |
| pySigma 2.1.0: parse + 31 built-in validators | 11 Sigma documents, correlation resolved, **0 issues** |
| SigmaHQ repository validators (`pysigma-validators-sigmahq`, 52) | **0 issues** |
| Deliberate breaks (mutation checks) | 21 of 21 caught (see `docs/TESTING.md`) |

## Lab validation (2026-11-17)

Windows 10 VM with the lab Sysmon config and PnP auditing; a 1 TB **UASP** USB disk attached. Activity: copy 60
files and a zip to the disk, `format.com /?`, `wevtutil cl Application`, collect; then **USBOblivion 1.17.0**
(real clean), collect again. Replayed with `usbhawk detections run --evtx … --removable-drives F:` and cross-checked
against EvtxECmd.

| Hypothesis | Before cleanup | After USBOblivion | EvtxECmd |
|---|---|---|---|
| H1 USB storage | ✅ the UASP disk (low) + first seen (medium) | gone: Security log cleared | ✅ |
| H3 bulk copy | ✅ 62 files in 14 s (high) | ✅ still in Sysmon | 62 ✅ |
| H4 archive | ✅ | ✅ | ✅ |
| H5 format | ✅ | ✅ | ✅ |
| H6 cleanup tool | none | ✅ USBOblivion64.exe (high) | 1 ✅ |
| H7 log cleared | ✅ the `wevtutil cl` | ✅ 11 clearing commands + 1102 + 104 | 11 ✅ |
| H8 registry wipe | none | ✅ 661 deletions (high) | 661 ✅ |

What the lab showed:

* **How USBOblivion clears logs:** it starts `wevtutil.exe cl` **ten times** (Partition/Diagnostic, Kernel-PnP,
  DriverFrameworks-UserMode, DeviceSetupManager, Kernel-ShimEngine, HardwareEvents, Application, Security, System),
  while its window mentions only DeviceSetupManager. It does **not** clear Sysmon, so H3–H6 survived. H7 caught all ten.
* **UASP gap confirmed again:** 661 deletions across DeviceClasses, Enum\USB, Enum\USBSTOR, MountPoints2, WPD,
  MountedDevices and EMDMgmt, and **none under Enum\SCSI**.
* **H1 covers UASP disks**, which SigmaHQ's 6416 rule (`DiskDrive` / `USB Mass Storage Device`) does not.
* **False positive found and fixed:** on every mount Explorer deletes and re-creates
  `MountPoints2\{volume}\shell\Autoplay\DropTarget` within milliseconds. H8 now excludes exactly that pattern; a
  regression test reproduces it.
* **The D:–Z: removable heuristic** produced no extra alerts on a VM with evidence drives on E: and G:.
* **Why forward logs live:** H1's evidence was destroyed when Security was cleared; a SIEM would already hold it.

## Real PC validation (2026-11-18)

The owner's own Windows 11 PC, replayed live from an elevated prompt (`--evtx C:\Windows\System32\winevt\Logs`)
and from a `collect_local.ps1` collection, both with the same result:

| Stage | Events | Alerts |
|---|---|---|
| Default Windows (no Sysmon, no PnP or process auditing) | 75,334, all plain log records | none, correctly; the new **Telemetry gaps** note names H1-H6 and H8 as unable to fire |
| With the lab Sysmon config and PnP auditing; a UASP disk connected, a folder of 1,000+ files and some archives copied to it | 106,340: device_connect 4, file_event 30,335, process_creation 433, registry_event 310 | H1 x2 (the disk, first seen), H3 x1 (high), H4 x4: exactly what was done |

**False positive found and fixed:** H3's first examples were the Recycle Bin `$I` metadata files Windows creates on
the disk when files on it are deleted (an archive's `$I` file keeps the `.zip` extension, so H4 was exposed too). H3
and H4 now skip `$RECYCLE.BIN\...\$I*` and System Volume Information; files copied *into* the Recycle Bin folder, a
place to hide data, still count. Must-not-match and must-match test events reproduce both.

## Reading an alert

A replay prints a **Look at first** block under the table: the alerts by level, high first, each with its first time.
Start there, then read the table as one story: the device (H1, H2), the copying (H3, H4), the cleanup (H5 to H8).

1. **H6 or H8 (high):** the wipe is happening now; collect a triage immediately and run `usbhawk tamper`.
2. **H7 command or 1102:** check the parent process; a cleanup tool as parent (USBOblivion → `wevtutil cl`) is decisive.
3. **H3 / H4:** identify the device (H1 at the same time), then run `usbhawk sessions` for the whole scored session.
4. **H1 first seen / H2 off hours:** context; rarely worth a page on their own, valuable next to H3/H4.

## Limits

* Sigma has no first-seen or time-of-day logic; those two detections exist for Elastic and Sentinel only.
* ES|QL has no time zones: work hours use the zone's standard offset (1 h off during daylight saving time).
* Sysmon / ECS file events do not say "removable": Sigma and Elastic use the D:–Z: heuristic; Sentinel is exact.
* Explorer-dialog formatting starts no process, so H5 misses it; the offline hunt still sees the new VSN.
* Elastic ES|QL rules were validated for structure, not yet run in a live Elastic stack; Sentinel KQL likewise.
* `detections run` replays first-seen against the logs' own span only (each alert states the history it had).
