# `usbhawk tamper`: did someone wipe the USB evidence, or did Windows clean it up?

Module #3. Insiders who copy data to a stick often run a cleaner afterwards (USBOblivion, CCleaner, `wevtutil cl`).
Windows also removes USB traces on its own, during feature updates. `usbhawk tamper` finds what is missing, then
tells the two apart: a device that survives in one artifact but is gone from `Enum` is an **orphan**, and its
severity depends on what happened after it (a feature update, a cleared log, a cleanup tool run).

| | |
|---|---|
| **Input** | The same triage folder as `usbhawk sessions` |
| **Output** | A findings table; with `--out`: `tamper.jsonl` (ECS) |
| **In this folder** | `wiped-host/`: a fictional PC wiped with USBOblivion, as real Windows files (registry hives and an event log) |
| **Full guide** | [docs/hunt-usb-tamper.md](../../docs/hunt-usb-tamper.md) |

Every one of the eight findings has a demo below:

| Finding | Demo |
|---|---|
| `cleanup_tool_execution`, `orphaned_device_reference`, `partition_log_gap`, `expected_artifact_missing`, `explained_by_feature_update` | [1. A wiped host](#1-a-wiped-host-fictional-included) |
| `orphan_checks_skipped` | [2. Missing SYSTEM hive](#2-without-the-system-hive) |
| `evidence_host_mismatch` | [3. A mixed triage folder](#3-a-triage-folder-from-two-machines-public-samples) |
| `log_cleared` | [4. Real log clearing](#4-real-log-clearing-public-attack-samples) |

## 1. A wiped host (fictional, included)

`wiped-host/` is the triage folder of `NW-LEG-WS031`, a fictional legal-department PC. Everything in it is
invented, but it is written in the real Windows formats: the registry hives are genuine `regf` files that Eric
Zimmerman's RECmd also opens, and the Partition/Diagnostic log is a genuine (empty) `.evtx` file.

```
wiped-host/
  Windows/System32/config/SYSTEM      devices (Enum), BAM program runs, feature-update history, DeviceMigration
  Windows/System32/config/SOFTWARE    install time, user profiles, EMDMgmt, Windows Portable Devices
  Users/m.ortiz/NTUSER.DAT            the volumes m.ortiz mounted (MountPoints2)
  Windows/System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx   emptied
  Windows/INF/setupapi.app.log        the INF folder, without setupapi.dev.log
```

**The story** (Thursday 2026-10-29, UTC): user `m.ortiz` connects a Samsung T7 USB 3 disk at 17:58, mounts a SanDisk
stick labelled `CASE-FILES` at 18:05 and a Kingston stick labelled `BACKUP` at 18:21, then runs **USBOblivion** at
18:42. USBOblivion deletes the sticks' device keys, empties the Partition log and deletes `setupapi.dev.log`. As in
our lab test of the real tool, it leaves its own run in BAM, misses EMDMgmt, Portable Devices and MountPoints2, and
does not clean the USB 3 (UASP) disk. Two older sticks were removed by Windows itself during the feature update of
2026-03-02: the benign twins.

```powershell
usbhawk tamper --triage examples\tamper\wiped-host
usbhawk tamper --triage examples\tamper\wiped-host --out out\wiped-host
```

What you should see (the Description column shortened):

```
Host NW-LEG-WS031  feature updates/installs: 2024-02-12, 2026-03-02
| Severity | Rule                        | Source Timestamp (UTC) | Description
| high     | orphaned_device_reference   | 2026-10-29 18:05:31 | USB serial 4C530001230601108811 still appears in registry:EMDMgmt but is missing from
|          |                             |                     | Enum ...; no feature update after it. ... USBOblivion was run by m.ortiz at 18:42:10Z, after this
|          |                             |                     | last reference: the traces were likely wiped with it.
| high     | orphaned_device_reference   | 2026-10-29 18:21:07 | USB serial 60A44C413D5FF380E95A2F11 still appears in registry:WindowsPortableDevices ... USBOblivion
|          |                             |                     | was run by m.ortiz at 18:42:10Z, after this last reference
| high     | cleanup_tool_execution      | 2026-10-29 18:42:10 | USBOblivion (USBOblivion64.exe) was run by m.ortiz, last at 2026-10-29T18:42:10Z (registry:BAM:
|          |                             |                     | \Device\HarddiskVolume3\Users\m.ortiz\Downloads\USBOblivion64.exe)
| medium   | orphaned_device_reference   | 2026-10-29 18:21:30 | volume {7c1e5a2b-91d4-11f0-a6b2-806e6f6e6963} (user m.ortiz) still appears in registry:MountPoints2
|          |                             |                     | ... USBOblivion was run by m.ortiz at 18:42:10Z, after this last reference
| medium   | partition_log_gap           | -                   | Partition/Diagnostic log is empty, yet the registry shows 1 USB storage device(s) arriving after the
|          |                             |                     | current Windows build was installed (2026-03-02T09:14:55Z): VID_04E8&PID_4001\N7T00042CF19 at 17:58:12Z
| low      | expected_artifact_missing   | -                   | setupapi.dev.log is missing from the triage although its folder (Windows\INF) was collected
| info     | explained_by_feature_update | 2025-11-14 12:30:10 | USB serial 07B21A9C3E5D4F81 is missing from Enum, but a feature update at 2026-03-02T09:14:55Z came
|          |                             |                     | after its last reference. Consistent with Windows cleanup.
| info     | explained_by_feature_update | 2026-02-20 16:45:00 | VID_0781&PID_5567\4C531001450817118421 is missing from Enum but listed in DeviceMigration: Windows
|          |                             |                     | archived it during a feature update. Benign.
```

### How to read it

1. **Start with the tool.** `cleanup_tool_execution` (high): Windows' Background Activity Moderator (BAM) recorded
   `USBOblivion64.exe` running from `m.ortiz`'s Downloads folder at 18:42:10. Cleaners rarely wipe their own trace.
2. **Then what it erased.** Each `orphaned_device_reference` is a stick that still shows up somewhere
   (`EMDMgmt`, `WindowsPortableDevices`, `MountPoints2`) but whose device keys in `Enum` are gone. The severity
   ladder:
   - a dated reference (the entry's own last-write time) starts at **medium**;
   - a volume GUID alone starts at **low** (it could also be a mounted ISO or VHD);
   - a cleanup tool that ran **after** the reference raises it **one level**: medium → high, low → medium.
   The direction matters: cleanup follows use, so a tool run *before* the stick was used would not raise it.
3. **The log that went quiet.** `partition_log_gap` (medium): Windows writes event 1006 to the Partition log on every
   USB connect. The log is empty, yet the registry shows the Samsung T7 arriving at 17:58, after the current Windows
   build was installed. Its records existed and are gone: the log was cleared or reset.
4. **The file that should be there.** `expected_artifact_missing` (low): `Windows\INF` was collected but
   `setupapi.dev.log` is not in it. Windows always keeps that log; USBOblivion deletes it. Low, because a collection
   that simply skipped the file looks the same.
5. **What is not tampering.** The two `explained_by_feature_update` (info) findings are sticks Windows removed
   itself: the Verbatim stick was last seen in November 2025, before the feature update of 2026-03-02, and the
   SanDisk Cruzer Blade is listed in `DeviceMigration`, Windows' own archive of devices it cleaned up. Calling these
   "wiped" would be a false accusation.

Who and where next: the stick serials and volume names (`CASE-FILES`, `BACKUP`) are what you search for on other
hosts with [`usbhawk graph`](../graph/README.md). On this host, `usbhawk sessions` still finds the Samsung T7 that
USBOblivion missed: first connected on 2026-09-15 (`first_seen_device`), then 33 minutes on the 29th, shortly before
the wipe (`long_session`):

```powershell
usbhawk sessions --triage examples\tamper\wiped-host --tz America/New_York
```

## 2. Without the SYSTEM hive

Orphans can only be judged against the device list in the SYSTEM hive. Without it, USBHawk says so instead of
guessing:

```powershell
usbhawk tamper --software examples\tamper\wiped-host\Windows\System32\config\SOFTWARE
```

```
| info | orphan_checks_skipped | - | SYSTEM hive not parsed, so it is unknown whether 3 referenced device(s) are still
|      |                       |   | in Enum; orphan checks skipped. Add the SYSTEM hive to the triage.
```

## 3. A triage folder from two machines (public samples)

The public sample hives and logs (`tests\data`, fetched once with `python scripts\fetch_test_samples.py`) come from
different computers:

```powershell
usbhawk tamper --triage tests\data
```

```
Host WKS-WIN732BITA  feature updates/installs: 2010-11-10
| info | evidence_host_mismatch | - | Partition/Diagnostic log was written by DESKTOP-GOGB42D (35 records),
|      |                        |   | WIN-9F6UT4I01JI (5 records), but the registry hives are from WKS-WIN732BITA:
|      |                        |   | this log comes from another machine. Devices seen only in it are excluded
|      |                        |   | from tamper checks; check how the triage folder was assembled.
```

A naive "in the log but not in the registry = wiped" check would report the log's three sticks (Patriot, two
Kingstons) as wiped. USBHawk reads from the log's own records that another machine wrote it, reports that as `info`,
and keeps those devices out of the orphan checks. On a real case the same check catches a triage folder that mixes
machines before you trust anything built on it.

## 4. Real log clearing (public attack samples)

EVTX-ATTACK-SAMPLES (GPL-3.0, by Samir Bousseaden) has real Security 1102 and System 104 records of an attacker
clearing logs. Fetch them (1.2 MB) and point `tamper` at them:

```
python scripts\fetch_demo_datasets.py evtx-attack
usbhawk tamper --security-log %USERPROFILE%\usbhawk-datasets\evtx-attack-samples\DE_1102_security_log_cleared.evtx --system-log %USERPROFILE%\usbhawk-datasets\evtx-attack-samples\DE_104_system_log_cleared.evtx
```

(In PowerShell write `$env:USERPROFILE` instead of `%USERPROFILE%`.)

```
Host unknown-host  feature updates/installs: none on record
| high | log_cleared | 2019-03-19 23:34:25 | System event log cleared by EXAMPLE\user01 at 2019-03-19T23:34:25.894341Z
|      |             |                     | (evtx:System:104). Clearing logs destroys evidence of device use and activity.
| high | log_cleared | 2019-03-19 23:35:07 | Security event log cleared by EXAMPLE\user01 at 2019-03-19T23:35:07.524202Z
|      |             |                     | (evtx:Security:1102). Clearing logs destroys evidence of device use and activity.
```

On a real wiped host these come together: a cleanup tool run, log clears within 24 hours after it (named in the
tool's finding), and orphans raised to **high** when a critical log was cleared within 24 hours after the stick was
last seen. That is exactly what the lab showed for USBOblivion 1.17.0 on Windows 10, cross-checked with RECmd and
EvtxECmd (details in the guide).

## 5. On your own evidence

```
usbhawk tamper --triage D:\cases\WS042 --out out\WS042
```

Write it into the same `--out` folder as `usbhawk sessions`: [`usbhawk graph`](../graph/README.md) then reports a stick
wiped on one host but still recorded on another (`wiped_here_seen_there`).
