# Hunt: USB tamper and cleanup detection (`usbhawk tamper`, module #3)

> **The question:** *Did someone wipe the evidence of USB use, or did Windows clean it up on its own?*

An insider who copies data to a USB stick and then runs a cleanup tool leaves a host that *looks* clean in a
device inventory. But Windows records a USB device in many places, and cleanup tools never get all of them.
`usbhawk tamper` looks for the **inconsistencies a wipe leaves behind**, separates them from what a Windows feature
update does on its own, and finds **traces of the cleanup itself**: the tool's execution, cleared logs, a reset
Partition log, a deleted `setupapi.dev.log`.

Every finding carries a severity and a one-sentence `why` that names the evidence. A finding without a reason is a bug.

## Quick start

```powershell
usbhawk tamper --triage D:\cases\WS042\kape --out .\out\WS042     # console table + out\WS042\tamper.jsonl
usbhawk tamper --system SYSTEM --software SOFTWARE --ntuser NTUSER.DAT=j.doe --partition-log Partition.evtx
```

Try it first on the demo: `usbhawk tamper --triage examples\tamper\wiped-host`, a fictional PC wiped with
USBOblivion that raises every finding below ([examples/tamper](../examples/tamper/README.md)).

Collect on a lab machine with `scripts\collect_local.ps1` (elevated). For real cases use KAPE (`RegistryHives`,
`EventLogs`, `USBDevicesLogs`) or Velociraptor. Feed it **everything from one host**: the SYSTEM hive is required for
orphan checks, and logs from another machine are detected and excluded.

## How it works

```
 Triage ──► PARSE (same parsers as module #2) ──► Evidence ──► tamper.find_tamper() ──► findings (JSONL / table)
            + MountedDevices signature volumes                  1. host consistency
            + BAM executions, ProfileList                       2. log clearing          (Security 1102, System 104)
            + Partition log record IDs                          3. Partition log gap     (rule 3)
            + missing expected files                            4. cleanup tools         (rule 5, BAM)
                                                                5. orphans: wiped vs feature update
```

### Where USB evidence lives, and what wipes it

| Easy to wipe (what cleanup tools target) | Usually survives |
|---|---|
| `SYSTEM\...\Enum\USB`, `Enum\USBSTOR`, `Enum\SCSI` (UASP) | `Partition/Diagnostic` 1006 events (unless the log is cleared) |
| `DeviceClasses`, `MountedDevices` device-path values | `MountPoints2` in each user's NTUSER.DAT |
| `setupapi.dev.log`, Security/System logs | Windows Portable Devices, EMDMgmt, `DeviceMigration` |
| | **BAM**: the record that the cleanup tool itself ran |

A device that still shows up in a surviving artifact but is gone from `Enum` is an **orphan**. Two things remove
devices from Enum: **Windows** (feature updates purge it and archive devices under `DeviceMigration`) and
**people** (USBOblivion, DriveCleanup, manual key deletion). The rules below tell them apart.

## Findings

| Rule | Severity | Fires when |
|---|---|---|
| `orphaned_device_reference` | medium (see ladder below) | A device or volume survives in another artifact but is missing from Enum, with no feature update or DeviceMigration entry to explain it |
| `explained_by_feature_update` | info | Same orphan, but it is in `DeviceMigration`, or a feature update/reinstall came **after** its last reference |
| `log_cleared` | high for Security, System, Partition/Diagnostic, Kernel-PnP, DriverFrameworks; medium for others | Security 1102 or System 104 (provider `Microsoft-Windows-Eventlog` only; ID 104 is reused by other providers) |
| `partition_log_gap` | medium | Record IDs jump inside the Partition/Diagnostic log, **or** the log is empty / starts at record 1 while the registry shows USB disks arriving after the current Windows build was installed |
| `cleanup_tool_execution` | high for USBOblivion; medium for DriveCleanup, USBDeview, PrivaZer, CCleaner, BleachBit, SDelete | BAM recorded the tool running; log clears within 24 h after it are named |
| `expected_artifact_missing` | low | `Windows\INF` was collected but `setupapi.dev.log` is absent (Windows always keeps it; USBOblivion deletes it) |
| `evidence_host_mismatch` | info | An event log was written by a different computer than the registry hives; its devices are excluded from orphan checks |
| `orphan_checks_skipped` | info | No SYSTEM hive, so "missing from Enum" cannot be judged; never guessed |

### Orphan severity ladder

| Situation | Severity |
|---|---|
| Last reference has its own timestamp (entry last-write, 1006 event) | **medium** |
| Only an upper bound (MountedDevices values share the key's last-write time) | low |
| No timestamp, feature updates on record (cannot be compared) | low |
| No timestamp, no feature update on record | medium |
| The reference is only a volume GUID (`MountPoints2`), not a device serial | low |
| A critical log was cleared within **24 h after** the last reference | **high** |
| A known cleanup tool ran **after** the last reference | one level up (low → medium → high) |

Direction matters: cleanup follows use. A log clear or a tool run *before* the last reference does not correlate.

### Rule 3 in detail: why record IDs

Windows numbers event records sequentially. When a log fills up it **rolls over**: the oldest records are
dropped, but the remaining IDs stay contiguous and start well above 1. When a log is **cleared**, numbering
restarts at 1. So:

* IDs jump inside the log → individual records were deleted (Windows never does this).
* The log starts at record 1 (or is empty), but the registry (`Enum` property `0066`) shows a USB disk arriving
  after the current Windows build was installed and *before* the oldest record → that arrival's 1006 events
  existed and are gone → the log was cleared or reset.

File size does **not** work for this: the lab's Partition log was 1.1 MB with only 85 records.

### Linking UASP / MBR disks

A USB 3 disk using UASP lives under `Enum\SCSI`, and when it has an MBR partition table `MountedDevices` stores only
its **disk signature + partition offset** (12 bytes), not a device path. Windows names such volumes
`{SSSSSSSS-0000-0000-OOOO-OOOOOOOOOOOO}` (signature, then the offset's little-endian bytes). `usbhawk` reads the
signature from the MBR inside each 1006 event and links the volume GUID, drive letter and `MountPoints2` users back
to the disk. Dynamic disks store `DMIO:ID:` + the volume GUID and are decoded too. MBR-style GUIDs are never listed
as `\??\Volume{...}` names, so their absence from MountedDevices is **not** evidence of tampering.

## Output

`tamper.jsonl`, one ECS-style document per finding (fictional example):

```json
{"@timestamp": "2026-10-30T21:14:00Z",
 "event": {"kind": "alert", "category": ["host"], "type": ["info"], "dataset": "usbhawk.tamper",
           "severity_label": "high", "risk_score": 75},
 "host": {"name": "NW-FIN-WS042"},
 "usbhawk": {"rule": "orphaned_device_reference", "severity": "high",
            "why": "VID_0951&PID_1666\\60A44C413D5FF380E95A0B7D still appears in evtx:Partition/Diagnostic but is missing from Enum\\USB/USBSTOR/SCSI; last referenced 2026-10-30T21:14:00Z; no feature update after it (latest on record: 2026-03-01T09:00:00Z). The device keys were likely deleted (e.g. USBOblivion or manual cleanup). USBOblivion was run by j.doe at 2026-10-30T21:54:00Z, after this last reference: the traces were likely wiped with it.",
            "evidence": {"last_reference": "2026-10-30T21:14:00Z", "surviving_sources": ["evtx:Partition/Diagnostic"],
                         "correlated_log_clear": null,
                         "correlated_cleanup_tool": {"name": "USBOblivion64.exe", "ts": "2026-10-30T21:54:00Z"}}}}
```

`event.kind` is `alert` for high/medium and `event` for low/info; `risk_score` is 75/50/25/0. All times are UTC.

## Lab validation (2026-11-16)

Tested on a Windows 10 22H2 VM (with a snapshot) using a 1 TB UASP USB disk, then **USBOblivion 1.17.0** in real
clean mode, run twice. Each stage was collected with `collect_local.ps1` and cross-checked against Eric Zimmerman's
**RECmd** (DFIRBatch) and **EvtxECmd**.

| Stage | What `usbhawk tamper` reports | Matches EZ tools |
|---|---|---|
| Baseline (disk used, ejected) | 5 × `log_cleared` from the VM's build (2025); `partition_log_gap`: the log restarted at record 1 the next day, losing 4 sticks' 1006 records. No orphans | ✅ 1102 ×1, 104 ×4; 85 × 1006 (20 USB, 64 VM disks, 1 mounted image) |
| After USBOblivion | `cleanup_tool_execution` high (BAM); `log_cleared` Security + System; **6 orphans = exactly the 6 sticks it wiped**, each raised to medium by the tool run; `partition_log_gap` (empty log, the UASP disk arrived that day); `expected_artifact_missing` setupapi.dev.log | ✅ BAM time identical to the microsecond; RECmd shows the 6 sticks' Enum keys only as **deleted** records |
| USBOblivion again (disk fully detached) | Same picture, with the second run's time | ✅ |

**What the lab taught us about USBOblivion 1.17.0** (one version, one disk):

* It **does not clean UASP disks**. Even fully detached, the disk stayed in `Enum\USB` and `Enum\SCSI`
  (`Found keys: 0`). It only targets `USBSTOR`-style devices.
* It **silently clears the Security and System logs** (1102 and 104 about 4 s after starting) and empties the
  Partition/Diagnostic log; its own window only mentions `DeviceSetupManager/Operational`.
* It deletes `setupapi.dev.log`, `MountedDevices` values, `DeviceClasses` and `Enum` keys, but **not BAM**, which
  records its own execution, and not the `MountPoints2` GUIDs of the sticks it wiped.

**Bugs the lab found in usbhawk (fixed, each with a regression test in `tests/hunt_usb_tamper/test_tamper_usboblivion_lab.py`):**

| Bug | Cause | Fix |
|---|---|---|
| Real sticks reported as orphans | regipy trims registry values to 128 bytes by default; USBSTOR paths in MountedDevices lost the end of the serial | Read values untrimmed |
| The VM's own C:, a mounted evidence image, the Cases drive and the UASP disk reported as orphans | MBR-signature and `DMIO:ID:` volumes are never stored as `\??\Volume` names | Decode them; type MBR GUIDs `mbr_volume`, never tamper evidence |
| A volume recreated after the cleanup was tied to the log clear | Correlation used ±24 h | Only a clear **after** the last reference counts |

Before the fixes the three lab folders produced 28 false findings (5 of them high); after, **zero false positives**,
and every wiped stick, cleared log and cleanup run is reported.

## Reading the results

1. Start with **high**: `cleanup_tool_execution`, `log_cleared` on Security/System/Partition, orphans raised by them.
   A cleanup tool run followed within seconds by log clears is a strong anti-forensics signal on its own.
2. For each **orphan**, the `why` names the surviving artifact. Pivot on it: a volume GUID from `MountPoints2` names
   the user who mounted it; a 1006 event gives capacity, VSN and partition layout; module #2 (`usbhawk sessions`)
   scores what was done while it was connected.
3. `explained_by_feature_update` (info) is the benign twin: check `DeviceMigration` or the update dates before
   escalating anything near a feature update.
4. `evidence_host_mismatch` means the triage folder mixes machines: fix the collection before trusting anything.

## Limits

* BAM exists on Windows 10 1709+ and keeps roughly a week of entries per user; Prefetch/Amcache are not parsed yet.
* A thorough wipe of a `USBSTOR` stick that also clears the Partition log leaves only `MountPoints2` volume GUIDs;
  those can name the user but not the device. The cleanup itself (BAM, cleared logs, gaps) is still reported.
* `partition_log_gap` needs the SOFTWARE hive (install/feature-update dates) and the device's `Enum` arrival time.
* `expected_artifact_missing` cannot tell a deleted `setupapi.dev.log` from one the collector skipped; hence low.
* Not yet built: `enum_without_properties` (rule 6: Enum instances with zeroed timestamps), Prefetch/Amcache
  execution evidence, DriverFrameworks/Kernel-PnP parsers. See `docs/ROADMAP.md`.
