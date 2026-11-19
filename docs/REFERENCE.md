# USBHawk reference

How the pipeline works, the scoring rules, time zones, every artifact parsed and the known limits.
Getting started: [GETTING-STARTED.md](GETTING-STARTED.md). One guide per hunt: `hunt-*.md`.

## How it works

```
 Triage folder ──► 1. COLLECT ──► 2. PARSE ──► 3. SESSIONS ──► 4. SCORE ──► 5. OUTPUT
 (KAPE / Velo /     find the       Device +      connect→remove   13 rules,     JSONL (SIEM)
  mounted image)    artifacts      Event list    windows + users  each with a   CSV (Excel)
                                                 + file activity  reason        terminal table
```

1. **Collect:** find the registry hives, event logs, `setupapi.dev.log` and EDR CSVs; one bad file never stops a run.
2. **Parse:** build a profile per device (vendor, serial, letter, volume name, VSN, user) and a UTC timeline of events.
3. **Sessions:** pair each connect with its removal; merge duplicate records from different artifacts; handle
   missing removals; detect reformats from volume-serial changes; attach logged-on users and file activity.
4. **Score:** apply 13 explainable rules (below).
5. **Output:** `sessions.jsonl` (ECS fields, Splunk/Elastic-ready), `sessions.csv`, `devices.jsonl`.

The full walkthrough, with a worked example, output field reference and triage tips, is in
**[docs/hunt-exfil-sessions.md](hunt-exfil-sessions.md)**.

## Scoring rules (defaults; tune in `config/scoring.toml`)

| Rule | Points | Fires when |
|---|---|---|
| `first_seen_device` | 25 | Session contains the device's first-ever install on the host |
| `off_hours` | 15 | Connected outside work hours / on a non-workday, judged on the employee's local clock |
| `file_writes` | 20 | Any file written to the device during the session |
| `bulk_transfer` | 20 | ≥ 50 files or ≥ 500 MB written |
| `archive_written` | 15 | .zip/.7z/.rar/.iso/.pst/.kdbx... written to the device |
| `reformat_or_repartition` | 25 | VSN or partition layout changed within or between sessions |
| `mass_delete_on_device` | 10 | ≥ 50 deletes on the device |
| `mtp_device` | 10 | Phone/tablet (no drive letter, DLP blind spot) |
| `high_capacity` | 5 | ≥ 256 GB |
| `long_session` | 5 | ≥ 30 minutes |
| `no_hardware_serial` | 5 | Windows-generated serial (hard to track fleet-wide) |
| `watchlist_user` | 30 | User on `--watchlist` active during the session |
| `allowlisted_device` | -50 | Serial on `--allowlist` |

Severity: high ≥ 70, medium ≥ 40, low ≥ 15, otherwise info. Score is clamped to 0–100.

### Time zones

All timestamps are stored and output in **UTC**, the common clock for hunting and IR. Only the `off_hours`
judgement uses a local clock, chosen in this order: `--tz` > `[work_hours] timezone` in the config file > the
host's own registry time zone (`TimeZoneKeyName`, mapped to IANA) > UTC with a warning. The reason text shows both
clocks and the source, e.g.
`connected 2020-11-29 08:51Z = Sun 2020-11-29 03:51 America/New_York, outside work hours (tz from host registry: Eastern Standard Time)`.
The registry holds the host's *current* zone; for laptops that travel, pass `--tz` if needed.

## Artifacts parsed

| Artifact | What it contributes |
|---|---|
| SYSTEM `Enum\USB` | VID/PID, iSerialNumber, class (Service), 0064/0066/0067 times |
| SYSTEM `Enum\USBSTOR`, `Enum\SCSI` (UASP) | Device ID, FriendlyName, DiskId, times; linked via property `000A` (parent instance) |
| SYSTEM `MountedDevices` | Drive letter, Volume GUID (device paths, MBR signature + offset, `DMIO:ID:`) |
| SYSTEM `DeviceMigration` | Devices archived by feature-update cleanup (`LastPresentDate`) |
| SYSTEM `Setup\Source OS`, SOFTWARE `InstallTime` | Feature-update history (explains Windows' own Enum purges) |
| SYSTEM `bam\State\UserSettings`, SOFTWARE `ProfileList` | Program executions per user (cleanup tools) |
| SYSTEM `TimeZoneInformation` | Host time zone (work hours, setupapi conversion with DST); bias as fallback |
| SOFTWARE `Windows Portable Devices` | Volume name (USBSTOR, UASP via DiskId, MTP) |
| SOFTWARE `VolumeInfoCache` | Label → drive letter |
| SOFTWARE `EMDMgmt` | VSN (decimal → hex), volume name |
| NTUSER `MountPoints2` | User attribution via Volume GUID |
| `Partition/Diagnostic` 1006 | Every connect/disconnect, capacity, MBR (disk signature, layout), VBR → VSN; record IDs (gap detection) |
| Security 6416 / 4663 / 4656 / 4624 / 4634 / 4647 / 4800 / 4801 | Plug-ins, removable file access, user sessions |
| System 20001 / 20003, `setupapi.dev.log` | First install (setupapi local time → UTC) |
| Security 1102, System 104 | Event log cleared (provider-checked) |
| File-event CSV | EDR file writes (drive letter or VSN matched) |

## Known limitations

- 4663 events carry no device serial; removable volumes are inferred (a volume active ≥ 80 % inside USB sessions).
- `setupapi.dev.log` is in local time: it is converted with the host's time zone (`TimeZoneKeyName`) and its
  daylight-saving rules. Only when the zone is unknown does it fall back to the current `ActiveTimeBias`, which can be
  off by 1 h across DST; `details.tz_used` on each first-install event says which was used.
- Hives are read as-is; replay dirty hive transaction logs first with `rla.exe` (KAPE copies the logs but does not apply them) or use
  `reg save` copies. Several copies of a hive in one folder (RegBack, Windows.old) are fine: the live one in
  `Windows\System32\config` is used and the others are listed as skipped.
- LNK/JumpList/ShellBag parsing is via CSV import (LECmd/JLECmd) for now.
- The registry time zone is the host's *current* one; pass `--tz` for laptops that travel.
- Tamper detection reads BAM for program execution (Windows 10 1709+, about a week of history); Prefetch/Amcache
  are not parsed yet. See [docs/hunt-usb-tamper.md](hunt-usb-tamper.md#limits).
- Detection rules: Sigma cannot express first-seen or time-of-day (those two exist for Elastic / Sentinel only); ES|QL
  work hours ignore daylight saving time; Elastic and Sentinel queries are structure-tested but not yet run in a live
  stack. See [docs/hunt-detection-rules.md](hunt-detection-rules.md#limits).
- Fleet graph: only as complete as the hosts collected; a stick reformatted with a new name cannot be linked when it
  has no real serial; users are accounts, not people. See [docs/hunt-fleet-device-graph.md](hunt-fleet-device-graph.md#limits).
- Windows 7 (found on the NIST CFReDS Data Leakage case): Windows 7 keeps no last-arrival / last-removal properties
  and no Partition/Diagnostic log, so USBHawk shows each stick's first connection only, and MBR volumes (drive letter,
  MountPoints2 user) and EMDMgmt entries without a device path stay unlinked. Each gap has a plan in
  [ideas/](../ideas/README.md).
