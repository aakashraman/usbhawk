# USBHawk

```
   __  _______ ____  __  __               __
  / / / / ___// __ )/ / / /___ __      __/ /__
 / / / /\__ \/ __  / /_/ / __ `/ | /| / / //_/
/ /_/ /___/ / /_/ / __  / /_/ /| |/ |/ / ,<
\____//____/_____/_/ /_/\__,_/ |__/|__/_/|_|
   USB forensics for threat hunting & incident response
```

Windows USB forensics built for **threat hunting and incident response**, not just device inventory.

Most USB tools answer *"what devices were plugged in?"*. USBHawk answers the questions an investigation actually asks:

| Command | Question it answers |
|---|---|
| `usbhawk sessions` | Which USB sessions look like data exfiltration, and why? |
| `usbhawk tamper` | Did someone wipe the USB evidence, or did Windows clean it up? |
| `usbhawk detections` | How do we catch it live next time? (Sigma, Elastic, Sentinel rules) |
| `usbhawk graph` | Where else has this stick been, and who else used it? (many hosts) |
| `usbhawk devices` | What devices were connected? (the FOR500 11-step profile) |

It turns the SANS FOR500 11-step device profiling process into connect → remove **sessions**, attaches users and file
activity, scores every session with explainable rules, and builds on that for tamper detection, live rules and a fleet
graph. *Formerly the "USB Threat Hunting Toolkit" (`usbthk`); `usbthk` still works as a command alias.*

```
Score      Start (UTC)          Dur   Class    Device            Letter  VSN                 Writes  Why
100 high   2026-10-30 21:14:52  26m   usbstor  Kingston DT 3.0   F:      8E2C41D7,11223344   61      first_seen_device; off_hours; file_writes;
                                                                                                     bulk_transfer; archive_written;
                                                                                                     reformat_or_repartition; watchlist_user
```
*(Synthetic insider scenario from `tests/hunt_exfil_sessions/test_exfil_session_building.py`.)*

Every point of every score comes with a reason, e.g.
`off_hours +15: connected 2026-10-30 21:14Z = Fri 2026-10-30 17:14 America/New_York, outside work hours (tz from --tz)`.

## Modules

| # | Module | Status | Question it answers | Docs |
|---|--------|--------|---------------------|------|
| 2 | `usbhawk sessions`: exfil session scoring | **done** | Which USB sessions look like exfil, and why? | [guide](docs/hunt-exfil-sessions.md) |
| 3 | `usbhawk tamper`: USB tamper and cleanup detection | **done** (lab-verified against USBOblivion) | Did someone wipe USB traces, or was it a Windows feature update? | [guide](docs/hunt-usb-tamper.md) |
| 4 | `usbhawk detections`: detection-as-code pack | **done** (lab-verified with Sysmon + USBOblivion) | Catch it live: the same hypotheses as Sigma, Elastic (ES\|QL) and Sentinel (KQL) rules | [guide](docs/hunt-detection-rules.md) |
| 1 | `usbhawk graph`: fleet device graph | **done** (lab-verified on two real hosts) | Where else has this stick been, and who else used it? | [guide](docs/hunt-fleet-device-graph.md) |

## Install

Requires Python 3.11+. Works natively on Windows, Linux and macOS (it analyses Windows evidence).

```powershell
# Windows (PowerShell)
git clone <your-repo-url> usbhawk
cd usbhawk
py -3 -m venv .venv                      # any Python 3.11+ (3.13 tested on Windows 11)
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python scripts\fetch_test_samples.py     # public MIT-licensed sample hives/logs for tests
pip install -e ".[sigma]"                # optional: pySigma + SigmaHQ validators for the Sigma tests
pytest -q                                # expect: 326 passed
usbhawk                                  # banner, the commands, examples
```

Every command explains itself: `usbhawk <command> --help` shows what it answers, its options, examples, the files it
writes and its guide. The banner appears in help and at the start of a run on an interactive terminal only (on stderr):
JSON and CSV output stays clean, and `-q` or `USBHAWK_NO_BANNER=1` turns it off.

```bash
# Linux / macOS / WSL
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts/fetch_test_samples.py && pytest -q
```

## Quick start

```powershell
# 1. Try it on the public sample data
usbhawk sessions --triage tests\data --out out

# 2. A real case: KAPE / Velociraptor triage folder or mounted image
usbhawk sessions --triage D:\cases\WS042\kape --out .\out\WS042

# 3. Add EDR file telemetry (MDE DeviceFileEvents, Sysmon 11, Falcon, LECmd CSV) + HR context
usbhawk sessions --triage D:\cases\WS042\kape --file-events mde_files.csv `
                --watchlist leavers.txt --allowlist approved_usb.txt --min-score 40 --out .\out

# 4. Device inventory only (11-step profile per device)
usbhawk devices --triage D:\cases\WS042\kape --out .\out

# 5. Was USB evidence wiped? (cleanup tools, cleared logs, orphaned device traces)
usbhawk tamper --triage D:\cases\WS042\kape --out .\out

# 6. Catch it live next time: build Sigma / Elastic / Sentinel rules, or replay event logs through them
usbhawk detections build --config config\scoring.toml --out build
usbhawk detections run --evtx D:\cases\WS042\kape\C\Windows\System32\winevt\Logs

# 7. Across the fleet: one output folder per host, then link them
usbhawk graph --runs .\out --out .\fleet               # where else has each stick been, who else used it
usbhawk graph --runs .\out device 60A44C41             # pivot on one stick (serial, VSN or name)
```

The work-hours time zone is detected from the host's registry; pass `--tz America/New_York` to override.

**Lab machine:** `scripts\collect_local.ps1` (elevated) collects everything needed with `reg save` and
`wevtutil epl`. Use a personal or lab machine (ideally a VM with a snapshot), not a corporate endpoint.

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
**[docs/hunt-exfil-sessions.md](docs/hunt-exfil-sessions.md)**.

## Tamper and cleanup detection (`usbhawk tamper`)

Windows records a USB device in places that are easy to wipe (`Enum\USB`, `USBSTOR`, `SCSI`) and places that
usually survive (Partition/Diagnostic log, MountPoints2, Portable Devices, EMDMgmt, DeviceMigration, BAM).
`usbhawk tamper` finds the inconsistencies a wipe leaves and separates them from Windows' own feature-update cleanup:

| Finding | Severity | Meaning |
|---|---|---|
| `cleanup_tool_execution` | high / medium | USBOblivion, DriveCleanup, USBDeview, CCleaner... ran (BAM) |
| `log_cleared` | high / medium | Security 1102 / System 104 |
| `orphaned_device_reference` | low → high | A device survives elsewhere but is gone from Enum, unexplained by a feature update; raised by a log clear or cleanup tool after it |
| `partition_log_gap` | medium | Partition log record IDs jump, or it restarted after USB disks arrived |
| `explained_by_feature_update` | info | The benign twin: DeviceMigration or a later feature update explains it |
| `expected_artifact_missing`, `evidence_host_mismatch`, `orphan_checks_skipped` | low / info | Collection problems, stated rather than guessed |

Lab-verified on a Windows 10 VM against **USBOblivion 1.17.0**: every wiped stick, cleared log and tool run was
reported with zero false positives (along the way the lab showed USBOblivion leaves UASP disks behind and silently
clears the Security and System logs). Full guide: **[docs/hunt-usb-tamper.md](docs/hunt-usb-tamper.md)**.

## Detection-as-code (`usbhawk detections`)

The same hypotheses, as live rules. Each is one YAML file (logic, ATT&CK, false positives, triage steps and its own
test events) generated for **Sigma** (SigmaHQ conventions, correlation rules), **Elastic** (ES|QL over ECS plus a
Kibana import file) and **Microsoft Sentinel / Defender XDR** (KQL). Thresholds and lists come from the same config the
offline hunts use.

| # | Rule | Fires on |
|---|---|---|
| H1 | USB Storage Device Connected | any USB storage (incl. UASP disks); a device not seen in 30 days |
| H2 | USB Storage Connected Outside Work Hours | local-clock work hours from the config |
| H3 | Bulk File Copy to Removable Media | ≥ 50 files in 10 minutes |
| H4 | Archive Written to Removable Media | zip / 7z / rar / iso / pst / kdbx … |
| H5 | Disk Formatted or Repartitioned | format.com, diskpart, Format-Volume … |
| H6 | USB History Cleanup Tool Executed | USBOblivion; general cleaners |
| H7 | Windows Event Log Cleared | 1102, 104, wevtutil / PowerShell / .NET / WMI clearing |
| H8 | USB Device History Deleted From the Registry | deletes under Enum, MountedDevices, MountPoints2 … |

Validated by pySigma and SigmaHQ's 52 repository validators (zero issues) and lab-verified on real Sysmon / Security
telemetry: every rule fired as expected, counts matched EvtxECmd, and the lab caught USBOblivion clearing ten event
logs through `wevtutil cl`. `usbhawk detections run --evtx` replays any collected logs through the rules. Full guide:
**[docs/hunt-detection-rules.md](docs/hunt-detection-rules.md)**.

## Fleet device graph (`usbhawk graph`)

Links the per-host outputs of the other modules into one graph of devices, hosts, users and volumes. A real hardware
serial identifies a stick everywhere (high confidence); Windows-generated and fake serials are matched only through
volume evidence (medium / low) and never on the serial alone.

| Finding | Severity | Meaning |
|---|---|---|
| `exfil_device_spread` | high | The stick behind a high-risk session (module #2) was also on other hosts |
| `wiped_here_seen_there` | high | A stick wiped on one host (module #3) is still recorded on another |
| `device_on_many_hosts` / `device_shared_by_users` | medium | One stick on many hosts / used by several accounts |
| `new_to_fleet` / `serial_collision` | low / info | New anywhere in the fleet / a serial that cannot be trusted |

Pivots (`device <serial|VSN|name>`, `user <name>`) show everywhere a stick has been or everything one user touched;
exports are JSON, GraphML (Gephi / yEd) and Neo4j Cypher. Lab-verified: the same USB disk on two real machines was
linked by its serial. Full guide: **[docs/hunt-fleet-device-graph.md](docs/hunt-fleet-device-graph.md)**.

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
| SYSTEM `TimeZoneInformation` | Host time zone (work hours) and bias (setupapi conversion) |
| SOFTWARE `Windows Portable Devices` | Volume name (USBSTOR, UASP via DiskId, MTP) |
| SOFTWARE `VolumeInfoCache` | Label → drive letter |
| SOFTWARE `EMDMgmt` | VSN (decimal → hex), volume name |
| NTUSER `MountPoints2` | User attribution via Volume GUID |
| `Partition/Diagnostic` 1006 | Every connect/disconnect, capacity, MBR (disk signature, layout), VBR → VSN; record IDs (gap detection) |
| Security 6416 / 4663 / 4656 / 4624 / 4634 / 4647 / 4800 / 4801 | Plug-ins, removable file access, user sessions |
| System 20001 / 20003, `setupapi.dev.log` | First install (setupapi local time → UTC) |
| Security 1102, System 104 | Event log cleared (provider-checked) |
| File-event CSV | EDR file writes (drive letter or VSN matched) |

## Testing

Every module is tested in three layers before it is committed: **automated tests** (`pytest -q`, 326 tests in
one folder per hunt: `tests/foundations`, `tests/hunt_exfil_sessions`, `tests/hunt_usb_tamper`,
`tests/hunt_detection_rules`, `tests/hunt_fleet_device_graph`), a **sample run** on
public artifacts, and a **lab test** on a throwaway VM, cross-checked with Eric Zimmerman's RECmd and EvtxECmd. Every rule threshold is tested on both
sides (e.g. 50 files fires, 49 doesn't), and the SIEM output fields are pinned by a contract test.

Test inventory, sample-data notes, rules for writing tests and the lab procedure:
**[docs/TESTING.md](docs/TESTING.md)**.

## Known limitations

- 4663 events carry no device serial; removable volumes are inferred (a volume active ≥ 80 % inside USB sessions).
- `setupapi.dev.log` conversion uses the host's current `ActiveTimeBias`, so it can be off by 1 h across DST.
- Hives are read as-is; replay dirty hive transaction logs first (KAPE does; or `rla.exe`) or use `reg save` copies.
- LNK/JumpList/ShellBag parsing is via CSV import (LECmd/JLECmd) for now.
- The registry time zone is the host's *current* one; pass `--tz` for laptops that travel.
- Tamper detection reads BAM for program execution (Windows 10 1709+, about a week of history); Prefetch/Amcache
  are not parsed yet. See [docs/hunt-usb-tamper.md](docs/hunt-usb-tamper.md#limits).
- Detection rules: Sigma cannot express first-seen or time-of-day (those two exist for Elastic / Sentinel only); ES|QL
  work hours ignore daylight saving time; Elastic and Sentinel queries are structure-tested but not yet run in a live
  stack. See [docs/hunt-detection-rules.md](docs/hunt-detection-rules.md#limits).
- Fleet graph: only as complete as the hosts collected; a stick reformatted with a new name cannot be linked when it
  has no real serial; users are accounts, not people. See [docs/hunt-fleet-device-graph.md](docs/hunt-fleet-device-graph.md#limits).

## Documentation

| Doc | Contents |
|---|---|
| [docs/hunt-exfil-sessions.md](docs/hunt-exfil-sessions.md) | Module #2 in depth: pipeline, session logic, rules, output fields, how to run and read results |
| [docs/hunt-usb-tamper.md](docs/hunt-usb-tamper.md) | Module #3 in depth: where USB evidence survives, every finding, severity logic, lab results against USBOblivion |
| [docs/hunt-detection-rules.md](docs/hunt-detection-rules.md) | Module #4 in depth: the 8 hypotheses, rule format, platform mappings and limits, deploying, Sysmon lab results |
| [docs/hunt-fleet-device-graph.md](docs/hunt-fleet-device-graph.md) | Module #1 in depth: identity across hosts, the six fleet hunts with sample output, pivots, exports, two-host lab |
| [docs/TESTING.md](docs/TESTING.md) | Test layers, how to run, full test inventory, lab procedures |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Build order and specs for modules #4 and #1, remaining ideas |
| [CLAUDE.md](CLAUDE.md) | Architecture rules and forensic gotchas for contributors (and Claude Code) |

## Credits

Methodology: SANS FOR500. Research: Yogesh Khatri (device property timestamps), Nicole Ibrahim (MTP/PTP),
Kevin Ripa (USB serial numbers), David Cowen & Phill Moore (DeviceMigration). Prior art: USB Detective (Jason Hale),
parseusbs (Kathryn Hedley), Partition-4DiagnosticParser (theAtropos4n6). Parsers: regipy, evtx (pyevtx-rs).

MIT License.
