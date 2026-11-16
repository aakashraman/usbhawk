# USB Threat Hunting Toolkit (`usbthk`)

Windows USB forensics built for **threat hunting and incident response**, not just device inventory.

Most USB tools answer *"what devices were plugged in?"*. `usbthk` answers *"which USB sessions look like data
exfiltration, and why?"*. It turns the SANS FOR500 11-step device profiling process into connect → remove
**sessions**, attaches users and file activity, and scores every session with explainable rules.

```
Score      Start (UTC)          Dur   Class    Device            Letter  VSN                 Writes  Why
100 high   2026-10-30 21:14:52  26m   usbstor  Kingston DT 3.0   F:      8E2C41D7,11223344   61      first_seen_device; off_hours; file_writes;
                                                                                                     bulk_transfer; archive_written;
                                                                                                     reformat_or_repartition; watchlist_user
```
*(Synthetic insider scenario from `tests/test_sessions_scoring.py`.)*

Every point of every score comes with a reason, e.g.
`off_hours +15: connected 2026-10-30 21:14Z = Fri 2026-10-30 17:14 America/New_York, outside work hours (tz from --tz)`.

## Modules

| # | Module | Status | Question it answers | Docs |
|---|--------|--------|---------------------|------|
| 2 | `usbthk sessions`: exfil session scoring | **done** | Which USB sessions look like exfil, and why? | [guide](docs/module2-sessions.md) |
| 3 | `usbthk tamper`: artifact tamper/gap detection | next | Did someone wipe USB traces, or was it a Windows feature update? | [roadmap](docs/ROADMAP.md#module-3-tamper--gap-detection-usbthk-tamper) |
| 4 | `usbthk detections`: detection-as-code pack | planned | Turn the findings into Sigma / SPL / KQL / Falcon / VQL rules | [roadmap](docs/ROADMAP.md#module-4-detection-as-code-pack-usbthk-detections) |
| 1 | `usbthk graph`: fleet device graph | planned | Where else has this stick been, and who else used it? | [roadmap](docs/ROADMAP.md#module-1-fleet-device-graph-usbthk-graph) |

## Install

Requires Python 3.11+. Works natively on Windows, Linux and macOS (it analyses Windows evidence).

```powershell
# Windows (PowerShell)
git clone <your-repo-url> usb-threat-hunting-toolkit
cd usb-threat-hunting-toolkit
py -3 -m venv .venv                      # any Python 3.11+ (3.13 tested on Windows 11)
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python scripts\fetch_test_samples.py     # public MIT-licensed sample hives/logs for tests
pytest -q                                # expect: 82 passed
```

```bash
# Linux / macOS / WSL
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts/fetch_test_samples.py && pytest -q
```

## Quick start

```powershell
# 1. Try it on the public sample data
usbthk sessions --triage tests\data --out out

# 2. A real case: KAPE / Velociraptor triage folder or mounted image
usbthk sessions --triage D:\cases\WS042\kape --out .\out\WS042

# 3. Add EDR file telemetry (MDE DeviceFileEvents, Sysmon 11, Falcon, LECmd CSV) + HR context
usbthk sessions --triage D:\cases\WS042\kape --file-events mde_files.csv `
                --watchlist leavers.txt --allowlist approved_usb.txt --min-score 40 --out .\out

# 4. Device inventory only (11-step profile per device)
usbthk devices --triage D:\cases\WS042\kape --out .\out
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
**[docs/module2-sessions.md](docs/module2-sessions.md)**.

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
| SYSTEM `MountedDevices` | Drive letter, Volume GUID |
| SYSTEM `DeviceMigration` | Devices archived by feature-update cleanup (`LastPresentDate`) |
| SYSTEM `TimeZoneInformation` | Host time zone (work hours) and bias (setupapi conversion) |
| SOFTWARE `Windows Portable Devices` | Volume name (USBSTOR, UASP via DiskId, MTP) |
| SOFTWARE `VolumeInfoCache` | Label → drive letter |
| SOFTWARE `EMDMgmt` | VSN (decimal → hex), volume name |
| NTUSER `MountPoints2` | User attribution via Volume GUID |
| `Partition/Diagnostic` 1006 | Every connect/disconnect, capacity, MBR, VBR → VSN + partition layout |
| Security 6416 / 4663 / 4656 / 4624 / 4634 / 4647 / 4800 / 4801 | Plug-ins, removable file access, user sessions |
| System 20001 / 20003, `setupapi.dev.log` | First install (setupapi local time → UTC) |
| File-event CSV | EDR file writes (drive letter or VSN matched) |

## Testing

Every module is tested in three layers before it is committed: **automated tests** (`pytest -q`, 82 tests), a
**sample run** on public artifacts, and a **lab test** on a throwaway VM. Every rule threshold is tested on both
sides (e.g. 50 files fires, 49 doesn't), and the SIEM output fields are pinned by a contract test.

Test inventory, sample-data notes, rules for writing tests and the lab procedure:
**[docs/TESTING.md](docs/TESTING.md)**.

## Known limitations

- 4663 events carry no device serial; removable volumes are inferred (a volume active ≥ 80 % inside USB sessions).
- `setupapi.dev.log` conversion uses the host's current `ActiveTimeBias`, so it can be off by 1 h across DST.
- Hives are read as-is; replay dirty hive transaction logs first (KAPE does; or `rla.exe`) or use `reg save` copies.
- LNK/JumpList/ShellBag parsing is via CSV import (LECmd/JLECmd) for now.
- The registry time zone is the host's *current* one; pass `--tz` for laptops that travel.

## Documentation

| Doc | Contents |
|---|---|
| [docs/module2-sessions.md](docs/module2-sessions.md) | Module #2 in depth: pipeline, session logic, rules, output fields, how to run and read results |
| [docs/TESTING.md](docs/TESTING.md) | Test layers, how to run, full test inventory, lab procedure |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Build order and specs for modules #3, #4, #1 |
| [CLAUDE.md](CLAUDE.md) | Architecture rules and forensic gotchas for contributors (and Claude Code) |

## Credits

Methodology: SANS FOR500. Research: Yogesh Khatri (device property timestamps), Nicole Ibrahim (MTP/PTP),
Kevin Ripa (USB serial numbers), David Cowen & Phill Moore (DeviceMigration). Prior art: USB Detective (Jason Hale),
parseusbs (Kathryn Hedley), Partition-4DiagnosticParser (theAtropos4n6). Parsers: regipy, evtx (pyevtx-rs).

MIT License.
