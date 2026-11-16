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

## Modules

| # | Module | Status | Question it answers |
|---|--------|--------|---------------------|
| 2 | `usbthk sessions`: exfil session scoring | **v0.1 (this release)** | Which USB sessions look like exfil, and why? |
| 3 | `usbthk tamper`: artifact tamper/gap detection | planned | Did someone wipe USB traces, or was it a Windows feature update? |
| 4 | `usbthk detections`: detection-as-code pack | planned | Turn the findings into Sigma / SPL / KQL / Falcon / VQL rules |
| 1 | `usbthk graph`: fleet device graph | planned | Where else has this stick been, and who else used it? |

## Install

Requires Python 3.11+. Works natively on Windows, Linux and macOS (analysis of Windows evidence).

```powershell
# Windows (PowerShell)
git clone <your-repo-url> usb-threat-hunting-toolkit
cd usb-threat-hunting-toolkit
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python scripts\fetch_test_samples.py     # public MIT-licensed sample hives/logs for tests
pytest -q
```

```bash
# Linux / macOS / WSL
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts/fetch_test_samples.py && pytest -q
```

## Quick start

```powershell
# 1. Point at a KAPE / Velociraptor triage folder or mounted image
usbthk sessions --triage D:\cases\WS042\kape --tz America/New_York --out .\out\WS042

# 2. Add EDR file telemetry (MDE DeviceFileEvents, Sysmon 11, Falcon, LECmd CSV) + HR context
usbthk sessions --triage D:\cases\WS042\kape --file-events mde_files.csv `
                --watchlist leavers.txt --allowlist approved_usb.txt --min-score 40 --out .\out

# 3. Device inventory only (11-step profile per device)
usbthk devices --triage D:\cases\WS042\kape --out .\out
```

Test on your own lab machine: `scripts\collect_local.ps1` (elevated) collects the needed artifacts with
`reg save` and `wevtutil epl`. Use a personal or lab machine, not a corporate endpoint.

Outputs in `--out`:
- `sessions.jsonl`: ECS-flavoured, one session per line, ready for Splunk/Elastic ingestion
- `sessions.csv`: flat, for analysts and reports
- `devices.jsonl`: full per-device profile

## Artifacts parsed

| Artifact | What it contributes |
|---|---|
| SYSTEM `Enum\USB` | VID/PID, iSerialNumber, class (Service), 0064/0066/0067 times |
| SYSTEM `Enum\USBSTOR`, `Enum\SCSI` (UASP) | Device ID, FriendlyName, DiskId, times; linked via property `000A` (parent instance) |
| SYSTEM `MountedDevices` | drive letter, Volume GUID |
| SYSTEM `DeviceMigration` | devices archived by feature-update cleanup (`LastPresentDate`) |
| SOFTWARE `Windows Portable Devices` | volume name (USBSTOR, UASP via DiskId, MTP) |
| SOFTWARE `VolumeInfoCache` | label → drive letter |
| SOFTWARE `EMDMgmt` | VSN (decimal → hex), volume name |
| NTUSER `MountPoints2` | user attribution via Volume GUID |
| `Partition/Diagnostic` 1006 | every connect/disconnect, capacity, MBR, VBR → VSN + partition layout |
| Security 6416 / 4663 / 4656 / 4624 / 4634 / 4647 / 4800 / 4801 | plug-ins, removable file access, user sessions |
| System 20001 / 20003, `setupapi.dev.log` | first install (setupapi local time → UTC) |
| File-event CSV | EDR file writes (drive letter or VSN matched) |

## Scoring rules (defaults; tune in `config/scoring.toml`)

| Rule | Points | Fires when |
|---|---|---|
| `first_seen_device` | 25 | session contains the device's first-ever install on the host |
| `off_hours` | 15 | connected outside configured work hours / on a non-workday |
| `file_writes` | 20 | any file written to the device during the session |
| `bulk_transfer` | 20 | ≥ 50 files or ≥ 500 MB written |
| `archive_written` | 15 | .zip/.7z/.rar/.iso/.pst/.kdbx... written to the device |
| `reformat_or_repartition` | 25 | VSN or partition layout changed within or between sessions |
| `mass_delete_on_device` | 10 | ≥ 50 deletes on the device |
| `mtp_device` | 10 | phone/tablet (no drive letter, DLP blind spot) |
| `high_capacity` | 5 | ≥ 256 GB |
| `long_session` | 5 | ≥ 30 minutes |
| `no_hardware_serial` | 5 | Windows-generated serial (hard to track fleet-wide) |
| `watchlist_user` | 30 | user on `--watchlist` active during the session |
| `allowlisted_device` | -50 | serial on `--allowlist` |

Severity: high ≥ 70, medium ≥ 40, low ≥ 15. Score is capped at 100.

## Known limitations (v0.1)

- 4663 events carry no device serial; removable volumes are inferred (a volume active ≥ 80% inside USB sessions).
- `setupapi.dev.log` conversion uses the host's current `ActiveTimeBias`, so it can be off by 1h across DST.
- Hives are read as-is; replay dirty hive transaction logs first (KAPE does; or `rla.exe`) or use `reg save` copies.
- LNK/JumpList/ShellBag parsing is via CSV import (LECmd/JLECmd) for now.

## Credits

Methodology: SANS FOR500. Research: Yogesh Khatri (device property timestamps), Nicole Ibrahim (MTP/PTP),
Kevin Ripa (USB serial numbers), David Cowen & Phill Moore (DeviceMigration). Prior art: USB Detective (Jason Hale),
parseusbs (Kathryn Hedley), Partition-4DiagnosticParser (theAtropos4n6). Parsers: regipy, evtx (pyevtx-rs).

MIT License.
