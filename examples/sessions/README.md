# `usbhawk sessions`: which USB sessions look like data exfiltration, and why?

Module #2. It reads a host's registry hives, event logs and `setupapi.dev.log`, builds **connect → remove sessions**,
attaches users and file activity, and scores each session with explainable rules. Every point comes with a reason.
`usbhawk devices` (part of the same module) prints the raw SANS FOR500 device profile behind the sessions.

| | |
|---|---|
| **Input** | A triage folder (KAPE, Velociraptor, a mounted image) or individual files (`--system`, `--partition-log`, ...) |
| **Output** | A console table; with `--out`: `sessions.jsonl` (ECS, SIEM-ready), `sessions.csv`, `devices.jsonl` |
| **Demo data** | Real public sample hives and logs (about 30 MB, fetched once into `tests\data`, never committed) |
| **In this folder** | `approved_devices.txt`, an allowlist for the allowlist demo |
| **Full guide** | [docs/hunt-exfil-sessions.md](../../docs/hunt-exfil-sessions.md) |

Why real data here? This module parses binary registry hives and `.evtx` logs; a made-up hive would only prove that
the tool reads made-up hives. So the demo uses public evidence from the regipy project (MIT) and
Partition-4DiagnosticParser.

## 1. Get the sample evidence (once)

From the repository root:

```powershell
python scripts\fetch_test_samples.py
```

## 2. Run the demo

```powershell
usbhawk sessions --triage tests\data --tz America/New_York
```

What you should see (the table trimmed to the key columns):

```
usbhawk 1.0.0: loading artifacts
  parsed SYSTEM tests\data\SYSTEM
  parsed SOFTWARE tests\data\SOFTWARE
  parsed NTUSER data
  parsed Partition/Diagnostic tests\data\Microsoft-Windows-Partition%4Diagnostic.evtx (30 records)
work hours 08:00-18:00 America/New_York (tz from --tz); all timestamps are UTC
Host WKS-WIN732BITA  Windows 7 Ultimate 7601 tz=Eastern Standard Time last install/feature update=2010-11-10T16:28:55Z

| Score     | Connected (UTC)     | Duration | Device                   | iSerialNumber            | VSN                         | Description
| 45 medium | 2020-11-29 08:51:44 | 33m    | Patriot Memory           | 0701935D84A40B14         | C8B91B23,76D3169C,56EE2567… | off_hours; reformat_or_repartition; long_session
| 40 medium | 2020-11-29 09:47:03 | 3m     | Patriot Memory           | 0701935D84A40B14         | DAFBDA6E,8C09DE0F,CA19B8CD  | off_hours; reformat_or_repartition
| 40 medium | 2020-11-29 09:52:07 | 1m     | Kingston DataTraveler G3 | 001CC0EC3458F110E5F31400 | 2C50410B                    | off_hours; reformat_or_repartition
| 40 medium | 2020-11-29 17:28:56 | no-end | Patriot Memory           | 0701935D84A40B14         |                             | off_hours; reformat_or_repartition
| 15 low    | 2020-11-29 09:22:33 | 0m     | Kingston DT microDuo 3C  | E0D55E1F377DE410C958272B |                             | off_hours
| 15 low    | 2020-11-29 09:25:07 | 1m     | Kingston DataTraveler G3 | 001CC0EC3458F110E5F31400 | 6A844219                    | off_hours
| 15 low    | 2020-11-29 09:27:32 | 2m     | Patriot Memory           | 0701935D84A40B14         | 6ECA9A94                    | off_hours
| 15 low    | 2020-11-29 09:53:05 | 0m     | Kingston DataTraveler G3 | 001CC0EC3458F110E5F31400 | 2C50410B                    | off_hours
warning: Partition/Diagnostic log was written by DESKTOP-GOGB42D (35 records), WIN-9F6UT4I01JI (5 records), but the
registry hives are from WKS-WIN732BITA: this log comes from another machine. ...
```

### How to read it

- **Score and severity.** The points of every rule that fired, clamped to 0-100: high ≥ 70, medium ≥ 40, low ≥ 15.
- **Description.** The rules that fired, with their points in `--out` files. The Patriot stick was **reformatted or repartitioned nine times** in one day (its
  volume serial number, VSN, kept changing), which is why it is the top session. `off_hours` fires because 08:51 UTC is
  03:51 on a Sunday in New York.
- **no-end.** No removal was recorded, so the session has a start but no end.
- **The warning.** These public samples come from *different* machines. USBHawk notices that the Partition log was
  written by another computer and says so, instead of treating its devices as this host's.

## 3. Variations

```powershell
usbhawk sessions --triage tests\data --tz America/New_York --out out\sample-host
usbhawk sessions --triage tests\data --tz America/New_York --min-score 40
usbhawk sessions --triage tests\data --tz America/New_York --allowlist examples\sessions\approved_devices.txt
usbhawk sessions --triage tests\data --config config\scoring.toml
usbhawk devices --triage tests\data
```

| Command | What changes |
|---|---|
| `--out out\sample-host` | Also writes `sessions.jsonl` (one ECS document per session, with every reason), `sessions.csv` (reasons as `off_hours(+15) \| reformat_or_repartition(+25)`) and `devices.jsonl` |
| `--min-score 40` | Shows only the four medium sessions |
| `--allowlist approved_devices.txt` | The Patriot stick is on the list (company-approved), so its sessions get `allowlisted_device` (−50) and drop to `0 info` |
| `--config config\scoring.toml` | Your own work hours, thresholds and weights; set a weight to `0` to switch a rule off |
| `devices` | One JSON line per device: the FOR500 profile (vendor, product, serial, volume names, drive letters, VSNs, users, and which artifact proved each) |

From `devices`, for example, the HP stick that was mounted as `E:` with the volume name `SECRETPLANS`:

```
{"host": "WKS-WIN732BITA", "key": "VID_03F0&PID_3207\\AA951D0000007252", "serial": "AA951D0000007252",
 "friendly_name": "HP v100w USB Device", "volume_names": ["SECRETPLANS"], "drive_letters": ["E:"], "vsns": ["B84479ED"],
 "sources": ["registry:EMDMgmt", "registry:Enum\\USB", "registry:Enum\\USBSTOR", "registry:MountedDevices", ...]}
```

## 4. What a real exfiltration session looks like

The public samples have no user or file activity, so their scores stay moderate. With file telemetry
(`--file-events`, a CSV from Microsoft Defender, Sysmon 11, CrowdStrike Falcon or LECmd) and a leavers list
(`--watchlist`), the insider scenario from the guide scores like this (fictional host and user):

```
Score      Connected (UTC)      Duration  Device            Letter  VSN                 Writes  Description
100 high   2026-10-30 21:14:52  26m   Kingston DT 3.0   F:      8E2C41D7,11223344   61      first_seen_device; off_hours; file_writes;
                                                                                            bulk_transfer; archive_written;
                                                                                            reformat_or_repartition; watchlist_user
```

| Rule | Points | Why it fired |
|---|---|---|
| `first_seen_device` | +25 | The stick had never been connected to this PC before |
| `off_hours` | +15 | 21:14 UTC is 17:14 in New York, after the 17:00 end of day |
| `file_writes`, `bulk_transfer` | +20, +20 | 60 spreadsheets written to `F:\Q4_Forecast\` |
| `archive_written` | +15 | A 900 MB `F:\finance_share.7z` |
| `reformat_or_repartition` | +25 | The VSN changed from `8E2C41D7` to `11223344`: the stick was reformatted |
| `watchlist_user` | +30 | `j.doe` is on the leavers list |

The total is 150, capped at 100: **high**. This scenario is a test in
`tests/hunt_exfil_sessions/test_exfil_session_building.py`.

## 5. On your own evidence

```
usbhawk sessions --triage D:\cases\WS042 --out out\WS042
usbhawk sessions --triage D:\cases\WS042 --tz America/New_York --watchlist leavers.txt --file-events mde_DeviceFileEvents.csv --out out\WS042
```

Keep the `--out` folder: [`usbhawk graph`](../graph/README.md) reads it to follow devices across hosts.
