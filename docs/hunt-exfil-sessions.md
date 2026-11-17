# Module #2: Exfil session scoring (`usbhawk sessions`)

> **Question it answers:** *When was a USB device plugged in, by whom, what happened while it was connected,
> and how suspicious was that?*

Most USB forensics tools stop at inventory: *"a Kingston stick was connected to this PC."* That is a fact, not a
finding. `usbhawk sessions` turns the same artifacts into **sessions** (one plug-in to one removal) and scores each
one with explainable rules:

> *A never-seen Kingston stick was connected for 26 minutes after hours while 61 files (1.6 GB) were written to it,
> including `finance_share.7z`, then the volume was reformatted. The user is on the leavers list.* → **100 / high**

Sessions are the unit an analyst actually triages, and every point of the score comes with a reason you can paste
into a case note.

---

## Contents

1. [The big picture](#1-the-big-picture)
2. [Stage 1: Collect](#2-stage-1-collect)
3. [Stage 2: Parse](#3-stage-2-parse)
4. [Stage 3: Build sessions](#4-stage-3-build-sessions)
5. [Stage 4: Score](#5-stage-4-score)
6. [Stage 5: Output](#6-stage-5-output)
7. [Worked example](#7-worked-example)
8. [How to run it](#8-how-to-run-it)
9. [Reading the results](#9-reading-the-results)
10. [Command reference](#10-command-reference)
11. [Known limitations](#11-known-limitations)

---

## 1. The big picture

```
 Triage folder ──► 1. COLLECT ──► 2. PARSE ──► 3. SESSIONS ──► 4. SCORE ──► 5. OUTPUT
 (KAPE / Velo /     find the       Device +      connect→remove   13 rules,     JSONL (SIEM)
  mounted image)    artifacts      Event list    windows + users  each with a   CSV (Excel)
                                                 + file activity  reason        terminal table
```

| Stage | Code | One job |
|---|---|---|
| Collect | `collect.py` | Find artifacts in a folder; run each parser; never let one bad file stop the run |
| Parse | `parsers/*.py` | Turn raw artifacts into `Device` and `Event` objects (`model.py`) |
| Sessions | `sessions.py` | Pair connects with removals; attach users and file activity |
| Score | `scoring.py` | Apply the rules; every point gets a `{"rule", "points", "why"}` reason |
| Output | `output.py` | Write ECS JSONL, CSV and the console table |

**Design rule: parsers never score, scorers never parse.** A new evidence source (CrowdStrike, Velociraptor, Linux)
is just a new parser that emits `Device`/`Event` objects; nothing downstream changes.

---

## 2. Stage 1: Collect

`collect.discover()` walks the `--triage` folder and picks up artifacts by name:

| File name | Used as |
|---|---|
| `SYSTEM`, `SOFTWARE` (preferring a `...\config\` path) | registry hives |
| `NTUSER.DAT` | per-user hive; the **parent folder name** becomes the username |
| `*Partition*Diagnostic*.evtx` | disk connect/disconnect log (the most valuable log for USB) |
| `Security.evtx`, `System.evtx` | logons, plug-ins, file access, first installs |
| `setupapi.dev*.log` | first install times |

File-activity CSVs (EDR exports) are **not** auto-discovered. Pass them with `--file-events`. Any artifact can also
be given by hand (`--system`, `--ntuser PATH=USER`, `--partition-log`, ...).

Parsers run in a fixed order (**SYSTEM → SOFTWARE → NTUSER → logs → CSVs**) because later artifacts are linked to
devices found by earlier ones. If a parser fails, the error is recorded as a warning and the run continues.

**Where the evidence comes from:**

- Real cases: KAPE targets `RegistryHives`, `EventLogs`, `USBDevicesLogs`, `LnkFilesAndJumpLists`, or a
  Velociraptor collection.
- Your own lab machine: `scripts\collect_local.ps1` (elevated) uses `reg save` and `wevtutil epl`.

---

## 3. Stage 2: Parse

Every source becomes two kinds of object:

- **`Device`**: everything known about one physical device on one host. The key is always
  `VID_xxxx&PID_yyyy\SERIAL` (uppercase).
- **`Event`**: one timestamped fact (`connect`, `disconnect`, `first_install`, `file_write`, `logon`, ...), always
  in **UTC**, always naming the artifact it came from.

| Artifact | What it contributes | FOR500 step |
|---|---|---|
| SYSTEM `Enum\USB` | VID, PID, iSerialNumber, class (driver service) | 1–3 |
| SYSTEM `Enum\USBSTOR`, `Enum\SCSI` (UASP) | Vendor/product, friendly name, DiskId | 4 |
| Device properties `0064` / `0066` / `0067` | First install / last connect / last removal | 5–6 |
| SOFTWARE `Windows Portable Devices` | Volume name (also MTP phones) | 7 |
| SOFTWARE `VolumeInfoCache`, SYSTEM `MountedDevices` | Drive letter | 8 |
| SYSTEM `MountedDevices` | Volume GUID | 9 |
| NTUSER `MountPoints2` | Which user mounted the volume | 10 |
| SOFTWARE `EMDMgmt`, Partition/Diagnostic 1006 | Volume serial number (VSN) | 11 |
| Partition/Diagnostic 1006 | **Every** connect/disconnect, capacity, partition table, VSN | beyond FOR500 |
| Security 6416 / 4663 / 4656 / 4624 / 4634 / 4647 / 4800 / 4801 | Plug-ins, file access, logon sessions | beyond FOR500 |
| System 20001 / 20003, `setupapi.dev.log` | First install time | 5 |
| File-event CSV (MDE, Sysmon 11, Falcon, LECmd) | File writes / reads / deletes, sizes | beyond FOR500 |

**Forensic details already handled** (see `CLAUDE.md` for the full list):

- Fast USB SSDs (UASP) live under `Enum\SCSI`, not `USBSTOR`. A USBSTOR-only tool misses them.
- `USBSTOR`/`SCSI` entries are linked to their `Enum\USB` parent through property `000A`, not by string matching.
- The volume serial is read from the boot sector at the right offset per filesystem (FAT 0x27, FAT32 0x43,
  exFAT 0x64, NTFS 0x48).
- `setupapi.dev.log` is in **local** time and is converted to UTC with the host's `ActiveTimeBias`.

---

## 4. Stage 3: Build sessions

A **session** is one window from *connect* to *removal* for one device. This is the core logic, and each rule below
solves a real-world problem:

| Problem | Rule | Default |
|---|---|---|
| Three artifacts record the **same** plug-in a second apart | Same-direction events within N seconds merge into one | 10 s |
| The removal record is missing | If the next connect is more than N hours after the last one, close the session (no end) and start a new one | 24 h |
| Was this the device's **first time** on this PC? | The first-install time falls inside the session (±2 min) → `first_seen = true` | ±2 min |
| The stick was **reformatted or repartitioned** | VSN or partition layout differs between consecutive 1006 connects | n/a |
| Removal with no matching connect | Kept as a session with an end but no start (still worth reviewing) | n/a |
| Only storage matters for exfil | Only `usbstor`, `uasp`, `mtp` (or anything with disk events) by default; `--all-classes` shows HID, hubs, etc. | storage only |

**Who was at the keyboard?** Users are attached from logon/logoff events (4624/4634/4647) whose window overlaps the
session. `MountPoints2` adds a user too, tagged `(MountPoints2)`, but it can point at the *last logged-on* user, so
treat it as supporting evidence, not proof.

**Which file activity belongs to the stick?** File events inside the session window are matched in this order:

1. **Volume serial (VSN)**: strongest, survives drive-letter changes.
2. **Drive letter**: the device's known letter; `C:` is never treated as removable.
3. **Security 4663 volume number**: 4663 has no serial, so a `\Device\HarddiskVolumeN` whose activity falls
   **≥ 80 %** inside USB sessions is inferred to be removable. The system volume is busy all day, so it never
   qualifies.

Each session gets a **stable ID** (hash of host + device + start), so re-running the same case does not create
duplicate SIEM records.

---

## 5. Stage 4: Score

Thirteen rules. Each one that fires adds its points **and** a human-readable reason.

| Rule | Points | Fires when | Threshold key in `scoring.toml` |
|---|---|---|---|
| `first_seen_device` | 25 | The session contains the device's first-ever install on this host | n/a |
| `off_hours` | 15 | Connected outside work hours or on a non-workday (local clock, see below) | `[work_hours]` |
| `file_writes` | 20 | Any file written to the device during the session | n/a |
| `bulk_transfer` | 20 | ≥ 50 files **or** ≥ 500 MB written | `bulk_files`, `bulk_bytes` |
| `archive_written` | 15 | `.zip .7z .rar .tar .gz .tgz .cab .iso .pst .kdbx` written | `archive_extensions` |
| `reformat_or_repartition` | 25 | VSN or partition layout changed within or between sessions | n/a |
| `mass_delete_on_device` | 10 | ≥ 50 delete events on the device | `bulk_files` |
| `mtp_device` | 10 | Phone/tablet (MTP): no drive letter, often a DLP blind spot | n/a |
| `high_capacity` | 5 | Device ≥ 256 GB | `high_capacity_bytes` |
| `long_session` | 5 | Connected ≥ 30 minutes | `long_session_minutes` |
| `no_hardware_serial` | 5 | Windows-generated serial (2nd char `&`): hard to track across the fleet | n/a |
| `watchlist_user` | 30 | A user on `--watchlist` (e.g. leavers) was active during the session | `watchlist_users` |
| `allowlisted_device` | **−50** | Serial is on `--allowlist` (approved company sticks) | `allowlist_serials` |

**Score and severity:** points are summed and clamped to **0–100**.

| Severity | Score |
|---|---|
| high | ≥ 70 |
| medium | ≥ 40 |
| low | ≥ 15 |
| info | < 15 |

Every weight and threshold can be tuned in `config/scoring.toml`. Setting a weight to `0` disables that rule.

### Time zones: UTC for facts, local clock for one judgement

- **Every timestamp the tool stores or outputs is UTC.** Analysts in any country read the same value, and
  sessions line up with EDR, SIEM, firewall and cloud logs, which are UTC too.
- **Only `off_hours` uses a local clock**, because *after hours* only means something on the employee's own clock.
  A 2 PM copy in New York is 19:00 UTC; judged in UTC it would be a false alarm.

The work-hours time zone is chosen in this order:

1. `--tz America/New_York` on the command line
2. `[work_hours] timezone` in the config file
3. **The host's own registry time zone** (`TimeZoneKeyName`, e.g. `Eastern Standard Time`), mapped to IANA
   (`America/New_York`) with an embedded CLDR table (`tzmap.py`)
4. UTC, **with a warning** telling you to pass `--tz`

The reason text shows both clocks and where the zone came from:

```
connected 2020-11-29 08:51Z = Sun 2020-11-29 03:51 America/New_York, outside work hours (tz from host registry: Eastern Standard Time)
```

The registry only holds the host's *current* zone. For a laptop that travels, older sessions may have happened
elsewhere; pass `--tz` if you know better.

---

## 6. Stage 5: Output

With `--out <folder>` you get three files. Without it, only the console table is shown.

### `sessions.jsonl` (for Splunk / Elastic)

One JSON document per session, using ECS field names where they exist:

| Field | Example | Notes |
|---|---|---|
| `@timestamp` | `2026-10-30T21:14:52Z` | Session start (UTC) |
| `event.dataset` | `usbhawk.session` | Filter on this in the SIEM |
| `event.start` / `event.end` | `...21:14:52Z` / `...21:41:07Z` | `end` is `null` if no removal was found |
| `event.duration` | `1575000000000` | **Nanoseconds** (ECS convention) |
| `event.risk_score` / `event.severity_label` | `100` / `high` | |
| `host.name` | `NW-FIN-WS042` | |
| `user.name` / `user.names` | `NW\j.doe` | First user / all users |
| `usb.device.*` | `serial`, `vid`, `pid`, `vendor`, `product`, `class`, `capacity_bytes`, `drive_letters`, `volume_names`, `vsns_all_time`, ... | Full device profile |
| `usbhawk.session_id` | `a1b2c3d4e5f60718` | Stable across re-runs |
| `usbhawk.reasons` | `[{"rule": "...", "points": 25, "why": "..."}]` | **The explanation** |
| `usbhawk.vsns` | `["8E2C41D7", "11223344"]` | VSNs seen *in this session* |
| `usbhawk.evidence.start` / `.end` | `["registry:Enum\\USBSTOR:0066", "evtx:Partition/Diagnostic:1006"]` | Which artifacts prove the times |
| `usbhawk.file_activity` | `writes`, `reads`, `deletes`, `bytes_written`, `sample` (first 25 paths) | |

### `sessions.csv` (for Excel and reports)

Columns: `score, severity, host, start_utc, end_utc, duration_min, device_class, vendor, product, serial,
volume_names, drive_letters, vsns, users, file_writes, first_seen, reasons, session_id`.
Lists are `;`-separated; reasons look like `first_seen_device(+25) | off_hours(+15)`.

### `devices.jsonl`

The full 11-step profile for every device found, including non-storage devices. This is the same data as
`usbhawk devices`.

---

## 7. Worked example

The synthetic insider scenario in `tests/hunt_exfil_sessions/test_exfil_session_building.py`: Friday 2026-10-30, fictional employee `j.doe`
on `NW-FIN-WS042`, work hours 08:00–17:00 New York (UTC−4 in October).

| UTC time | What happened | What the tool does |
|---|---|---|
| 20:50 | `j.doe` logs on | Logon window opens |
| 21:14:52 | A never-seen Kingston stick is plugged in. `Enum\USB 0064`, `USBSTOR 0066` and Partition 1006 all record it within 1 s | Merged into **one** session; `first_seen_device` (+25) |
| 21:14 | 17:14 local, after the 17:00 end of day | `off_hours` (+15) |
| 21:20–21:29 | 60 × 12 MB `.xlsx` files written to `F:\Q4_Forecast\` | `file_writes` (+20), `bulk_transfer` (+20) |
| 21:30 | 900 MB `F:\finance_share.7z` written | `archive_written` (+15) |
| 21:30 | `C:\Users\j.doe\notes.txt` written | **Ignored**: not on the stick |
| 21:38 | Partition 1006 shows a new VSN (`8E2C41D7` → `11223344`) | `reformat_or_repartition` (+25) |
| 21:41:07 | Stick removed | Session = 26 min 15 s |
| n/a | `j.doe` is on the leavers list | `watchlist_user` (+30) |

**Total:** 25 + 15 + 20 + 20 + 15 + 25 + 30 = 150 → **capped at 100 → high**.

---

## 8. How to run it

**Step 1: open PowerShell in the project and activate the environment**

```powershell
cd C:\path\to\usb-threat-hunting-toolkit
.\.venv\Scripts\Activate.ps1
```

✅ The prompt starts with `(.venv)`.

**Step 2: run it on the public sample data**

```powershell
usbhawk sessions --triage tests\data --out out
```

✅ Expect `work hours 08:00-18:00 America/New_York (tz from host registry: Eastern Standard Time)` and
`wrote 8 sessions to out`.

**Step 3: read the results with their reasons**

```powershell
Get-Content out\sessions.jsonl | ConvertFrom-Json | ForEach-Object {
  "{0} {1,3}  {2}" -f $_.usbhawk.severity, $_.usbhawk.score, $_.usb.device.product
  $_.usbhawk.reasons | ForEach-Object { "      +{0} {1}: {2}" -f $_.points, $_.rule, $_.why }
}
```

✅ Expect 4 **medium** sessions (Patriot / Kingston sticks reformatted, after hours) and 4 **low** ones.

**Step 4 (optional): open the spreadsheet**

```powershell
start out\sessions.csv
```

**On a real case:**

```powershell
# Triage folder + EDR file telemetry + HR context, only show medium and above
usbhawk sessions --triage D:\cases\WS042\kape `
                --file-events D:\cases\WS042\mde_DeviceFileEvents.csv `
                --watchlist leavers.txt --allowlist approved_usb.txt `
                --min-score 40 --out D:\cases\WS042\usbhawk
```

**On your own lab machine** (elevated PowerShell, a machine you own):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\collect_local.ps1 -Out C:\usbhawk-triage
usbhawk sessions --triage C:\usbhawk-triage --out .\out
```

Plug in a thumb drive, copy some files, reformat it, then collect and run again to watch the rules fire.

---

## 9. Reading the results

1. **Start with the score and severity.** High (≥ 70) first, then medium.
2. **Read the reasons.** They are the finding. A 45 made of `off_hours + reformat_or_repartition + long_session`
   tells a different story from a 45 made of `file_writes + bulk_transfer`.
3. **Check `usbhawk.evidence`.** It lists the artifacts that prove the start and end times. Two independent
   sources agreeing (registry + event log) is stronger than one.
4. **Pivot on the device.** Use `usb.device.serial` and `vsns_all_time` to find the same stick in other sessions,
   on other hosts (module #1), or in LNK files.
5. **Remember the gaps.** No file events usually means *no telemetry*, not *no copying*. Add `--file-events` from
   your EDR when you have it.

---

## 10. Command reference

```
usbhawk sessions [evidence options] [--out DIR] [scoring options]
usbhawk devices  [evidence options] [--out DIR]
```

| Option | What it does |
|---|---|
| `--triage DIR` | Auto-discover artifacts in a KAPE/Velociraptor folder or mounted image |
| `--system`, `--software` | SYSTEM / SOFTWARE hive (overrides discovery) |
| `--ntuser PATH[=USER]` | NTUSER.DAT, repeatable; username defaults to the parent folder name |
| `--partition-log`, `--security-log`, `--system-log` | Event logs, repeatable |
| `--setupapi PATH` | `setupapi.dev.log`, repeatable |
| `--file-events CSV` | EDR file activity; column names are matched automatically (MDE `DeviceFileEvents`, Sysmon 11, Falcon, LECmd) |
| `--out DIR` | Write `sessions.jsonl`, `sessions.csv`, `devices.jsonl` |
| `-q`, `--quiet` | No progress messages |
| `--config FILE` | Scoring TOML (see `config/scoring.toml`) |
| `--tz ZONE` | IANA zone for work hours; default is config, then the host registry, then UTC |
| `--watchlist FILE` | Usernames, one per line (`#` comments allowed), e.g. leavers |
| `--allowlist FILE` | Approved device serials, one per line |
| `--min-score N` | Only output sessions scoring ≥ N |
| `--all-classes` | Include HID, hubs, etc., not just storage |
| `--limit N` | Rows to print in the console table (files always get everything) |

---

## 11. Known limitations

- **Security 4663 has no device serial.** Removable volumes are inferred (≥ 80 % of activity inside USB sessions).
- **`setupapi.dev.log` uses the host's *current* time bias**, so it can be an hour off across a DST change.
- **Hives are read as-is.** Replay dirty transaction logs first (KAPE does this; or `rla.exe`), or use `reg save`
  copies.
- **LNK / JumpList / ShellBag data comes in via CSV** (LECmd/JLECmd output) for now.
- **The registry time zone is the *current* one.** Pass `--tz` for laptops that travel.
- **No file telemetry means no file rules.** Without `--file-events` or Security 4663 auditing,
  `file_writes`/`bulk_transfer`/`archive_written` cannot fire.
