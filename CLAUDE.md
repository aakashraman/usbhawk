# CLAUDE.md: USB Threat Hunting Toolkit (`usbthk`)

Context for Claude Code working in this repo. Owner: Aakash (detection engineer, DFIR). Primary dev machine is
**Windows** (PowerShell); Linux/WSL also fine. Keep everything cross-platform.

## What this is
A Python toolkit that analyses **offline Windows evidence** (KAPE/Velociraptor triage folders, mounted images)
for USB-based data exfiltration and related threats. Built on the SANS FOR500 11-step USB profiling method,
extended for threat hunting. Roadmap and module specs: `docs/ROADMAP.md`. Build order: #2 (done) → #3 → #4 → #1.

## Commands
```powershell
py -3.12 -m venv .venv; .\.venv\Scripts\Activate.ps1     # Linux: python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts\fetch_test_samples.py    # downloads public sample hives/evtx into tests\data (gitignored)
pytest -q                               # must stay green; run after every change
usbthk sessions --triage tests\data --tz America/New_York
usbthk devices  --triage tests\data
```

## Architecture (keep these boundaries)
```
parsers/ (registry.py, evtx_logs.py, setupapi.py, file_events.py)
   └─> model.Evidence { host: HostInfo, devices: {key: Device}, events: [Event], unlinked, migrated, ... }
         └─> sessions.build_sessions()  -> [Session]   (pairing, dedupe, users, file attach)
               └─> scoring.score_sessions(cfg)          (explainable rules -> score, severity, reasons)
                     └─> output.py                      (ECS JSONL, CSV, rich table)
collect.py  discovers artifacts in a folder and runs parsers in order: SYSTEM → SOFTWARE → NTUSER → logs → CSVs
cli.py      argparse subcommands
```
- **Parsers never score; scorers never parse.** New sources (EDR, Velociraptor, Linux) = new parser emitting `Device`/`Event`.
- Device key is always `VID_xxxx&PID_yyyy\SERIAL` (uppercase) via `util.device_key()`. Use `Evidence.device()` to get-or-create.
- All timestamps are **aware UTC datetimes** (`util.to_utc`). Convert local-time sources explicitly (see setupapi).
- Every scoring rule appends `{"rule", "points", "why"}`; a score without reasons is a bug.
- One bad artifact must never kill a run: `collect.load()` wraps each parser and records `ev.warnings`.
- Keep runtime deps minimal (regipy, evtx, rich). No network calls at runtime.

## Forensic gotchas already handled (don't regress)
- regipy returns REG_BINARY as **hex strings** sometimes → `util.as_bytes()`; REG_SZ can be raw UTF-16 bytes → `clean_reg_string()`.
- USBSTOR/SCSI → USB parent link uses property `{83da6326-...}\000A` (parent instance id), not string matching.
- UASP devices live in `Enum\SCSI`; Enum\USB instance often `MSFT30...`. Service `UASPStor`.
- Properties `0064` first install, `0066` last arrival, `0067` last removal (`0065` = driver install, ignored).
- Partition/Diagnostic 1006: `Capacity == 0` means disconnect; repeated connects without disconnect = sleep/resume or
  partition changes; `RegistryId` == Partmgr `DiskId`; VSN offsets FAT12/16 0x27, FAT32 0x43, exFAT 0x64, NTFS 0x48.
- Partition layout/VSN change between consecutive 1006 connects = repartition/reformat (real sample: Patriot stick).
- setupapi.dev.log is **local time** → UTC via `ActiveTimeBias` (approximate across DST).
- 4663 has no device serial; removable volume inferred from activity inside sessions (≥80%).
- MountPoints2 can attribute to the *last logged-on* user; treat as supporting evidence, not proof.

## Testing conventions
- Every parser/rule gets (a) a synthetic unit test and (b) a real-sample test if a sample exists (`tests/test_real_samples.py`,
  auto-skips when `tests/data` is missing).
- Never commit evidence or sample artifacts (`tests/data/` is gitignored). Never commit real case data or employer data.
- Synthetic scenarios use fictional values (e.g., host NW-FIN-WS042, user j.doe).

## Next task (Module #3: tamper detection)
Create `src/usbthk/tamper.py` + `usbthk tamper` subcommand per the spec in `docs/ROADMAP.md`. Start with rules 1, 2 and 4
(orphaned references vs feature-update explanation; log cleared 1102/104). Inputs already exist on `Evidence`
(`unlinked`, `migrated`, `host.install_time`). Add System/Security 104/1102 parsing to `evtx_logs.py`.
Output findings as JSONL with the same `{"rule","severity","why","evidence"}` shape. Add tests first.

## Style
Python 3.11+, type hints, small pure functions, f-strings, no print() inside library code (use the `verbose` callback / logging).
Commit messages: imperative, scoped (`parsers: add 104/1102`, `tamper: orphaned WPD rule`).
