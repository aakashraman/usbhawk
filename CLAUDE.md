# CLAUDE.md: USBHawk (`usbhawk`)

Context for Claude Code working in this repo. Owner: Aakash (detection engineer, DFIR). Primary dev machine is
**Windows** (PowerShell); Linux/WSL also fine. Keep everything cross-platform.

## What this is
A Python toolkit that analyses **offline Windows evidence** (KAPE/Velociraptor triage folders, mounted images)
for USB-based data exfiltration and related threats. Built on the classic 11-step USB profiling method, extended for
threat hunting. Name the course/methodology only in the README's "Credits and references" (owner's rule). Roadmap and module specs: `docs/ROADMAP.md`. Build order: #2 → #3 → #4 → #1, all done.
One guide per hunt in `docs/hunt-*.md`; tests in `tests/foundations/` and one `tests/hunt_*/` folder per module.

## Commands
```powershell
py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1        # Linux: python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts\fetch_test_samples.py    # downloads public sample hives/evtx into tests\data (gitignored)
pip install -e ".[dev,sigma]"           # sigma extra: pySigma + SigmaHQ validators (Sigma tests skip without it)
pytest -q                               # must stay green (438); run after every change
pytest -q tests\hunt_usb_tamper         # one hunt's tests
usbhawk sessions --triage tests\data --tz America/New_York
usbhawk devices  --triage tests\data
usbhawk tamper   --triage tests\data     # expect only evidence_host_mismatch (the samples mix hosts)
usbhawk detections test                  # every rule's own test events
usbhawk detections build --out build     # build/ is gitignored; never commit generated rules
usbhawk detections run --evtx <logs> --removable-drives F:
usbhawk graph --runs <folder of per-host --out folders> [--out fleet] [device QUERY | user NAME]
python scripts\make_examples.py          # regenerate examples/ after changing the fleet, timeline or wiped-host builders
python scripts\fetch_demo_datasets.py --list   # public real data (NIST case, EVTX-ATTACK) into ~\usbhawk-datasets
pip install -e ".[dev,build]"; powershell -ExecutionPolicy Bypass -File scripts\build_release.ps1
                                         # dist\: usbhawk.exe zip + wheel, smoke-tested, SHA256SUMS (dist/ gitignored)
```

## Architecture (keep these boundaries)
```
parsers/ (registry.py, evtx_logs.py, setupapi.py, file_events.py)
   └─> model.Evidence { host: HostInfo, devices: {key: Device}, events: [Event], unlinked, migrated, ... }
         └─> sessions.build_sessions()  -> [Session]   (pairing, dedupe, users, file attach)
               └─> scoring.score_sessions(cfg)          (explainable rules -> score, severity, reasons)
                     └─> output.py                      (ECS JSONL, CSV, rich table)
         └─> tamper.find_tamper()       -> [Finding]   (module #3: orphans, log clears, gaps, cleanup tools)
detections/ (module #4)  rules/H*.yml (source of truth, ${...} from tamper.CLEANUP_TOOLS + scoring config)
            core.py: validate + reference evaluator   generators.py: sigma | elastic | sentinel   replay.py: .evtx -> alerts
graph.py (module #1)     reads many hosts' devices/sessions/tamper .jsonl (never raw evidence) -> clusters -> G1-G6,
            pivots, JSON/GraphML/Cypher. Identity: serial (high) > vsn (medium) > name+capacity (low).
            Cluster.id must be unique (weak serials repeat: `@host` suffix), or exports merge separate sticks
collect.py  discovers artifacts in a folder and runs parsers in order: SYSTEM → SOFTWARE → NTUSER → logs → CSVs,
            then link_mbr_volumes() (needs MountedDevices + 1006 MBR signatures)
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
- regipy **trims values to 128 bytes by default**: always `iter_values(trim_values=False)` (done in `registry._values`).
  Lab-found: MountedDevices USBSTOR paths lost the end of the serial → false "missing from Enum".
- MBR volumes get GUIDs `{SIG-0000-0000-OFFSET}` (disk signature + partition offset, LE) and dynamic disks
  store `DMIO:ID:`+GUID; neither appears as a `\??\Volume` name (`util.mounted_volume_guid`). MountPoints2
  GUIDs of the MBR form are typed `mbr_volume` and never count as tamper evidence.
- Detection rules: the evaluator in `detections/core.py` is the spec; every generator must match it (tests enforce).
  Sigma output follows SigmaHQ (file prefixes, Title Case, UUID v4, no MITRE links in references; pySigma + SigmaHQ
  validators must report 0 issues). ATT&CK is v18: TA0005 = Stealth, TA0112 = Defense Impairment, log clearing T1685.005.
  Never silently weaken a rule a platform cannot express: emit `.unsupported.txt` and say why.
- Lab-found: Explorer deletes + recreates `MountPoints2\{vol}\shell\Autoplay\DropTarget` on every mount (H8 excludes it);
  USBOblivion clears 10 logs by spawning `wevtutil cl` (not Sysmon).
- RECmd recovers deleted keys/values by default (`Deleted=True` in the batch CSV; plugin CSVs don't flag it):
  when cross-checking a wiped hive, compare against live keys only.
- USBSTOR/SCSI → USB parent link uses property `{83da6326-...}\000A` (parent instance id), not string matching.
- UASP devices live in `Enum\SCSI`; Enum\USB instance often `MSFT30...`. Service `UASPStor`.
- Properties `0064` first install, `0066` last arrival, `0067` last removal (`0065` = driver install, ignored).
- Partition/Diagnostic 1006: `Capacity == 0` means disconnect; repeated connects without disconnect = sleep/resume or
  partition changes; `RegistryId` == Partmgr `DiskId`; VSN offsets FAT12/16 0x27, FAT32 0x43, exFAT 0x64, NTFS 0x48.
- Partition layout/VSN change between consecutive 1006 connects = repartition/reformat (real sample: Patriot stick).
- setupapi.dev.log is **local time** → UTC via `ActiveTimeBias` (approximate across DST).
- 4663 has no device serial; removable volume inferred from activity inside sessions (≥80%).
- MountPoints2 can attribute to the *last logged-on* user; treat as supporting evidence, not proof.
- Windows 7 (NIST CFReDS case): no `0066/0067` properties and no Partition/Diagnostic log, so only first connections;
  EMDMgmt entries may lack the `USBSTOR#` device path; MBR volumes stay unlinked. Plans in `ideas/`.
- Event logs can mix computer names on ONE host (renamed PC, base image): `evidence_host_mismatch` says "mixed" when
  the host's own name is also present; exclusion is per record, never per log.
- Collections hold several hives with one name (KAPE copies `config\RegBack`: 0-byte since Win10 1803; `Windows.old`).
  `collect._hive_rank` picks `Windows\System32\config`, skips empty files and lists the rest in `arts.skipped`.
  Lab-found while documenting KAPE: an empty RegBack\SYSTEM used to replace the live hive.
- Table headings name what each time is (owner's request): `Connected (UTC)`, `Source Timestamp (UTC)`,
  `Event Timestamp (UTC)`, `First / Last Seen (UTC)`; explanation columns are `Description`. JSON/CSV field names
  (`why`, `reasons`, `serial`) never change: they are the SIEM contract.
- H3/H4 skip Windows-written files on the stick (`$RECYCLE.BIN\...\$I*` metadata, System Volume Information) but
  NOT other files inside `$RECYCLE.BIN` (an insider can hide data there). Owner's real-PC Sysmon run, 2026-11-18.
- `detections run --evtx` must survive unreadable logs (live folder without admin, locked, damaged): skip and list;
  it ends with `coverage_gaps()` (telemetry the rules need but the logs lack). Zero alerts must never look clean.
- Real PC (owner's, 2026-11-18): card readers log 1006 "no media" removals on every poll (only a device's first
  removal may start an end-only session); composite devices (`usbccgp`) get their class from `&MI_` interfaces via
  `ParentIdPrefix`; Windows 11 rotates setupapi.dev.log into `setupapi.dev.<date>.log` (all are read; the current
  one must exist or `expected_artifact_missing` fires).
- CLI: `graph --runs` is `nargs="+"`, so pivot words follow it directly (`_split_pivot`); missing `--runs`,
  `--config` or list files are errors, never silent defaults.
- Windows has no IANA tz database: `tzdata` is a win32 dependency, and an unresolvable work-hours zone must raise,
  never fall back silently. Work-hours tz priority: `--tz` > config > host `TimeZoneKeyName` (`tzmap.py`) > UTC + warning.
  Timestamps stay UTC everywhere; only the `off_hours` judgement is local.
- Real KAPE case (1.0.1, 2026-11-18). Evidence from a running PC is imperfect: read .evtx through
  `evtx_logs.iter_evtx_records` (skips damaged chunks/records, counts them; never PyEvtxParser directly), and guard
  every `System`/`Event` dict (`"System": null` happens). Dirty hives (header sequence numbers differ) are flagged in
  `ev.host.dirty_hives`; orphans on a dirty SYSTEM carry a caution. `detections run` takes H2's zone from `--tz`, else
  the SYSTEM hive under `--evtx`. Windows logs 6416 per plug-in twice (USB node + USBSTOR disk): the table pairs them
  (`_pair_plug_ins`), alerts.jsonl keeps both. Evidence text in rich tables goes through `rich.markup.escape`
  (a `[lowercase ...]` substring is otherwise read as markup and silently dropped).

## Testing conventions
- Every parser/rule gets (a) a synthetic unit test, (b) guard tests for where it must stay quiet, and (c) a real-sample
  test if a sample exists (`tests/foundations/test_public_samples.py` style, auto-skips when `tests/data` is missing).
- Tests go in the hunt's folder (`tests/hunt_<name>/test_<hunt>_*.py`); shared decoding/time tests in `tests/foundations/`.
  Basenames must be unique across folders (no `__init__.py`); `conftest.py` helpers import as `from conftest import ...`.
- Never commit evidence or sample artifacts (`tests/data/` is gitignored). Never commit real case, employer or lab-VM
  data; a lab finding becomes a regression test with fictional values (see `test_tamper_usboblivion_lab.py`).
- Synthetic scenarios use fictional values (e.g., host NW-FIN-WS042, user j.doe).
- Lab tests: throwaway VM + snapshot, triage copied to `C:\lab` (outside the repo and OneDrive), cross-checked with
  RECmd/EvtxECmd. Procedure and results: `docs/TESTING.md`, `docs/hunt-usb-tamper.md`, `docs/hunt-detection-rules.md`.
- Detection rules: every detection needs must-match and must-not-match test events in its YAML; lab false positives
  become `match: false` test events with a `note` saying they were lab-observed.
- Fleet graph tests build hosts with `tests/hunt_fleet_device_graph/fleet_builder.py`, which writes through the REAL
  module #2/#3 writers; never hand-write per-host JSONL. Lab-found: module #2 tags users as `name (MountPoints2)`.
- Binary demo evidence (registry hives, evtx) is WRITTEN, never copied from a machine: `tests/hunt_usb_tamper/
  wiped_host_builder.py` has a small deterministic regf writer (ASCII names, `lh` lists, no big-data cells) and an
  empty-evtx writer. Mirror the value types of a real hive (DEVPROP 0xFFFF0010 FILETIME / 0xFFFF0012 string, inline
  values <= 4 bytes); check new output with RECmd/EvtxECmd once. `make_examples.py` clears files, never folders
  (OneDrive can hold a folder open: rmtree failed with access denied).
- Every documented "sample output" is backed by a test (`test_detection_sample_timeline.py`, `test_fleet_sample_fleet.py`).

## Status and next steps
All four modules are done and the project is branded **USBHawk** (one command, `usbhawk`). The banner
lives in `banner.py` (help always; runs: stderr on a TTY only, never stdout, off with `-q` / `USBHAWK_NO_BANNER=1`);
every command's help comes from `HELP` in `cli.py` (question, examples, outputs, guide). New commands must add a
`HELP` entry and a case in `tests/foundations/test_cli_help_and_banner.py`.
Version 1.0.1 (single source `usbhawk.__version__`): standalone exe + wheel via `scripts/build_release.ps1`, demo kit
in `examples/`, one folder per tool (tested by `tests/examples_demo/`: every `usbhawk` line in a powershell/bash
block of `examples/**/README.md`, plus the `examples` demos in README.md and GETTING-STARTED, is run; unlabelled
blocks are not),
docs in `docs/GETTING-STARTED.md` and `docs/REFERENCE.md`, `CHANGELOG.md`. Future work: one file per idea in
`ideas/`. Publishing to GitHub is the owner's decision; never push without an explicit OK.

## Style
Python 3.11+, type hints, small pure functions, f-strings, no print() inside library code (use the `verbose` callback / logging).
Commit messages: imperative, scoped (`parsers: add 104/1102`, `tamper: orphaned WPD rule`). Owner's rule: no emojis and
no AI attribution lines (no Co-Authored-By); feature commits list each use case with a short sample of real output.
