# Roadmap

Build order agreed: **#2 → #3 → #4 → #1**, then package as one toolkit. Go slow; every module ships with tests,
a sample run, an explanation, and is only committed after review (see `docs/TESTING.md`).

## ✅ Module #2: Exfil session scoring (`usbthk sessions`)

Done: registry/evtx/setupapi/file-CSV parsers → Evidence model → sessions → explainable scoring → JSONL/CSV/table.
Full guide: [`docs/module2-sessions.md`](module2-sessions.md). Tests: 82, every rule threshold covered both sides.

Hardening after v0.1:
- [x] Windows: `tzdata` dependency; unknown work-hours zone now errors instead of silently using UTC
- [x] Work-hours zone auto-detected from the host registry (`TimeZoneKeyName` → IANA); reasons show UTC + local
- [x] Per-rule threshold tests and an output (SIEM field) contract test

Follow-ups (small, pick any):
- [ ] `--lnk-csv` first-class import of LECmd/JLECmd output, matched by VSN (stronger than drive letter)
- [ ] Staging signal: archive creation on C:/shares in the 60 min *before* a session (`staging_before_session`)
- [ ] HTML report per host (session timeline + reasons)
- [ ] Replay dirty hive transaction logs via regipy's recovery helpers
- [ ] DriverFrameworks-UserMode 2003/2100/2102 and Kernel-PnP/Configuration 400/410 parsers

## Module #3: Tamper / gap detection (`usbthk tamper`)

Goal: distinguish **Windows cleanup** (feature update purge) from **deliberate wiping** (USBOblivion, manual key deletion, log clearing).

Inputs already captured in `Evidence`: `unlinked` (WPD/MountedDevices/EMDMgmt/MountPoints2 entries with no `Enum` parent),
`migrated` (DeviceMigration), `host.install_time`, every event timestamp.

Findings to implement (each a function returning `Finding(rule, severity, why, evidence)`):
1. `orphaned_device_reference`: device in WPD/MountedDevices/EMDMgmt/MountPoints2 but missing from `Enum\USB`/`USBSTOR`,
   **and** absent from DeviceMigration, **and** no feature update after its last-write time → likely manual deletion.
2. `explained_by_feature_update`: same orphan but `install_time` > reference time, or present in DeviceMigration → benign (info).
3. `partition_log_gap`: Partition/Diagnostic record IDs jump, or log starts long after `install_time`.
4. `security_log_cleared`: Security 1102 / System 104.
5. `cleanup_tool_execution`: USBOblivion/PrivaZer/CCleaner in Prefetch/Amcache/BAM (needs a small Prefetch/Amcache parser or CSV import).
6. `enum_without_properties`: Enum instance whose Properties timestamps are missing/zeroed.

Tests: scenarios S1–S8 on synthetic Evidence (clean, wiped, explained-by-update, DeviceMigration, log cleared,
wipe + log clear, no-timestamp reference, mixed-host evidence) + public samples + lab VM (USBOblivion, `wevtutil cl`).

Findings from investigating the public samples (2026-11-15):
- The Win7 sample has **no** orphaned MountPoints2 GUIDs (both are local C:/D: volumes): it is a clean negative control.
- Win10 1709 `DeviceMigration` `LastPresentDate` is a REG_BINARY FILETIME hex string; v0.1 decodes it to `None`. Fix first.
- `SYSTEM\Setup\Source OS (Updated on <date>)` keys give the **full feature-update history**, better than `InstallTime` alone.
- `MountedDevices` / `EMDMgmt` unlinked entries carry no timestamp yet; add `ref_time` + scope (entry vs parent key).
- `tests/data` mixes hosts (Win7 hives + another PC's Partition log): add an evtx `Computer` vs hostname check.

## Module #4: Detection-as-code pack (`usbthk detections`)

Goal: generate deployable rules from the same rule definitions the scorer uses.
- `detections/rules/*.yml`: one source-of-truth YAML per hypothesis (H1–H8 from the blog)
- Generators: Sigma (SigmaHQ format), Splunk SPL, Microsoft KQL (MDE), CrowdStrike LogScale, Velociraptor VQL artifact
- `usbthk detections build --target splunk --out build/` and `usbthk detections test` (validate Sigma with `sigma-cli` / pySigma)
- Include the Velociraptor artifact that collects everything `usbthk` needs (bridges to module #1)

## Module #1: Fleet device graph (`usbthk graph`)

Goal: "Where else has this stick been, and who else used it?"
- Ingest many hosts' `devices.jsonl` + `sessions.jsonl` (from Velociraptor hunt or per-host runs)
- Nodes: Device (iSerialNumber; VSN as secondary), Host, User, File/Folder; edges: CONNECTED_TO, USED_BY, WROTE
- Backends: NetworkX in-memory first; export to GraphML/Neo4j (BloodHound-style queries) later
- Hunts: device on > N hosts (sneakernet/malware spread), device shared between users, first-seen-in-enterprise devices
- Windows-generated serials (`?&...`) are host-local, so join them on VSN/volume name with a lower confidence

## Packaging: "USB Threat Hunting Toolkit"

- Single CLI with subcommands: `sessions`, `devices`, `tamper`, `detections`, `graph`
- PyPI package + standalone Windows `usbthk.exe` via PyInstaller (GitHub Actions on windows-latest)
- Velociraptor artifact + KAPE module definitions
- Docs site (mkdocs) reusing the Medium post content
