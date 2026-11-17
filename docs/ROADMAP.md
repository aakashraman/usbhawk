# Roadmap

Build order agreed: **#2 → #3 → #4 → #1**, then package as one toolkit. Go slow; every module ships with tests,
a sample run, an explanation, and is only committed after review (see `docs/TESTING.md`).

## ✅ Module #2: Exfil session scoring (`usbthk sessions`)

Done: registry/evtx/setupapi/file-CSV parsers → Evidence model → sessions → explainable scoring → JSONL/CSV/table.
Full guide: [`docs/hunt-exfil-sessions.md`](hunt-exfil-sessions.md). Tests: 38 in `tests/hunt_exfil_sessions/` plus shared `tests/foundations/`, every rule threshold covered both sides.

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

## ✅ Module #3: Tamper / cleanup detection (`usbthk tamper`)

Goal: distinguish **Windows cleanup** (feature update purge) from **deliberate wiping** (USBOblivion, manual key
deletion, log clearing). Full guide: [`docs/hunt-usb-tamper.md`](hunt-usb-tamper.md). Tests: 63 in
`tests/hunt_usb_tamper/`. Lab-verified 2026-11-16 against USBOblivion 1.17.0 on a Windows 10 VM, cross-checked
with RECmd and EvtxECmd: every wiped stick, cleared log and tool run reported, zero false positives.

Built:
- [x] `orphaned_device_reference`: device/volume survives (Partition log, MountedDevices, WPD, EMDMgmt, MountPoints2)
      but missing from `Enum`; severity by timestamp quality; raised by a log clear (24 h after) or a cleanup tool run after it
- [x] `explained_by_feature_update`: DeviceMigration, or a feature update/reinstall after the last reference
      (history from `Setup\Source OS` keys + InstallTime)
- [x] `log_cleared` (spec'd as `security_log_cleared`): Security 1102 / System 104, provider-checked
- [x] `partition_log_gap`: record-ID jumps, or a log empty / starting at record 1 after USB arrivals on the current build
- [x] `cleanup_tool_execution`: USBOblivion, DriveCleanup, USBDeview, PrivaZer, CCleaner, BleachBit, SDelete via BAM
- [x] `expected_artifact_missing`, `evidence_host_mismatch`, `orphan_checks_skipped`
- [x] UASP/MBR disks linked through the MBR disk signature (letter, volume GUID, MountPoints2 user)
- [x] Lab fixes: untrimmed registry values (regipy), MBR/`DMIO:ID:` volume GUIDs, correlation direction

Follow-ups:
- [ ] `enum_without_properties` (rule 6): Enum instance whose Properties timestamps are missing/zeroed
- [ ] Prefetch / Amcache execution evidence (BAM keeps about a week); cleanup tools' backup files (e.g. `USBOblivion-*.reg`)
- [ ] Partition logs from several files (archived copies) merged for gap detection

## ✅ Module #4: Detection-as-code pack (`usbthk detections`)

Goal: the hunts' hypotheses as live rules, generated from one source. Full guide:
[`docs/hunt-detection-rules.md`](hunt-detection-rules.md). Tests: 115 in `tests/hunt_detection_rules/` plus 54 test
events inside the rules. Lab-verified 2026-11-17 on Sysmon + Security telemetry (activity, then USBOblivion), counts
cross-checked with EvtxECmd.

Built:
- [x] 8 hypotheses / 12 detections as YAML (`src/usbthk/detections/rules/`), lists and thresholds from the hunts' config
- [x] Generators: Sigma (SigmaHQ conventions, correlation rules), Elastic (ES|QL over ECS + Kibana import), Sentinel (KQL).
      Splunk was dropped in favour of Elastic (user decision 2026-11-17)
- [x] Validation: pySigma + SigmaHQ repository validators (0 issues); ATT&CK v18 tags
- [x] `usbthk detections list | test | build | run --evtx` (replay real logs through the rules)
- [x] Lab Sysmon config (`scripts/lab/sysmon-usbthk-lab.xml`); collector exports Sysmon

Follow-ups:
- [ ] Run the Elastic rules in a live Elastic stack (field population per integration) and the KQL in Sentinel
- [ ] Cross-check generated queries against pySigma backends (Elasticsearch ES|QL, Kusto)
- [ ] CrowdStrike LogScale and Velociraptor VQL generators
- [ ] Velociraptor artifact that collects everything usbthk needs (bridges to module #1)
- [ ] Partition/Diagnostic 1006 forwarding: reformat (VSN change) as a live rule

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
