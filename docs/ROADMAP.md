# Roadmap

Build order agreed: **#2 → #3 → #4 → #1**, then package as one toolkit. Go slow; every module ships with tests,
a sample run, an explanation, and is only committed after review (see `docs/TESTING.md`).

## ✅ Module #2: Exfil session scoring (`usbhawk sessions`)

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

## ✅ Module #3: Tamper / cleanup detection (`usbhawk tamper`)

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

## ✅ Module #4: Detection-as-code pack (`usbhawk detections`)

Goal: the hunts' hypotheses as live rules, generated from one source. Full guide:
[`docs/hunt-detection-rules.md`](hunt-detection-rules.md). Tests: 115 in `tests/hunt_detection_rules/` plus 54 test
events inside the rules. Lab-verified 2026-11-17 on Sysmon + Security telemetry (activity, then USBOblivion), counts
cross-checked with EvtxECmd.

Built:
- [x] 8 hypotheses / 12 detections as YAML (`src/usbhawk/detections/rules/`), lists and thresholds from the hunts' config
- [x] Generators: Sigma (SigmaHQ conventions, correlation rules), Elastic (ES|QL over ECS + Kibana import), Sentinel (KQL).
      Splunk was dropped in favour of Elastic (user decision 2026-11-17)
- [x] Validation: pySigma + SigmaHQ repository validators (0 issues); ATT&CK v18 tags
- [x] `usbhawk detections list | test | build | run --evtx` (replay real logs through the rules)
- [x] Lab Sysmon config (`scripts/lab/sysmon-usbhawk-lab.xml`); collector exports Sysmon

Follow-ups:
- [ ] Run the Elastic rules in a live Elastic stack (field population per integration) and the KQL in Sentinel
- [ ] Cross-check generated queries against pySigma backends (Elasticsearch ES|QL, Kusto)
- [ ] CrowdStrike LogScale and Velociraptor VQL generators
- [ ] Velociraptor artifact that collects everything usbhawk needs (bridges to module #1)
- [ ] Partition/Diagnostic 1006 forwarding: reformat (VSN change) as a live rule

## ✅ Module #1: Fleet device graph (`usbhawk graph`)

Goal: "Where else has this stick been, and who else used it?" Full guide:
[`docs/hunt-fleet-device-graph.md`](hunt-fleet-device-graph.md). Tests: 49 in `tests/hunt_fleet_device_graph/`.
Lab-verified 2026-11-17 on two real machines sharing one USB disk.

Built:
- [x] Reads the per-host outputs of modules #2 and #3 (devices, sessions, tamper) from any number of hosts
- [x] Identity: real serial (high), shared VSN (medium), volume name + capacity (low); weak and Windows-generated
      serials never trusted alone; two real serials never merged
- [x] Hunts: device_on_many_hosts, device_shared_by_users, exfil_device_spread, wiped_here_seen_there, new_to_fleet,
      serial_collision
- [x] Pivots by device and by user; exports graph.json, GraphML, Neo4j Cypher, findings.jsonl (ECS)
- [x] Plain-Python graph (no NetworkX dependency)

Follow-ups:
- [ ] File nodes (WROTE edges from session file samples) and LNK/JumpList evidence of files opened from a stick
- [ ] Velociraptor hunt artifact producing per-host outputs for the whole fleet
- [ ] Load the Cypher export into a live Neo4j and ship example BloodHound-style queries

## Packaging: USBHawk

Done (2026-11-17):
- [x] Name: **USBHawk**; command `usbhawk`; output datasets and fields `usbhawk.*`
- [x] Single CLI with subcommands `sessions`, `tamper`, `detections`, `graph`, `devices`
- [x] ASCII banner in help and on interactive runs (stderr only; never in JSON/CSV; `-q` / `USBHAWK_NO_BANNER=1`)
- [x] `--help` per command: the question it answers, options, examples, output files, guide

Done (1.0.0, 2026-11-17):
- [x] Standalone Windows `usbhawk.exe` (PyInstaller, one file) and a wheel; `python -m usbhawk`;
      `scripts/build_release.ps1` builds both, smoke-tests them and writes SHA-256 hashes
- [x] Demo kit (`examples/`) for every module, run by the tests; public real data on demand
      (`scripts/fetch_demo_datasets.py`); getting-started guide, reference, changelog
- [x] Validated on the NIST CFReDS Data Leakage case and EVTX-ATTACK-SAMPLES (`docs/TESTING.md`)

Next:
- [ ] Publish the GitHub repository and the 1.0.0 release (owner's decision)
- [ ] Release builds in GitHub Actions on windows-latest, signed (`ideas/signed-releases.md`)
- [ ] Velociraptor artifact + KAPE module definitions that produce USBHawk's inputs (`ideas/velociraptor-kape.md`)
- [ ] Windows 7 gaps found on the NIST case (`ideas/win7-last-connection.md` and the two after it)
- [ ] A docs site (mkdocs) from `docs/`

More ideas, one file each: [ideas/](../ideas/README.md).
