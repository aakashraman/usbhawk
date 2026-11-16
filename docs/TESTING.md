# Testing

Every module is tested in **three layers** before it is committed. A module is only "done" when all three pass
and the output has been read and explained, not just when `pytest` is green.

| Layer | What it is | Command | Passing means |
|---|---|---|---|
| **1. Automated tests** | Small scenarios with a known right answer: synthetic (fictional data) and real public samples | `pytest -q` | Every rule gives the expected answer; nothing old broke |
| **2. Sample run** | The real CLI on public sample artifacts | `usbthk sessions --triage tests\data --out out` | The output makes forensic sense on real-world files |
| **3. Lab test** | Your own device on your own lab VM: do the thing, collect, run | `scripts\collect_local.ps1`, then `usbthk ...` | It catches what you actually did |

## Running the tests

```powershell
.\.venv\Scripts\Activate.ps1
python scripts\fetch_test_samples.py     # once: downloads public samples into tests\data (gitignored)
pytest -q                                # all tests; expect "82 passed"
pytest -q tests\test_scoring_rules.py    # one file
pytest -v -k off_hours                   # tests whose name matches
```

Tests that need the public samples **skip** (they don't fail) when `tests\data` is missing, so the synthetic
tests always run, even offline.

## Rules for writing tests

1. **Tests first.** Write the test, watch it fail for the right reason, then write the code.
2. **Prove the test can fail.** After a fix, put the old code back (or break the threshold on purpose) and confirm
   the test goes red. A test that passes either way proves nothing.
3. **Test both sides of every threshold.** For "≥ 50 files", test 50 (fires) **and** 49 (doesn't).
4. **Pick values where a wrong answer flips the result.** For time zones, use times where UTC and local time
   disagree about work hours; otherwise the test passes by luck.
5. **Synthetic data is fictional.** Host `NW-FIN-WS042`, user `j.doe`, made-up serials. **Never** put real case or
   employer data in a test or fixture.
6. **Every parser or rule gets a synthetic test**, plus a real-sample test when a public sample exists.

## Public sample data

Downloaded by `scripts/fetch_test_samples.py` into `tests\data` (gitignored, never committed):

| File | Source (MIT) | Contains |
|---|---|---|
| `SYSTEM`, `SOFTWARE`, `NTUSER.DAT` | [regipy](https://github.com/mkorman90/regipy) test data | Win7 host `WKS-WIN732BITA`: HP v100w stick, `E:`, volume `SECRETPLANS`, Eastern time zone |
| `SYSTEM_WIN_10_1709` | regipy test data | Win10: SanDisk Cruzer, two UASP SSDs under `Enum\SCSI`, DeviceMigration, feature-update history |
| `Microsoft-Windows-Partition%4Diagnostic.evtx` | [Partition-4DiagnosticParser](https://github.com/theAtropos4n6/Partition-4DiagnosticParser) | 30 records: Patriot and Kingston sticks, including a repartition/reformat |

> **Caveat:** the Partition/Diagnostic log comes from a **different machine** than the Win7 hives. The sample run
> therefore attributes the Patriot/Kingston sticks to `WKS-WIN732BITA`. Module #3 adds a host-consistency check.

## Test inventory: module #2 (82 tests)

### `test_util.py` (5): low-level decoding

| Test | Proves |
|---|---|
| `test_filetime_bytes_and_int` | Windows FILETIME decodes from bytes and integers; `0` means "no time" |
| `test_vsn_offsets_all_filesystems` | The volume serial is read at the right boot-sector offset for exFAT, NTFS, FAT32, FAT16 |
| `test_mbr_partition_entry` | MBR partition entries (from 1006 events) decode correctly |
| `test_identifier_parsing` | VID/PID/serial and USBSTOR paths parse (`\` and `#` styles); the `&0` LUN suffix is stripped; composite children (`&MI_00`) are not devices; Windows-generated serials are recognised |
| `test_mounted_devices_hex_string_decode` | MountedDevices values decode whether regipy returns bytes or a hex string; MBR disk signatures are not mistaken for paths |

### `test_setupapi.py` (1): first-install times

| Test | Proves |
|---|---|
| `test_setupapi_local_time_to_utc` | `setupapi.dev.log` local time → UTC (EDT, UTC−4); non-USB installs ignored |

### `test_real_samples.py` (3): real public artifacts

| Test | Proves |
|---|---|
| `test_win7_full_registry_profile` | Full 11-step profile from real hives: HP v100w, `E:`, volume GUID, `SECRETPLANS`, VSN `B84479ED`, time zone |
| `test_win10_uasp_linked_via_parent_property` | Fast USB SSDs found under `Enum\SCSI` and linked via property `000A`; the Cruzer found under `USBSTOR` |
| `test_partition_diagnostic_detects_reformat` | 30 records parsed; the Patriot stick's four VSNs found and its reformat flagged |

### `test_sessions_scoring.py` (5): the end-to-end insider scenario

| Test | Proves |
|---|---|
| `test_one_session_with_dedupe_and_duration` | Three artifacts recording one plug-in → **one** session; duration 26 m 15 s; `first_seen`; user attached |
| `test_full_scoring_with_edr_file_events` | MDE CSV import; 7 rules fire; the `C:\` file is excluded; score 100 / high |
| `test_allowlist_pulls_score_down` | An approved serial subtracts 50 |
| `test_4663_volume_inference` | Security 4663 without a serial: the USB volume is inferred, the busy system volume is not |
| `test_orphan_and_missing_disconnect` | A connect with no removal for > 24 h closes; the next connect starts a new session |

### `test_scoring_rules.py` (28): each rule and its threshold, in isolation

All at Mon 2026-11-16 10:00 New York, inside work hours, so `off_hours` adds no noise.

| Test | Fires at | Does not fire at |
|---|---|---|
| `test_quiet_session_scores_zero` | n/a | A 5-minute session with no activity scores 0 / info |
| `test_file_writes_fires_on_one_write` | 1 write | n/a |
| `test_bulk_transfer_by_file_count` | 50 files | 49 files |
| `test_bulk_transfer_by_bytes` | 500 MB | 500 MB − 1 byte |
| `test_archive_written` (×6) | `.zip .7z .RAR .pst .kdbx .iso` | n/a |
| `test_archive_not_fired_for_documents` | n/a | `.docx`, and `zip_notes.txt` (the extension must match, not just the name) |
| `test_mass_delete_on_device` | 50 deletes | 49 deletes |
| `test_mtp_device` | MTP class | USB storage |
| `test_high_capacity` | 256 GB | 255.99 GB |
| `test_long_session` | 30 min | 29 min |
| `test_no_hardware_serial` | `7&2A1B3C4D&0` | A real serial |
| `test_reformat_between_sessions_via_new_vsn` | 2nd connect with a new VSN | 1st connect (nothing to compare) |
| `test_watchlist_matches_domain_qualified_user` | `J.DOE` matches `j.doe` (case-insensitive) | `a.smith` |
| `test_allowlist_never_goes_below_zero` | Allowlist alone → score 0, not −50 | n/a |
| `test_severity_boundaries` (×6) | 15 low, 40 medium, 70 high | 14 info, 39 low, 69 medium |
| `test_score_is_capped_at_100` | 180 points → 100 | n/a |
| `test_disabling_a_rule_with_zero_weight` | n/a | Weight `0` turns a rule off |
| `test_every_point_has_a_reason` | Every reason is `{rule, points, why}`, and the score equals the sum (capped) | n/a |

### `test_output.py` (5): the SIEM contract

If one of these breaks, a Splunk/Elastic search or dashboard probably breaks too.

| Test | Proves |
|---|---|
| `test_ecs_document_has_siem_fields` | `@timestamp`, `event.*` (duration in **nanoseconds**), `host.name`, `user.name`, `usb.device.*`, reasons, byte counts |
| `test_all_timestamps_are_utc_z` | Every timestamp ends in `Z` |
| `test_jsonl_one_valid_document_per_session` | One valid JSON document per line, one line per session |
| `test_csv_columns_and_reason_format` | Exact CSV header; reasons formatted `rule(+points)`; lists `;`-separated |
| `test_session_id_is_stable_across_runs` | The same evidence gives the same session ID (no duplicate SIEM records on re-run) |

### `test_timezone.py` (14): the work-hours clock

| Test | Proves |
|---|---|
| `test_afternoon_in_new_york_is_work_hours` | 20:00 UTC = 15:00 New York is **not** flagged (UTC would flag it) |
| `test_early_morning_in_new_york_is_off_hours...` | 12:30 UTC = 07:30 New York **is** flagged, with local time in the reason |
| `test_unknown_timezone_fails_loudly` | A bad zone name stops with an error instead of silently using UTC |
| `test_work_hours_edge_cases` (×8) | DST spring forward and fall back; Sunday UTC = Monday Tokyo; Friday UTC = Saturday Tokyo; India's +5:30; 08:00 inclusive; 18:00 exclusive |
| `test_config_file_timezone_and_cli_override` | Config file sets the zone; `--tz` overrides it |
| `test_bad_timezone_in_config_file_fails_loudly` | `Eastern Standard Time` (a Windows name) in the config is rejected |
| `test_shipped_example_config_loads` | `config/scoring.toml` is valid |

### `test_host_timezone.py` (21): time zone auto-detected from the host

| Test | Proves |
|---|---|
| `test_common_windows_zones_map_to_iana` (×7) | `Eastern Standard Time` → `America/New_York`, India, London, Berlin, Sydney, UTC, Pacific |
| `test_every_mapped_zone_exists_in_tz_database` | All 151 table entries resolve in the real tz database |
| `test_unknown_or_unresolved_names_return_none` | Empty, `@tzres.dll,-112`, unknown names → no mapping |
| `test_registry_padding_is_tolerated` | Win7's NUL padding after the name is ignored |
| `test_host_registry_used_when_nothing_else_given` | No `--tz`, no config → the host's zone is used |
| `test_cli_tz_beats_host_registry` / `test_config_file_beats_host_registry` | The priority order holds |
| `test_falls_back_to_utc_with_warning` (×3) | Unmappable zone → UTC **plus a warning** |
| `test_apply_host_timezone_does_not_mutate_input` | The config passed in is not changed |
| `test_2pm_new_york_is_not_flagged_when_tz_comes_from_host` | The false alarm the feature exists to prevent |
| `test_off_hours_reason_shows_utc_local_and_tz_source` | The reason shows the UTC time, local time and zone source |
| `test_win7_sample_host_timezone_resolves` | The real Win7 hive's zone maps to `America/New_York` |
| `test_cli_without_tz_uses_host_registry` | End-to-end through the CLI |

## Proving the tests have teeth

These checks were run by hand when the tests were written (temporarily breaking the code, then restoring it):

| Broken on purpose | Tests that went red |
|---|---|
| Original v0.1 `scoring.py` with no `tzdata` installed (silent UTC fallback) | 10 of 14 in `test_timezone.py` |
| `long_session` threshold `>=` changed to `>` | `test_long_session` |
| `mass_delete_on_device` threshold `>=` changed to `>` | `test_mass_delete_on_device` |

## Lab test (layer 3)

Use a **throwaway Windows VM** with a snapshot, never your main machine or a work endpoint.

| Step | Do | Expect from `usbthk sessions` |
|---|---|---|
| 1. Snapshot | Take a VM snapshot | n/a |
| 2. Baseline | Connect a USB stick to the VM, copy a few files, eject | One session; `first_seen_device`; correct letter and volume name |
| 3. After hours | Repeat outside 08:00–18:00 local (or set `--tz` to a zone where it is night) | `off_hours` with the right local time |
| 4. Reformat | Format the stick (Explorer → Format), reconnect | `reformat_or_repartition` |
| 5. Collect | Elevated: `powershell -ExecutionPolicy Bypass -File .\scripts\collect_local.ps1 -Out C:\usbthk-triage` | n/a |
| 6. Run | Copy `C:\usbthk-triage` to the analysis machine; `usbthk sessions --triage <folder> --out out` | The sessions above, with reasons |
| 7. Reset | Revert the snapshot | Clean VM for the next test |
