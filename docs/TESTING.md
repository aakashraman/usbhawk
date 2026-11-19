# Testing

Every module is tested in **three layers** before it is committed. A module is only "done" when all three pass
and the output has been read and explained, not just when `pytest` is green.

| Layer | What it is | Command | Passing means |
|---|---|---|---|
| **1. Automated tests** | Small scenarios with a known right answer: synthetic (fictional data) and real public samples | `pytest -q` | Every rule gives the expected answer; nothing old broke |
| **2. Sample run** | The real CLI on public sample artifacts | `usbhawk sessions --triage tests\data --out out` | The output makes forensic sense on real-world files |
| **3. Lab test** | Your own device on your own lab VM: do the thing, collect, run, cross-check with Eric Zimmerman's tools | `scripts\collect_local.ps1`, then `usbhawk ...` | It catches what you actually did, and only that |

## Layout: one folder per hunt

```
tests/
  conftest.py                         shared helpers (utc(), sample(), DATA)
  foundations/                        decoding and time, used by every hunt
  hunt_exfil_sessions/                module #2: usbhawk sessions
  hunt_usb_tamper/                    module #3: usbhawk tamper
  hunt_detection_rules/               module #4: usbhawk detections
  hunt_fleet_device_graph/            module #1: usbhawk graph (fleet_builder.py writes fictional hosts with the real writers)
  examples_demo/                      the demo kit: examples/ is current and every demo command in its READMEs runs
  data/                               public samples, downloaded, gitignored, never committed
```

## Running the tests

```powershell
.\.venv\Scripts\Activate.ps1
python scripts\fetch_test_samples.py              # once: downloads public samples into tests\data (gitignored)
pip install -e ".[dev,sigma]"                     # once: pytest + pySigma and the SigmaHQ validators
pytest -q                                         # all tests; expect "449 passed"
usbhawk detections test                            # module #4: every rule's own test events
pytest -q tests\hunt_usb_tamper                   # one hunt
pytest -q tests\hunt_exfil_sessions\test_exfil_scoring_rules.py   # one file
pytest -v -k off_hours                            # tests whose name matches
```

Tests that need the public samples **skip** (they don't fail) when `tests\data` is missing, so the synthetic
tests always run, even offline.

## Rules for writing tests

1. **Tests first.** Write the test, watch it fail for the right reason, then write the code.
2. **Prove the test can fail.** After a fix, put the old code back (or break the rule on purpose) and confirm
   the test goes red. A test that passes either way proves nothing.
3. **Test both sides of every threshold.** For "≥ 50 files", test 50 (fires) **and** 49 (doesn't).
4. **Pick values where a wrong answer flips the result.** For time zones, use times where UTC and local time
   disagree about work hours; otherwise the test passes by luck.
5. **Synthetic data is fictional.** Host `NW-FIN-WS042`, user `j.doe`, made-up serials. **Never** put real case,
   employer or lab-VM data in a test or fixture. A lab finding becomes a test by reproducing it with fictional values.
6. **Every parser or rule gets a synthetic test**, plus a real-sample test when a public sample exists.
7. **Every rule also gets guard tests**: the cases where it must stay quiet (rolled-over log, tool run before use,
   log from another machine...). False positives are bugs too.

## Public sample data

Downloaded by `scripts/fetch_test_samples.py` into `tests\data` (gitignored, never committed):

| File | Source (MIT) | Contains |
|---|---|---|
| `SYSTEM`, `SOFTWARE`, `NTUSER.DAT` | [regipy](https://github.com/mkorman90/regipy) test data | Win7 host `WKS-WIN732BITA`: HP v100w stick, `E:`, volume `SECRETPLANS`, Eastern time zone |
| `SYSTEM_WIN_10_1709` | regipy test data | Win10: SanDisk Cruzer, two UASP SSDs under `Enum\SCSI`, DeviceMigration, feature-update history |
| `Microsoft-Windows-Partition%4Diagnostic.evtx` | [Partition-4DiagnosticParser](https://github.com/theAtropos4n6/Partition-4DiagnosticParser) | 40 records: Patriot and Kingston sticks, including a repartition/reformat |

> **Caveat:** the Partition/Diagnostic log comes from **two other machines** (`DESKTOP-GOGB42D`,
> `WIN-9F6UT4I01JI`), not the Win7 host. Module #3's `evidence_host_mismatch` reports this and excludes those
> devices from tamper checks; module #2 shows it as a warning.

## Test inventory (449 tests)

| Folder | Tests |
|---|---|
| `foundations/` | 68 |
| `hunt_exfil_sessions/` (module #2) | 41 |
| `hunt_usb_tamper/` (module #3) | 96 |
| `hunt_detection_rules/` (module #4) | 138 (4 skip without the `[sigma]` extra) |
| `hunt_fleet_device_graph/` (module #1) | 54 |
| `examples_demo/` (the demo kit) | 52 (10 skip without `tests\data`) |

Module #4 rules also carry their own **59 test events** (run by `usbhawk detections test` and by
`test_rule_passes_its_own_test_events`): every detection has events that must match and events that must not.

### `foundations/test_cli_help_and_banner.py` (17): the command line people see

| Test | Proves |
|---|---|
| `test_banner_text`, `test_version` | Banner art, tagline and version; `usbhawk --version` |
| `test_top_level_help_shows_banner_hunts_and_examples` / `test_no_command_prints_help_instead_of_an_error` | `usbhawk --help` and a bare `usbhawk` show the banner, every command and examples |
| `test_every_command_help_has_examples` (×7) | Every command and the `detections build/run` actions have examples; each hunt links its guide |
| `test_banner_on_an_interactive_terminal` / `test_no_banner_when_output_is_not_a_terminal` / `test_no_banner_with_quiet_or_env` | The banner goes to stderr on a terminal only; never when piped, with `-q` or `USBHAWK_NO_BANNER=1` |
| `test_json_on_stdout_stays_clean_with_a_banner` | With the banner on, every stdout line of `usbhawk devices` is still pure JSON |
| `test_one_command_is_installed` / `test_output_datasets_use_the_new_name` | Installing the package gives one command, `usbhawk`; output datasets and fields are `usbhawk.*` |

### `foundations/test_artifact_decoding.py` (5): low-level decoding

| Test | Proves |
|---|---|
| `test_filetime_bytes_and_int` | Windows FILETIME decodes from bytes and integers; `0` means "no time" |
| `test_vsn_offsets_all_filesystems` | The volume serial is read at the right boot-sector offset for exFAT, NTFS, FAT32, FAT16 |
| `test_mbr_partition_entry` | MBR partition entries (from 1006 events) decode correctly |
| `test_identifier_parsing` | VID/PID/serial and USBSTOR paths parse (`\` and `#` styles); the `&0` LUN suffix is stripped; composite children (`&MI_00`) are not devices; Windows-generated serials are recognised |
| `test_mounted_devices_hex_string_decode` | MountedDevices values decode whether regipy returns bytes or a hex string; MBR disk signatures are not mistaken for paths |

### `foundations/test_setupapi_log.py` (5): first-install times

| Test | Proves |
|---|---|
| `test_setupapi_local_time_to_utc` | `setupapi.dev.log` local time → UTC (EDT, UTC−4); non-USB installs ignored |
| `test_summer_install_collected_in_winter_uses_summer_offset` / `test_winter_install_uses_winter_offset` | 1.0.2, real-case: the host's zone with its DST rules, not the collection-time bias; an October (EDT) install on a PC collected in EST lands at the right hour |
| `test_unknown_zone_falls_back_to_active_time_bias` / `test_no_zone_and_no_bias_is_flagged_as_assumed_utc` | Unknown zone: the bias, said in `tz_used`; nothing at all: assumed UTC and flagged |

### `foundations/test_public_samples.py` (3): real public artifacts

| Test | Proves |
|---|---|
| `test_win7_full_registry_profile` | Full 11-step profile from real hives: HP v100w, `E:`, volume GUID, `SECRETPLANS`, VSN `B84479ED`, time zone |
| `test_win10_uasp_linked_via_parent_property` | Fast USB SSDs found under `Enum\SCSI` and linked via property `000A`; the Cruzer found under `USBSTOR` |
| `test_partition_diagnostic_detects_reformat` | Records parsed; the Patriot stick's four VSNs found and its reformat flagged |

### `foundations/test_utc_timestamps.py` (14): the work-hours clock

| Test | Proves |
|---|---|
| `test_afternoon_in_new_york_is_work_hours` | 20:00 UTC = 15:00 New York is **not** flagged (UTC would flag it) |
| `test_early_morning_in_new_york_is_off_hours...` | 12:30 UTC = 07:30 New York **is** flagged, with local time in the reason |
| `test_unknown_timezone_fails_loudly` | A bad zone name stops with an error instead of silently using UTC |
| `test_work_hours_edge_cases` (×8) | DST spring forward and fall back; Sunday UTC = Monday Tokyo; Friday UTC = Saturday Tokyo; India's +5:30; 08:00 inclusive; 18:00 exclusive |
| `test_config_file_timezone_and_cli_override` | Config file sets the zone; `--tz` overrides it |
| `test_bad_timezone_in_config_file_fails_loudly` | `Eastern Standard Time` (a Windows name) in the config is rejected |
| `test_shipped_example_config_loads` | `config/scoring.toml` is valid |

### `foundations/test_host_work_hours_tz.py` (24): time zone auto-detected from the host

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
| `test_missing_config_file_is_an_error_not_silent_defaults` / `test_cli_reports_missing_config_and_list_files` | A mistyped `--config`, `--watchlist` or `--allowlist` stops with a clear error instead of running on defaults |

### `hunt_exfil_sessions/test_exfil_session_building.py` (8): the end-to-end insider scenario

| Test | Proves |
|---|---|
| `test_one_session_with_dedupe_and_duration` | Three artifacts recording one plug-in → **one** session; duration 26 m 15 s; `first_seen`; user attached |
| `test_full_scoring_with_edr_file_events` | MDE CSV import; 7 rules fire; the `C:\` file is excluded; score 100 / high |
| `test_allowlist_pulls_score_down` | An approved serial subtracts 50 |
| `test_4663_volume_inference` | Security 4663 without a serial: the USB volume is inferred, the busy system volume is not |
| `test_orphan_and_missing_disconnect` | A connect with no removal for > 24 h closes; the next connect starts a new session |
| `test_repeat_removals_without_a_connect_are_not_sessions` / `test_a_card_inserted_later_is_still_a_normal_session` | Found on a real PC (test case 3.8): an empty card-reader slot's 1,624 "no media" removals each became a session (1,655 sessions, now 29). Only the first removal may start an end-only session; the rest are counted in one warning; a card inserted later still pairs normally |
| `test_table_says_unknown_connect_and_flags_generated_serials` | A session without a connect time shows `unknown (removed ...)` instead of `?` / `no-end`; a Windows-made instance ID shows as `(none) <id>`, not as an iSerialNumber |

### `hunt_exfil_sessions/test_exfil_scoring_rules.py` (28): each rule and its threshold, in isolation

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

### `hunt_exfil_sessions/test_exfil_siem_output.py` (5): the SIEM contract

If one of these breaks, a Splunk/Elastic search or dashboard probably breaks too.

| Test | Proves |
|---|---|
| `test_ecs_document_has_siem_fields` | `@timestamp`, `event.*` (duration in **nanoseconds**), `host.name`, `user.name`, `usb.device.*`, reasons, byte counts |
| `test_all_timestamps_are_utc_z` | Every timestamp ends in `Z` |
| `test_jsonl_one_valid_document_per_session` | One valid JSON document per line, one line per session |
| `test_csv_columns_and_reason_format` | Exact CSV header; reasons formatted `rule(+points)`; lists `;`-separated |
| `test_session_id_is_stable_across_runs` | The same evidence gives the same session ID (no duplicate SIEM records on re-run) |

### `hunt_usb_tamper/test_tamper_scenarios.py` (22): scenarios S1–S8 on synthetic evidence

Fictional host `NW-FIN-WS042`, user `j.doe`; the "wiped" stick was last seen Fri 2026-10-30 21:14Z.

| Test | Proves |
|---|---|
| `test_s1_clean_host_has_no_findings` | A stick still fully in Enum produces nothing (negative control) |
| `test_s2_device_only_in_partition_log_is_orphaned` | A stick only the Partition log remembers is a **medium** orphan naming its surviving source |
| `test_s2_unlinked_wpd_reference_is_orphaned` | A Windows Portable Devices entry with no Enum parent is an orphan |
| `test_s3_feature_update_after_last_reference_explains_it` | An update **after** the last reference → `explained_by_feature_update` (info), not an alert |
| `test_s4_device_in_device_migration_is_explained` / `..._unlinked_reference_matching_device_migration_...` | DeviceMigration explains both device and unlinked-reference orphans |
| `test_s5_security_log_cleared_is_high` / `..._system_log_and_partition_log_cleared_are_high` / `..._other_log_cleared_is_medium` | Log-clear severity by channel |
| `test_s6_orphan_near_log_clear_is_raised_to_high` / `test_s6_log_clear_days_later_does_not_raise` | 24 h correlation window, both sides |
| `test_s7_*` (×4) | Weak timestamps: no timestamp (low with updates on record, medium without); parent-key upper bound (low); an update after the upper bound still explains |
| `test_s8_foreign_log_device_is_not_an_orphan_and_mismatch_is_reported` / `test_s8_fqdn_of_same_host_is_not_a_mismatch` | Mixed-host evidence detected and excluded; FQDN of the same host is fine |
| `test_s8_mixed_log_reads_as_a_renamed_host_not_another_machine` | A log with this host's records **and** another name (NIST case: the base image's name) is reported as mixed, not foreign; the host's own records still count |
| `test_no_system_hive_means_no_orphan_checks` | Without SYSTEM, nothing is called "wiped" (`orphan_checks_skipped`) |
| `test_mountpoints2_volume_orphan_is_low` / `test_volume_label_only_references_are_ignored` | Volume GUIDs are weak evidence; label-only EMDMgmt entries are ignored |
| `test_findings_sorted_most_severe_first_and_every_finding_explained` | Ordering, and every finding has a `why` |

### `hunt_usb_tamper/test_tamper_artifact_parsing.py` (13): parser inputs and real samples

| Test | Proves |
|---|---|
| `test_to_utc_decodes_hex_filetime_string` | DeviceMigration's hex-string FILETIME decodes (was `None` in v0.1) |
| `test_device_migration_last_present_is_decoded` | The real Win10 Cruzer's USB and USBSTOR `LastPresentDate`s |
| `test_feature_update_history_from_setup_source_os_keys` | All four feature updates from `Setup\Source OS` keys and InstallTime |
| `test_parsed_artifacts_are_recorded` / `test_unlinked_entries_are_normalised` | What was parsed is recorded; every unlinked entry has the same shape |
| `test_1102_security_log_cleared` / `test_104_names_the_cleared_channel` / `test_104_from_another_provider_is_ignored` | Log-clear parsing, including the provider guard |
| `test_partition_log_computer_names_are_recorded` | Per-log computer counts (the host check's input) |
| `test_win7_registry_is_a_clean_negative_control` / `test_win7_plus_foreign_partition_log_reports_mismatch_only` / `test_win10_sample_has_nothing_suspicious` | Real samples: no false alarms |
| `test_cli_tamper_writes_jsonl` | End-to-end through the CLI |

### `hunt_usb_tamper/test_tamper_usboblivion_lab.py` (9): regressions found in the lab

Each reproduces a real lab failure with fictional values.

| Test | Proves |
|---|---|
| `test_a_registry_values_are_read_untrimmed` | A 218-byte USBSTOR path keeps its full serial (regipy trims to 128 bytes by default) |
| `test_b_mbr_signature_and_offset_give_the_volume_guid` (offsets 1 MiB, 64 KiB, 0x7E00, hex input) | `{SIG-0000-0000-OFFSET}` derivation |
| `test_b_dynamic_disk_value_gives_the_volume_guid` / `test_b_device_paths_and_junk_give_no_guid` | `DMIO:ID:` decoding; paths and junk give nothing |
| `test_b_mbr_style_guids_are_recognised` | MBR-style vs Mount Manager GUIDs |
| `test_b_mounted_devices_letters_make_their_volumes_known` | C:/G: style letters make their volumes known |
| `test_b_mountpoints2_only_reports_mount_manager_guids` | MBR GUIDs become `mbr_volume`; a vanished Mount Manager GUID is a `volume_guid` |
| `test_b_tamper_ignores_mbr_derived_volumes` | `mbr_volume` never produces a finding |
| `test_c_log_clear_before_the_last_reference_does_not_raise` | Correlation only counts clears **after** use |

### `hunt_usb_tamper/test_tamper_cleanup_traces.py` (20): traces of the cleanup itself

| Test | Proves |
|---|---|
| `test_mbr_signature_is_read_from_the_mbr` | Disk signature at 0x1B8; zero (GPT) means none |
| `test_mounted_devices_records_mbr_volumes_with_their_letter` / `test_mbr_volume_links_letter_and_mountpoints2_user_to_the_disk` | A UASP/MBR disk gets its letter, volume GUID and MountPoints2 user back |
| `test_partition_log_gives_the_disk_signature` | Real sample: signatures and record statistics (no ID gaps) |
| `test_r3_empty_partition_log_with_recent_usb_arrival_is_a_gap` / `test_r3_log_starting_fresh_after_an_arrival_is_a_gap` / `test_r3_record_id_jump_is_a_gap` | Rule 3 fires |
| `test_r3_rolled_over_log_is_not_a_gap` / `..._arrival_before_the_current_build_...` / `..._log_from_another_machine_is_skipped` / `test_r3_needs_the_partition_log` | Rule 3 stays quiet |
| `test_r5_bam_parser_reads_executions` / `test_r5_profile_list_maps_sids_to_users` | BAM and SID → user parsing |
| `test_r5_usboblivion_execution_is_high` / `test_r5_general_cleaner_is_medium_and_log_clear_after_it_is_noted` / `test_r5_ordinary_programs_are_ignored` | Rule 5 severities and guard |
| `test_r5_cleanup_tool_after_the_reference_raises_the_orphan` / `..._before_the_reference_does_not_raise` | The tool raises an orphan one level only when it ran after use |
| `test_missing_setupapi_next_to_collected_inf_dir_is_noted` / `test_present_setupapi_is_not_missing` | `expected_artifact_missing`, both sides |

### `hunt_usb_tamper/test_tamper_wiped_host_demo.py` (5): the wiped-host demo

`wiped_host_builder.py` writes a fictional PC wiped with USBOblivion as real Windows files: registry hives in the
`regf` format (4 KB hive bins, `lh` subkey lists, a security descriptor, inline small values, device-property types)
and an emptied `.evtx`. Cross-checked once by hand: RECmd's DFIRBatch decodes the hives' USB, BAM, Portable Devices,
MountPoints2 and install-time entries the same way, and EvtxECmd accepts the log's checksum.

| Test | Proves |
|---|---|
| `test_builder_is_deterministic` | The same files byte for byte on every run (so `examples/` can be drift-checked) |
| `test_hives_are_valid_regf_and_read_back_like_windows_hives` | Header checksum and bin layout; regipy returns the same types as for a real Windows 10 hive (DEVPROP string and FILETIME, inline DWORD) |
| `test_wiped_host_raises_every_documented_finding` | Exactly the eight findings `examples/tamper/README.md` shows, in order: two orphans raised to high and a volume raised to medium by the later USBOblivion run, the tool run, the emptied Partition log, the missing setupapi.dev.log, and the two benign twins (feature update, DeviceMigration) |
| `test_wiped_host_reasons_name_the_user_tool_and_timing` | The reasons name m.ortiz, the surviving artifact, the correlated tool run and the device whose 1006 records are gone |
| `test_without_the_system_hive_orphan_checks_are_skipped_not_guessed` | SOFTWARE alone gives `orphan_checks_skipped`, never a guess |

Teeth: moving the USBOblivion run to before the sticks were used fails three tests (no severity raise, and the
committed demo files no longer match).

### `hunt_usb_tamper/test_tamper_triage_layouts.py` (5): KAPE and Velociraptor folders

Found while documenting KAPE and Velociraptor use: KAPE also collects `config\RegBack`, whose 0-byte placeholder
`SYSTEM` replaced the live hive, so the host name and every device finding were lost (only
`orphan_checks_skipped` remained). Four of these tests fail without the fix.

| Test | Proves |
|---|---|
| `test_kape_layout_with_empty_regback_uses_the_live_hives` | A KAPE layout (`<tdest>\C\Windows\...`) with empty RegBack hives gives exactly the findings of the plain folder; both copies are reported as skipped |
| `test_older_copies_never_replace_the_live_hive` | Non-empty RegBack and Windows.old copies lose to `Windows\System32\config`, with the reason |
| `test_a_backup_is_used_when_it_is_the_only_copy` / `test_hand_copied_flat_folder_still_works` | Better than nothing: a lone backup or a hand-copied flat folder is still used |
| `test_velociraptor_layout_with_encoded_names` | `uploads\auto\C%3A\...` and `...Partition%254Diagnostic.evtx` are found; same findings as the plain folder |

### `hunt_usb_tamper/test_tamper_device_classes.py` (7): device classes and setupapi archives

Found on a real Windows 11 PC (test case 3.8): its keyboards and mice are composite USB devices (`usbccgp`) whose
`&MI_` interfaces carry `HidUsb`, so 3 of 4 HID devices were filed as "other"; phones with MTP + ADB have the same
layout. Hives are written with the regf writer, fictional values.

| Test | Proves |
|---|---|
| `test_composite_keyboard_and_mouse_are_hid` / `test_composite_phone_with_mtp_and_adb_is_mtp` / `test_a_webcam_stays_other` | A composite device takes its class from its interfaces (MTP, then USB storage, then HID) |
| `test_interfaces_belong_to_their_own_parent_only` | Interfaces are matched by `ParentIdPrefix`, so two devices with one VID/PID keep their own class |
| `test_plain_storage_and_direct_mtp_are_unchanged` | Non-composite storage and MTP devices are classified as before |
| `test_rotated_setupapi_archives_are_all_read` / `test_archives_without_the_current_log_still_count_as_missing` | Windows 11's `setupapi.dev.<date>.log` archives are read; archives without the current log still raise `expected_artifact_missing` |

### `hunt_usb_tamper/test_tamper_damaged_evidence.py` (10): imperfect collections (1.0.1)

Found on a real KAPE collection of a running PC: a log copied while open had a zeroed chunk (the whole Security.evtx
was dropped), a malformed record crashed a file, a dirty SYSTEM hive made the drive connected just before collection
look wiped, and Windows.old logs carried the PC's setup-time name. Rebuilt from the public samples and the fictional
wiped host, never from the case.

| Test | Proves |
|---|---|
| `test_a_damaged_chunk_costs_only_that_chunk` | The public Partition log with chunk 1 zeroed still gives records 1-14 and 35-40 (20 of 40), and the damage is counted |
| `test_damaged_partition_log_is_read_around_the_damage_and_reported` / `test_undamaged_log_reports_no_damage` | The parser keeps the readable records, records the gap and a warning naming the file; an intact log reports no damage |
| `test_record_id_jump_in_a_damaged_log_is_low_not_deletion` | `partition_log_gap` drops to low and says the jump may be damage when the file was damaged |
| `test_malformed_records_are_skipped_not_fatal` | `"System": null` and `"Event": null` records are skipped or read with an empty System, never fatal |
| `test_public_dirty_hive_is_flagged` / `test_public_clean_hive_is_not_flagged` | `SYSTEM_WIN_10_1709` (sequence numbers 4317/4316) is flagged dirty with the `rla.exe` advice; the clean `SYSTEM` is not |
| `test_orphans_on_a_dirty_system_hive_carry_a_caution` | On the wiped host with a dirty SYSTEM hive every `orphaned_device_reference` says to replay the logs first (`system_hive_dirty` in the evidence); the clean build says nothing |
| `test_windows_old_logs_are_labelled_and_explain_setup_time_names` / `test_no_windows_old_note_without_windows_old` | Logs under `Windows.old` are labelled as the previous installation and `evidence_host_mismatch` explains setup-time names; no note without Windows.old |

### `hunt_detection_rules/test_detection_rule_schema.py` (20): rule sources and shared definitions

| Test | Proves |
|---|---|
| `test_every_shipped_rule_is_valid` / `test_rule_ids_and_hypotheses_are_unique` / `test_file_name_starts_with_the_hypothesis` | The 8 YAML rules are valid, uniquely identified, consistently named |
| `test_cleanup_tool_lists_come_from_the_tamper_module` / `test_a_new_cleanup_tool_reaches_the_live_rules` | H6's tool list **is** `tamper.CLEANUP_TOOLS`: adding a tool there changes the live rule |
| `test_thresholds_and_extensions_come_from_scoring_config` | H3/H4 use the scoring config's numbers and extensions |
| `test_placeholders_expand_inside_lists_and_scalars` / `test_unknown_placeholder_is_an_error` | `${...}` substitution, and typos fail loudly |
| `test_valid_example_passes` / `test_validator_reports_each_mistake` (×11) / `test_event_log_detection_needs_a_channel` | The validator catches bad level, id, hypothesis, technique, telemetry, undefined selection, unknown field or modifier, missing positive or negative test, and a false-positive or response item that YAML turned into a dict (found in H3/H4: an unquoted `...on C: shortly before` showed as a Python dict in the Elastic triage note) |

### `hunt_detection_rules/test_detection_rule_logic.py` (39): what the rules match

| Test | Proves |
|---|---|
| `test_rule_passes_its_own_test_events` (×8) | Every rule's embedded events give the expected answer |
| `test_values_compare_case_insensitively`, `test_modifiers` (×6), `test_list_means_any_of`, `test_fields_in_one_selection_must_all_match`, `test_missing_field_never_matches`, `test_numbers_and_strings_compare_equal`, `test_condition_and_or_not_parentheses`, `test_contains_all_needs_every_value`, `test_event_log_detection_checks_the_channel` | Evaluator semantics: the reference every generator must follow |
| `test_h3_threshold_both_sides` / `..._counts_per_user` / `..._follows_the_scoring_config` | 50 fires, 49 does not; 30 + 30 by two users does not; the config's number is used |
| `test_h1_first_seen_uses_the_newest_event_as_now`, `test_h2_uses_the_configured_time_zone` | First seen and off-hours behave like the scheduled queries; a New York config moves 15:00 into work hours |
| H4, H6, H7, H8 spot checks (×12) | Extensions from config, tool tiers, 1102/104 provider guard, clearing commands both ways, Windows uninstall excluded but `reg.exe` not |

### `hunt_detection_rules/test_detection_generators.py` (38): Sigma, Elastic, Sentinel output

| Test | Proves |
|---|---|
| `test_every_detection_is_built_or_explained_for_every_target` (×3), `test_build_is_deterministic` (×3) | Nothing is silently dropped; rebuilds are byte-identical (stable IDs) |
| `test_queries_have_balanced_parentheses_and_quotes` (×2), `test_generated_files_say_where_they_come_from` (×4) | Well-formed queries; every file points back to its YAML source |
| `test_sigma_file_names_follow_sigmahq_prefixes`, `..._ids_are_uuid_v4_and_stable`, `..._references_have_no_mitre_links`, `test_sigma_structure_and_unique_ids` | SigmaHQ conventions |
| `test_sigma_h1/h3/h4/h6/h7/h8_*`, `test_sigma_says_what_it_cannot_express` (×2) | 6416 log source, correlation rule, removable regex, `Image` mapping, SigmaHQ-aligned H7, registry_delete; `.unsupported.txt` for first-seen and work hours |
| `test_elastic_*` (×7) | ECS fields, `LIKE` / `\|all`, `STATS … BUCKET`, first seen, off-hours offset, Kibana import (disabled, ATT&CK v18 threat map), IDs shared with Sigma |
| `test_sentinel_*` (×6) | Tables per telemetry, `UsbDriveMounted` join, `summarize … bin`, `datetime_utc_to_local`, registry deletes |

### `hunt_detection_rules/test_detection_pysigma.py` (4): checked by pySigma

| Test | Proves |
|---|---|
| `test_pysigma_parses_every_rule` / `test_pysigma_resolves_the_correlation` | The reference Sigma implementation loads all 11 documents and links H3's correlation to its base rule |
| `test_builtin_validators_pass` / `test_sigmahq_repository_validators_pass` | 31 pySigma + 52 SigmaHQ validators: zero issues (skips without `pip install -e .[sigma]`) |

### `hunt_detection_rules/test_detection_replay.py` (21): real event logs through the rules

| Test | Proves |
|---|---|
| Sysmon 1 / 11 / 12, Security 4688 / 6416, 1102 / 104 normalisation (×7), `test_unknown_channels_are_ignored` | Each record becomes the right neutral event; `--removable-drives` overrides the D:–Z: heuristic |
| `test_replay_fires_the_right_rules` / `test_replay_quiet_baseline_has_no_alerts` | A cleanup timeline fires H3, H4, H6, H7 and not H8; ordinary activity fires nothing |
| `test_replay_first_seen_reports_the_history_it_had` / `test_alerts_are_sorted_and_explained` | First seen alerts once and states its history; alerts are ordered and explained |
| `test_one_unreadable_log_never_stops_the_replay` / `test_cli_reports_unreadable_logs_and_keeps_going` / `test_cli_fails_clearly_when_no_log_is_readable` | Found pointing `--evtx` at a live log folder without admin rights: the first unreadable file ended the run with a traceback. Now each one is listed and skipped; if none can be read the error says to run elevated or export with `wevtutil epl` (3 tests fail without the fix) |
| `test_coverage_names_the_hypotheses_that_could_not_fire` / `test_coverage_is_silent_when_every_kind_of_telemetry_is_present` / `test_cli_prints_the_telemetry_gaps` | Found on a real PC (test case 3.7): 75,334 events, all plain log records, zero alerts. The replay now names the hypotheses that could not fire and the telemetry each needs |
| `test_cli_says_which_alerts_to_look_at_first` | The owner's question on the Sysmon run: the replay ends with the alerts by level (high first) with their first time, under a `Hypothesis` column (was `Hyp`) |
| `test_events_jsonl_feeds_the_same_replay` / `test_events_jsonl_rejects_unknown_telemetry` | `--events` JSONL replays like `.evtx`; an unknown `_telemetry` is an error with the known list |

### `hunt_detection_rules/test_detection_replay_hardening.py` (13): replaying a real collection (1.0.1, 1.0.2)

| Test | Proves |
|---|---|
| `test_one_plug_in_logged_twice_is_one_row_preferring_the_disk` / `test_different_sticks_or_times_are_never_merged` | Windows logs one plug-in twice (USB device node and USBSTOR disk); the table pairs them, keeping the disk row, and never pairs different serials or times |
| `test_slow_disk_logged_seconds_after_its_usb_node_is_still_one_row` / `test_pairing_window_is_bounded_and_never_holds_two_disks` | 1.0.2, real-case: an external hard disk logged 5 s after its USB node is one row; 31 s apart, or two disks 10 s apart (a re-plug), stay two rows |
| `test_table_says_the_row_stands_for_two_log_entries` | The paired row says so (lab-found: rich read the `[...]` note as markup and dropped it), and `alerts.jsonl` keeps all four alerts |
| `test_damaged_log_is_listed_and_still_replayed` / `test_not_an_evtx_is_an_error_not_a_crash` | A damaged log is read around the damage and listed as damaged; a file that is not a log is listed as unreadable |
| `test_tz_flag_sets_the_h2_zone` / `test_host_hive_next_to_the_logs_sets_the_h2_zone` / `test_no_zone_anywhere_warns_that_h2_is_utc` | H2 off hours use `--tz`, else the SYSTEM hive found next to the logs (the wiped host: America/New_York), else UTC with a warning |
| `test_disk_image_given_to_triage_prints_mount_steps` / `test_e01_and_evtx_paths_get_their_own_hints` / `test_other_file_given_to_triage_asks_for_the_folder` | A `.vhdx` / `.E01` given to `--triage` or `--evtx` prints how to mount it; any other file asks for the folder |

### `hunt_usb_tamper/test_tamper_volume_id_time.py` (5): dating orphaned volumes (1.0.2)

Real case: one orphaned `MountPoints2` volume GUID decoded to a stick's reformat time, and five others to the same
millisecond while no plug-in started. Built from GUIDs made for the test with a made-up MAC.

| Test | Proves |
|---|---|
| `test_v1_guid_time_is_decoded` / `test_other_guid_versions_have_no_time` | A version-1 GUID gives its creation time (with or without braces); other versions and junk give none |
| `test_orphaned_volume_says_when_it_was_created` | The finding prints the creation time as "at or shortly after" (a real host's stamp ran 89 s early) and stores `volume_created`; severity stays low |
| `test_burst_of_volumes_created_in_one_second_is_called_out` | Five orphans made in one second each say "4 other ... in the same second" with the possible causes; a sixth made hours later does not |
| `test_non_time_based_volume_guid_keeps_the_old_text` | A non-time-based GUID gets no date |

### `hunt_detection_rules/test_detection_sample_timeline.py` (2): the documented use cases

| Test | Proves |
|---|---|
| `test_every_hypothesis_fires_in_the_documented_order` | The insider timeline in `docs/hunt-detection-rules.md` (plug in, copy, archive, format, USBOblivion, registry wipe, log clear) fires H1-H8 in exactly the documented order |
| `test_documented_details` | The sample alerts' details (60 files in the bucket, the archive name, H6 level, the USBSTOR path) stay true |

### `hunt_fleet_device_graph/test_fleet_identity.py` (17): same stick on two hosts?

| Test | Proves |
|---|---|
| `test_weak_serials_are_recognised` (×8) | Fake / shared serials (sequences, repeats, too short, mostly zeros) are recognised; real ones are not |
| `test_real_serial_links_hosts_with_high_confidence` | A real serial links hosts even after a reformat changed the VSN |
| `test_windows_generated_serials_join_on_volume_serial` / `..._on_name_and_capacity_with_low_confidence` / `..._alone_never_join` | Host-local serials link only through volume evidence, with the right confidence |
| `test_fake_serial_is_not_trusted_without_volume_evidence` / `test_fake_serial_with_shared_volume_serial_does_join` | Weak serials need a shared VSN |
| `test_two_real_serials_are_never_merged_by_a_shared_volume_serial` | Cloned images do not merge different sticks |
| `test_only_storage_devices_by_default` / `test_device_known_only_from_a_partition_log_still_counts` | Virtual hubs stay out; module #3 orphans (no Enum class) stay in |

### `hunt_fleet_device_graph/test_fleet_hunts.py` (18): G1-G6 on both sides

| Test | Proves |
|---|---|
| `test_g1_*` (×2) | 3 hosts fires, 2 does not; `--min-hosts` is honoured |
| `test_g2_*` (×3) | Two accounts fire; `NW\j.doe`, `J.DOE` and `j.doe (MountPoints2)` are one user (lab-found); machine accounts ignored |
| `test_g3_*` (×3) | A high-risk session plus another host fires; one host, or no high-risk session, does not |
| `test_g4_*` (×4) | Wiped on A and recorded on B fires; the wiping host itself is never "history"; nowhere else, no finding |
| `test_g5_*` (×3) | New within the window fires; too little fleet history or more than one host does not |
| `test_g6_*` (×2) | Same serial on different VID/PIDs; a weak serial on unrelated sticks (which also stops G1) |
| `test_findings_are_explained_and_sorted` | Every finding has a why and a confidence; high first |

### `hunt_fleet_device_graph/test_fleet_io.py` (16) and `test_fleet_sample_fleet.py` (3)

| Test | Proves |
|---|---|
| `test_find_runs_*`, `test_fleet_summary`, `test_host_without_sessions_file_still_loads` | Folders, parent folders and wildcards; counts; missing files warn instead of failing |
| `test_device_pivot_*`, `test_user_pivot` | Pivots by serial fragment, VSN or user, in time order |
| `test_graph_json_*`, `test_graphml_*`, `test_cypher_*` | Export structure, valid GraphML, Cypher `MERGE` with quote and backslash escaping |
| `test_cli_*` (×6) | End to end: files written, pivots printed (also in the documented form `--runs out device X`, which `--runs` used to swallow), a folder named `device` is still a run, clear errors for a missing or empty `--runs` |
| `test_two_sticks_sharing_a_weak_serial_stay_two_nodes_in_every_export` | Found in release test case 4.5: the two sticks `serial_collision` keeps apart shared one ID, so graph.json, GraphML and Cypher merged them into one node tied to both hosts. IDs now carry the host when keys collide |
| `test_device_pivot_names_the_host_where_the_stick_was_wiped` | Found in test case 4.4: a wiped host has no records left, so the pivot never mentioned the wipe; it now prints `Also wiped from the registry on ...` |
| `test_fleet_sample_fleet.py` | The fleet in `docs/hunt-fleet-device-graph.md` fires all six hunts with the documented details |

### `examples_demo/test_examples_demo.py` (52): the demo kit

| Test | Proves |
|---|---|
| `test_committed_examples_match_the_generator` | `examples/` is exactly what `scripts/make_examples.py` writes (no drift), byte for byte for the wiped host's hives and log |
| `test_every_generated_example_file_is_tracked_by_git` | Found before the first push: `.gitignore` keeps real `*.evtx` / `*.DAT` evidence out, which also hid the demo host's NTUSER.DAT and evtx; every generated example file must be committable |
| `test_examples_are_fictional_only` | Only the documented fictional hosts and users; no SIDs, no IP addresses |
| `test_demo_graph_*` (×3) | All six fleet hunts and the exports; the device pivot's rows, order, score and volumes; the user pivot |
| `test_demo_detections_*` (×2) | The insider timeline fires H1-H8 with the documented counts; `test` and `build` succeed |
| `test_demo_sessions_devices_tamper_on_public_samples` | Modules #2 and #3 demos on the public samples (skips without them) |
| `test_demo_sessions_readme_claims` | What `examples/sessions` and `examples/tamper` say: the Patriot stick tops the list at 45 with its three reasons, four sessions are medium, the allowlist drops its sessions to 0 info, tamper reports exactly one info finding |
| `test_every_tool_has_a_demo_folder` (×4) | `examples/sessions`, `tamper`, `detections` and `graph` each exist, are linked from the index and demo every subcommand |
| `test_every_readme_demo_runs` (×38) | Every `usbhawk` command in the powershell blocks of `examples/**/README.md`, plus the demos on the front page, in GETTING-STARTED and in USE-CASES, runs from a scratch folder (those on `tests\data` skip without the samples) |

The release build (`scripts/build_release.ps1`) adds `scripts/smoke_test.py`: the same demos, plus error cases, run against the built `usbhawk.exe` from the release zip and against the wheel in a fresh virtual environment.

## Proving the tests have teeth

These checks were run by hand (break the code on purpose, run the tests, restore):

| Broken on purpose | Tests that went red |
|---|---|
| Original v0.1 `scoring.py` with no `tzdata` installed (silent UTC fallback) | 10 of 14 in `test_utc_timestamps.py` |
| `long_session` / `mass_delete_on_device` threshold `>=` changed to `>` | `test_long_session` / `test_mass_delete_on_device` |
| Tamper: feature updates ignored; 24 h window shrunk to 1 h; foreign-host exclusion removed; 104 provider check removed | One scenario test each |
| Lab fixes A, B, C absent (the code before the lab) | 7 of 9 in `test_tamper_usboblivion_lab.py` (the other 2 are guards) |
| Rule 3: rolled-over logs treated as fresh; install time ignored; foreign-log guard removed; ID jumps ignored | One test each |
| Rule 5: tool run before use still raises; tool never raises; BAM keeps non-path values | One test each |
| MBR linking leaves the entry unlinked | `test_mbr_volume_links_letter_and_mountpoints2_user_to_the_disk` |
| Detections: evaluator case-sensitive; tool lists not read from tamper; Sigma startswith on full path; ES\|QL / KQL case-sensitive; H7 provider check removed | 6–8, 8, 1, 1, 1, 5 tests |
| Detections: threshold off by one; first seen ignores the window; 18:00 counted as work hours; removable flag or registry action ignored | 3, 2, 1, 2, 1 tests |
| Detections: KQL drops the USB-drive join; weekday numbering wrong in KQL or ES\|QL; Sigma correlation `gt`; MITRE links kept | 1 test each (2 for the links) |
| Replay: every drive removable; every registry event a delete; first seen on every sighting; 4688 ignored; H8 Explorer exclusion removed | 1, 1, 1, 1, 4 tests |
| Graph: weak-serial check off; cloned VSN merges real serials; generated serials trusted; storage filter off | 2, 1, 4, 1 tests |
| Graph: G1 off by one; user spelling not normalised; G3 without a second host; G4 counts the wiping host; G5 history guard removed | 4, 5, 1, 2, 1 tests |
| Graph: Cypher escaping removed; GraphML escaping removed | 1, 1 tests |
| Graph: pivot words after `--runs` not split off (the bug found while writing the demo kit) | 5 tests |

## Lab tests (layer 3)

Use a **throwaway Windows VM** with a snapshot, never your main machine or a work endpoint. Collect each stage
with `collect_local.ps1` (elevated), copy the folder to the analysis machine **outside the repo and outside cloud
sync** (e.g. `C:\lab`), and cross-check with RECmd (`DFIRBatch.reb`) and EvtxECmd.

> RECmd recovers **deleted** keys and values by default. In its batch CSV they carry `Deleted=True`; its plugin
> CSVs (USB, USBSTOR, MountedDevices...) do not flag them. Compare a wiped hive against live keys only.

### Module #2: sessions

| Step | Do | Expect from `usbhawk sessions` |
|---|---|---|
| 1. Snapshot | Take a VM snapshot | n/a |
| 2. Baseline | Connect a USB stick to the VM, copy a few files, eject | One session; `first_seen_device`; correct letter and volume name |
| 3. After hours | Repeat outside 08:00–18:00 local (or set `--tz` to a zone where it is night) | `off_hours` with the right local time |
| 4. Reformat | Format the stick (Explorer → Format), reconnect | `reformat_or_repartition` |
| 5. Collect, run, reset | Collect, `usbhawk sessions --triage <folder> --out out`, revert the snapshot | The sessions above, with reasons |

### Module #3: tamper (run 2026-11-16, results in `docs/hunt-usb-tamper.md`)

| Step | Do | Expect from `usbhawk tamper` |
|---|---|---|
| 1. Snapshot | Take a VM snapshot | n/a |
| 2. Baseline | Connect a USB disk (VMware: VM → Removable Devices → Connect), copy a file, eject, collect | No orphans; any old `log_cleared` from the VM's history |
| 3. Wipe | Run USBOblivion (download it yourself, *Do real clean* ticked), collect | `cleanup_tool_execution` high, `log_cleared`, orphans for the wiped devices, `partition_log_gap`, `expected_artifact_missing` |
| 4. Variation | Detach the disk from the VM entirely, run it again, collect | Same picture; shows whether the tool handles that device type (USBOblivion 1.17.0 leaves UASP disks) |
| 5. Reset | Revert the snapshot | Clean VM for the next test |

### Module #4: detections (run 2026-11-17, results in `docs/hunt-detection-rules.md`)

| Step | Do | Expect from `usbhawk detections run --evtx <folder> --removable-drives <USB letter>` |
|---|---|---|
| 1. Snapshot + telemetry | Snapshot; install Sysmon with `scripts/lab/sysmon-usbhawk-lab.xml`; `auditpol /set /subcategory:"Plug and Play Events" /success:enable` | n/a |
| 2. Activity | Connect a USB disk; write 60 files and a zip to it; `format.com /?`; `wevtutil cl Application`; collect (the script exports Sysmon too) | H1 (+ first seen), H3, H4, H5, H7 command + 104; no H6, no H8 |
| 3. Cleanup | Run USBOblivion (real clean); collect | adds H6, H7 (1102, 104 and the tool's own `wevtutil cl` children), H8; H1 gone with the Security log |
| 4. Cross-check | EvtxECmd `--inc 1,11,12,1102,104,6416` on the same logs | Counts equal (clear commands, registry deletes, tool starts, files on the USB drive) |
| 5. Reset | Remove the test files from the disk; revert the snapshot | Clean VM |

### Module #1: fleet graph (run 2026-11-17, results in `docs/hunt-fleet-device-graph.md`)

| Step | Do | Expect from `usbhawk graph` |
|---|---|---|
| 1. Two hosts, one disk | Use the same USB disk on two machines (e.g. the analysis PC and a lab VM) | n/a |
| 2. Collect | `collect_local.ps1` on each (read-only; keep the folders outside the repo) | n/a |
| 3. Per host | `usbhawk sessions --triage <folder> --out C:\lab\fleet\<host>` | n/a |
| 4. Fleet | `usbhawk graph --runs C:\lab\fleet --min-hosts 2`, then `... device <serial>` | The disk linked by serial (high), `device_on_many_hosts`, a two-host pivot; no other cross-host links |

## Release test cases (1.0.0)

Run by hand against the released `usbhawk.exe`, unzipped from `dist\`, in CMD (2026-11-18). Cases on fictional
demo data are also automated; the rest use real data that stays outside the repository.

| Case | Command | Result |
|---|---|---|
| 3.1 | `detections list` | 8 hypotheses, 12 detections, ATT&CK v18 IDs, offline hunt per rule |
| 3.2 | `detections test` | `8 rules, 12 detections, 54 test events: all passed` (59 after the real-PC H3/H4 fix) |
| 3.3 | `detections run --events examples\detections\insider_timeline.jsonl --out ...` | H1 2, H2 1, H3 1, H4 1, H5 1, H6 1, H7 2, H8 1; 10 alerts in `alerts.jsonl` |
| 3.4 | `detections run --evtx <EVTX-ATTACK-SAMPLES>` | 113 events; H7 twice (System 104 medium, Security 1102 high), as EvtxECmd counts |
| 3.5 | `detections build --out ...` | 37 files (sigma, elastic, sentinel) |
| 3.6 | `detections run --evtx C:\Windows\System32\winevt\Logs`, not elevated | All 469 files refused; clear error with the elevation / `wevtutil epl` hint, exit 2 (was a traceback before this release) |
| 3.7 | the same, **elevated** (owner's PC) | All 469 live logs read, none skipped (75,334 events); zero alerts, correctly: the PC had no Sysmon and no PnP or process auditing. **Found:** nothing said so; the replay now prints the telemetry gaps |
| 3.7b | the same after installing Sysmon (lab config) and PnP auditing, then using the owner's Seagate | 106,340 events: device_connect 4, file_event 30,335, process_creation 433, registry_event 310. H1 x2, H3 x1, H4 x4: exactly the activity done, no telemetry gaps for them. **Found:** H3's first examples were Recycle Bin `$I` metadata files Windows writes when files on the stick are deleted; H3 and H4 now skip those and System Volume Information (files copied *into* the Recycle Bin folder, a hiding place, still count) |
| 3.8b | `collect_local.ps1`, then `detections run` on its output, with Sysmon | 4 log files (Sysmon exported too), the same alerts as the live replay |
| 3.8 | `collect_local.ps1` (elevated), then `detections run` and `sessions` on its output (owner's PC) | Collection and both commands work. **Found:** 1,655 sessions, 1,624 of them an empty card-reader slot's "no media" removals (now 29 sessions); 3 of 4 HID devices classed "other" (composite devices); a Windows-made instance ID shown as the iSerialNumber; only the current `setupapi.dev.log` collected although 8 rotated archives existed. All fixed, with tests |
| 4.1 | `graph --runs examples\graph\fleet` | 4 hosts, 6 devices, all six hunts |
| 4.2 / 4.3 | `graph ... device 60A44C41` / `device 8E2C41D7` | The Kingston on 3 hosts by serial and by volume serial |
| 4.4 | `graph ... user a.smith` | Both sticks; **found:** the SanDisk's wipe on NW-OPS-WS019 was not mentioned (fixed) |
| 4.5 | `graph ... --out ...` | Valid GraphML, JSON without dangling edges, ECS findings, well-formed Cypher; **found:** 6 devices but 5 device nodes, the two colliding weak-serial sticks merged (fixed) |
| 4.6 | `graph --runs <lab fleet: host PC + VM>` | 2 hosts; the Seagate UASP disk linked by serial (`device_shared_by_users`) |
| 4.7 | `sessions` + `tamper` on the public samples, the wiped host and the NIST case, then `graph` | 3 hosts, 7 devices, no stick in common: `No fleet findings.` (correct) |

## Real-data validation (public datasets)

Public evidence anyone can reproduce with `python scripts\fetch_demo_datasets.py <name>` (hash-checked, kept outside
the repository, never committed). Run 2026-11-17 with USBHawk 1.0.0, the source build and the release exe giving the
same results.

### NIST CFReDS Data Leakage case (Windows 7 Ultimate SP1, `nist-leakage`)

A scripted insider case with a written answer key. The triage folder holds SYSTEM, SOFTWARE, four NTUSER.DAT files,
54 event logs and `setupapi.dev.log` (Windows 7 has no Partition/Diagnostic log).

| Answer key (times EDT) | USBHawk | Result |
|---|---|---|
| RM#1 SanDisk Cruzer Fit, serial `4C530012450531101593`, first connected 2015-03-23 14:31 | `sessions`: 2015-03-23 18:31:09 UTC (= 14:31 EDT), VID_0781&PID_5571, from Enum, USBSTOR, setupapi and System 20001/20003 | match |
| RM#2 SanDisk Cruzer Fit, serial `4C530012550531106501`, first connected 2015-03-24 09:58 | 2015-03-24 13:58:31 UTC (= 09:58 EDT) | match |
| user `informant` | `informant-PC\informant` on both sessions | match |
| RM#1 reconnected 03-24 09:38; RM#2 reconnected 03-24 15:38 | not reported: Windows 7 keeps no `0066` last-arrival property. The times survive as key last-write times (13:38:00 and 19:38:09 UTC) | gap, see `ideas/win7-last-connection.md` |
| RM#1 label "Authorized USB"; RM#2 label "IAMAN $_@", quick-formatted 03-24 ~17:00 | not linked: the EMDMgmt entries have no device path (RM#2's label appears with two VSNs, the second at 21:02 UTC: the format) | gap, see `ideas/emdmgmt-volume-labels.md` |
| drive letter E: | not linked: MountedDevices holds MBR signature + offset values, which USBHawk links only through the Partition log | gap, see `ideas/mbr-volumes-without-partition-log.md` |
| Eraser and CCleaner run (anti-forensics) | not reported: Windows 7 has no BAM; the proof is in Prefetch / UserAssist / Shimcache | gap, see `ideas/execution-evidence.md` |

- **Tamper** (`usbhawk tamper`): no orphans, no log clears, which is correct: the sticks were never wiped from the
  registry and no log was cleared. It reported `evidence_host_mismatch` because 13 Security and 348 System records
  carry the computer name `37L4247F27-25` (the base image's name, 2010, and a burst on 2015-03-25 10:15-10:18) next
  to the host's own records. The first run worded this as "comes from another machine", which is wrong for a mixed
  log; fixed and covered by `test_s8_mixed_log_reads_as_a_renamed_host_not_another_machine`.
- **Detections** (`usbhawk detections run --evtx`): 2,833 events, 0 alerts, which is correct: Windows 7's default
  audit policy records none of the rules' telemetry (no Sysmon, no 4688, no 6416) and no log was cleared.
- **Graph**: one host, so no fleet findings; the device pivot by serial works.

### EVTX-ATTACK-SAMPLES (`evtx-attack`)

`DE_1102_security_log_cleared.evtx` and `DE_104_system_log_cleared.evtx` by Samir Bousseaden: 113 events, and H7 fired
exactly twice (System 104 at 2019-03-19 23:34:25 UTC and Security 1102 at 23:35:07 UTC, by `EXAMPLE\user01`), with
no other alerts. EvtxECmd counts the same records (104 ×1, 1102 ×1).
