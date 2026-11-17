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
  data/                               public samples, downloaded, gitignored, never committed
```

## Running the tests

```powershell
.\.venv\Scripts\Activate.ps1
python scripts\fetch_test_samples.py              # once: downloads public samples into tests\data (gitignored)
pip install -e ".[dev,sigma]"                     # once: pytest + pySigma and the SigmaHQ validators
pytest -q                                         # all tests; expect "326 passed"
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

## Test inventory (326 tests)

| Folder | Tests |
|---|---|
| `foundations/` | 61 |
| `hunt_exfil_sessions/` (module #2) | 38 |
| `hunt_usb_tamper/` (module #3) | 63 |
| `hunt_detection_rules/` (module #4) | 115 (4 skip without the `[sigma]` extra) |
| `hunt_fleet_device_graph/` (module #1) | 49 |

Module #4 rules also carry their own **54 test events** (run by `usbhawk detections test` and by
`test_rule_passes_its_own_test_events`): every detection has events that must match and events that must not.

### `foundations/test_cli_help_and_banner.py` (17): the command line people see

| Test | Proves |
|---|---|
| `test_banner_text`, `test_version` | Banner art, tagline and version; `usbhawk --version` |
| `test_top_level_help_shows_banner_hunts_and_examples` / `test_no_command_prints_help_instead_of_an_error` | `usbhawk --help` and a bare `usbhawk` show the banner, every command and examples |
| `test_every_command_help_has_examples` (×7) | Every command and the `detections build/run` actions have examples; each hunt links its guide |
| `test_banner_on_an_interactive_terminal` / `test_no_banner_when_output_is_not_a_terminal` / `test_no_banner_with_quiet_or_env` | The banner goes to stderr on a terminal only; never when piped, with `-q` or `USBHAWK_NO_BANNER=1` |
| `test_json_on_stdout_stays_clean_with_a_banner` | With the banner on, every stdout line of `usbhawk devices` is still pure JSON |
| `test_usbthk_alias_is_installed_alongside_usbhawk` / `test_output_datasets_use_the_new_name` | The former command still works; output datasets and fields are `usbhawk.*` |

### `foundations/test_artifact_decoding.py` (5): low-level decoding

| Test | Proves |
|---|---|
| `test_filetime_bytes_and_int` | Windows FILETIME decodes from bytes and integers; `0` means "no time" |
| `test_vsn_offsets_all_filesystems` | The volume serial is read at the right boot-sector offset for exFAT, NTFS, FAT32, FAT16 |
| `test_mbr_partition_entry` | MBR partition entries (from 1006 events) decode correctly |
| `test_identifier_parsing` | VID/PID/serial and USBSTOR paths parse (`\` and `#` styles); the `&0` LUN suffix is stripped; composite children (`&MI_00`) are not devices; Windows-generated serials are recognised |
| `test_mounted_devices_hex_string_decode` | MountedDevices values decode whether regipy returns bytes or a hex string; MBR disk signatures are not mistaken for paths |

### `foundations/test_setupapi_log.py` (1): first-install times

| Test | Proves |
|---|---|
| `test_setupapi_local_time_to_utc` | `setupapi.dev.log` local time → UTC (EDT, UTC−4); non-USB installs ignored |

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

### `foundations/test_host_work_hours_tz.py` (21): time zone auto-detected from the host

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

### `hunt_exfil_sessions/test_exfil_session_building.py` (5): the end-to-end insider scenario

| Test | Proves |
|---|---|
| `test_one_session_with_dedupe_and_duration` | Three artifacts recording one plug-in → **one** session; duration 26 m 15 s; `first_seen`; user attached |
| `test_full_scoring_with_edr_file_events` | MDE CSV import; 7 rules fire; the `C:\` file is excluded; score 100 / high |
| `test_allowlist_pulls_score_down` | An approved serial subtracts 50 |
| `test_4663_volume_inference` | Security 4663 without a serial: the USB volume is inferred, the busy system volume is not |
| `test_orphan_and_missing_disconnect` | A connect with no removal for > 24 h closes; the next connect starts a new session |

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

### `hunt_usb_tamper/test_tamper_scenarios.py` (21): scenarios S1–S8 on synthetic evidence

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

### `hunt_detection_rules/test_detection_rule_schema.py` (20): rule sources and shared definitions

| Test | Proves |
|---|---|
| `test_every_shipped_rule_is_valid` / `test_rule_ids_and_hypotheses_are_unique` / `test_file_name_starts_with_the_hypothesis` | The 8 YAML rules are valid, uniquely identified, consistently named |
| `test_cleanup_tool_lists_come_from_the_tamper_module` / `test_a_new_cleanup_tool_reaches_the_live_rules` | H6's tool list **is** `tamper.CLEANUP_TOOLS`: adding a tool there changes the live rule |
| `test_thresholds_and_extensions_come_from_scoring_config` | H3/H4 use the scoring config's numbers and extensions |
| `test_placeholders_expand_inside_lists_and_scalars` / `test_unknown_placeholder_is_an_error` | `${...}` substitution, and typos fail loudly |
| `test_valid_example_passes` / `test_validator_reports_each_mistake` (×10) / `test_event_log_detection_needs_a_channel` | The validator catches bad level, id, hypothesis, technique, telemetry, undefined selection, unknown field or modifier, missing positive or negative test |

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

### `hunt_detection_rules/test_detection_replay.py` (12): real event logs through the rules

| Test | Proves |
|---|---|
| Sysmon 1 / 11 / 12, Security 4688 / 6416, 1102 / 104 normalisation (×7), `test_unknown_channels_are_ignored` | Each record becomes the right neutral event; `--removable-drives` overrides the D:–Z: heuristic |
| `test_replay_fires_the_right_rules` / `test_replay_quiet_baseline_has_no_alerts` | A cleanup timeline fires H3, H4, H6, H7 and not H8; ordinary activity fires nothing |
| `test_replay_first_seen_reports_the_history_it_had` / `test_alerts_are_sorted_and_explained` | First seen alerts once and states its history; alerts are ordered and explained |

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

### `hunt_fleet_device_graph/test_fleet_io.py` (11) and `test_fleet_sample_fleet.py` (3)

| Test | Proves |
|---|---|
| `test_find_runs_*`, `test_fleet_summary`, `test_host_without_sessions_file_still_loads` | Folders, parent folders and wildcards; counts; missing files warn instead of failing |
| `test_device_pivot_*`, `test_user_pivot` | Pivots by serial fragment, VSN or user, in time order |
| `test_graph_json_*`, `test_graphml_*`, `test_cypher_*` | Export structure, valid GraphML, Cypher `MERGE` with quote and backslash escaping |
| `test_cli_*` (×3) | End to end: files written, pivots printed, clear error without input |
| `test_fleet_sample_fleet.py` | The fleet in `docs/hunt-fleet-device-graph.md` fires all six hunts with the documented details |

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
