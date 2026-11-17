"""Module #3 inputs: the parser fixes and additions tamper detection depends on, plus real-sample runs."""

from datetime import datetime, timezone

from usbthk.cli import main
from usbthk.model import LOG_CLEARED, Evidence
from usbthk.parsers.evtx_logs import log_cleared_event, parse_partition_diagnostic
from usbthk.parsers.registry import parse_ntuser, parse_software, parse_system
from usbthk.tamper import find_tamper
from usbthk.util import to_utc

from conftest import DATA, sample, utc


def utc_us(*args):
    return datetime(*args, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- timestamps
def test_to_utc_decodes_hex_filetime_string():
    # regipy returns some REG_BINARY FILETIMEs (DeviceMigration LastPresentDate) as hex strings.
    assert to_utc("f470d2aa67fcd501") == utc_us(2020, 3, 17, 14, 23, 45, 504690)
    assert to_utc("2026-10-30T21:14:52Z") == utc(2026, 10, 30, 21, 14, 52)    # ISO still works
    assert to_utc("deadbeef") is None                                       # too short to be a FILETIME


# --------------------------------------------------------------------------- SYSTEM: Win10 1709 sample
def test_device_migration_last_present_is_decoded():
    ev = Evidence()
    parse_system(sample("SYSTEM_WIN_10_1709"), ev)
    # The Cruzer is archived twice: as its USB parent and as its USBSTOR disk, seconds apart.
    cruzer = {m["id"].split("\\")[0]: m["last_present"] for m in ev.migrated
              if "200608767007B7C08A6A" in m["id"].upper()}
    assert cruzer == {"USB": utc_us(2020, 3, 17, 14, 23, 50, 324556),
                      "USBSTOR": utc_us(2020, 3, 17, 14, 23, 45, 504690)}


def test_feature_update_history_from_setup_source_os_keys():
    ev = Evidence()
    parse_system(sample("SYSTEM_WIN_10_1709"), ev)
    times = {f["ts"] for f in ev.host.feature_updates}
    assert utc_us(2017, 7, 12, 7, 18, 28, 931242) in times     # build 15063 installed (InstallTime)
    assert utc_us(2019, 1, 27, 10, 39, 32, 898056) in times    # build 17134 installed (InstallTime)
    assert utc(2019, 1, 6, 2, 18, 37) in times                 # "Updated on" in the key name
    assert utc(2019, 5, 16, 0, 55, 20) in times
    assert all(f["source"] for f in ev.host.feature_updates)


def test_parsed_artifacts_are_recorded():
    ev = Evidence()
    parse_system(sample("SYSTEM"), ev)
    parse_software(sample("SOFTWARE"), ev)
    assert {"SYSTEM", "SOFTWARE"} <= ev.parsed


# --------------------------------------------------------------------------- unlinked normalisation (Win7)
REQUIRED = {"artifact", "id_type", "id_value", "ref_time", "ref_time_scope", "user", "details"}


def test_unlinked_entries_are_normalised():
    ev = Evidence()
    parse_system(sample("SYSTEM"), ev)
    parse_software(sample("SOFTWARE"), ev)
    parse_ntuser(sample("NTUSER.DAT"), ev, "testuser")
    assert ev.unlinked, "Win7 sample has one EMDMgmt entry with no device path"
    for u in ev.unlinked:
        assert REQUIRED <= set(u), u
    emd = [u for u in ev.unlinked if u["artifact"] == "EMDMgmt"][0]
    assert emd["id_type"] == "volume_label" and emd["id_value"] == "WR_Q__"
    assert emd["details"]["vsn"] == "AC036525"
    assert emd["ref_time"] is not None and emd["ref_time_scope"] == "entry"


# --------------------------------------------------------------------------- 1102 / 104
def _system(channel, provider="Microsoft-Windows-Eventlog", computer="NW-FIN-WS042.corp.example"):
    return {"Provider": {"#attributes": {"Name": provider}}, "Channel": channel, "Computer": computer,
            "TimeCreated": {"#attributes": {"SystemTime": "2026-10-30T22:00:00.000000Z"}}}


def test_1102_security_log_cleared():
    body = {"LogFileCleared": {"SubjectUserSid": "S-1-5-21-1-2-3-1001", "SubjectUserName": "j.doe",
                               "SubjectDomainName": "NW", "SubjectLogonId": "0x3e7"}}
    e = log_cleared_event(1102, _system("Security"), body, None)
    assert e.kind == LOG_CLEARED and e.source == "evtx:Security:1102"
    assert e.ts == utc(2026, 10, 30, 22, 0) and e.user == "NW\\j.doe"
    assert e.details["channel"] == "Security"
    assert e.details["computer"] == "NW-FIN-WS042.corp.example"


def test_104_names_the_cleared_channel():
    body = {"LogFileCleared": {"SubjectUserName": "j.doe", "SubjectDomainName": "NW",
                               "Channel": "Microsoft-Windows-Partition/Diagnostic", "BackupPath": ""}}
    e = log_cleared_event(104, _system("System"), body, None)
    assert e.source == "evtx:System:104"
    assert e.details["channel"] == "Microsoft-Windows-Partition/Diagnostic"


def test_104_from_another_provider_is_ignored():
    # Event ID 104 is reused by other providers; only Microsoft-Windows-Eventlog means "log cleared".
    assert log_cleared_event(104, _system("System", provider="Microsoft-Windows-Kernel-Power"), {}, None) is None


# --------------------------------------------------------------------------- host consistency
def test_partition_log_computer_names_are_recorded():
    ev = Evidence()
    parse_partition_diagnostic(sample("Microsoft-Windows-Partition%4Diagnostic.evtx"), ev)
    assert ev.log_computers["Partition/Diagnostic"] == {"WIN-9F6UT4I01JI": 5, "DESKTOP-GOGB42D": 35}
    assert all(e.details.get("computer") for e in ev.events)


# --------------------------------------------------------------------------- real-sample tamper runs
def test_win7_registry_is_a_clean_negative_control():
    ev = Evidence()
    parse_system(sample("SYSTEM"), ev)
    parse_software(sample("SOFTWARE"), ev)
    parse_ntuser(sample("NTUSER.DAT"), ev, "testuser")
    assert find_tamper(ev) == []


def test_win7_plus_foreign_partition_log_reports_mismatch_only():
    ev = Evidence()
    parse_system(sample("SYSTEM"), ev)
    parse_software(sample("SOFTWARE"), ev)
    parse_partition_diagnostic(sample("Microsoft-Windows-Partition%4Diagnostic.evtx"), ev)
    findings = find_tamper(ev)
    assert [f.rule for f in findings] == ["evidence_host_mismatch"]
    assert "DESKTOP-GOGB42D" in findings[0].why and "WIN-9F6UT4I01JI" in findings[0].why


def test_win10_sample_has_nothing_suspicious():
    ev = Evidence()
    parse_system(sample("SYSTEM_WIN_10_1709"), ev)
    assert not [f for f in find_tamper(ev) if f.severity in ("medium", "high")]


def test_cli_tamper_writes_jsonl(tmp_path):
    sample("SYSTEM")
    assert main(["tamper", "--triage", DATA, "--out", str(tmp_path), "-q"]) == 0
    lines = (tmp_path / "tamper.jsonl").read_text(encoding="utf-8").splitlines()
    assert any('"evidence_host_mismatch"' in line for line in lines)
