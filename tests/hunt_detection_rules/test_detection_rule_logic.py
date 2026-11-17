"""Module #4: what each rule matches, proved with events in the neutral schema.

Every rule YAML carries its own `tests:` (events that must match and events that must not). These run here, plus
evaluator semantics and hand-written cases for each hypothesis. Fictional host NW-FIN-WS042, user NW\\j.doe.
"""

from datetime import timedelta

import pytest

from usbhawk.detections import evaluate, evaluate_stream, load_rules, run_rule_tests
from usbhawk.scoring import load_config
from usbhawk.util import to_utc

RULES = load_rules()


def rule(h):
    return next(r for r in RULES if r.hypothesis == h)


def det(selections, condition, telemetry="process_creation", **extra):
    return {"name": "d", "telemetry": telemetry, "selections": selections, "condition": condition, **extra}


# --------------------------------------------------------------------------- every rule's own tests
@pytest.mark.parametrize("r", RULES, ids=[r.hypothesis for r in RULES])
def test_rule_passes_its_own_test_events(r):
    assert run_rule_tests(r) == []


# --------------------------------------------------------------------------- evaluator semantics
def test_values_compare_case_insensitively():
    assert evaluate(det({"s": {"process_name": "WEVTUTIL.exe"}}, "s"), {"process_name": "wevtutil.EXE"})


@pytest.mark.parametrize("modifier, value, field_value, expected", [
    ("startswith", "usboblivion", "USBOblivion64.exe", True),
    ("startswith", "oblivion", "USBOblivion64.exe", False),
    ("endswith", ".zip", "F:\\loot\\q3.ZIP", True),
    ("endswith", ".zip", "F:\\loot\\q3.zip.txt", False),
    ("contains", " cl ", "wevtutil.exe cl Security", True),
    ("contains", " cl ", "wevtutil.exe qe Security", False),
])
def test_modifiers(modifier, value, field_value, expected):
    d = det({"s": {f"command_line|{modifier}": value}}, "s")
    assert evaluate(d, {"command_line": field_value}) is expected


def test_list_means_any_of():
    d = det({"s": {"process_name": ["a.exe", "b.exe"]}}, "s")
    assert evaluate(d, {"process_name": "b.exe"}) and not evaluate(d, {"process_name": "c.exe"})


def test_fields_in_one_selection_must_all_match():
    d = det({"s": {"process_name": "wevtutil.exe", "command_line|contains": " cl "}}, "s")
    assert evaluate(d, {"process_name": "wevtutil.exe", "command_line": "wevtutil cl System"})
    assert not evaluate(d, {"process_name": "wevtutil.exe", "command_line": "wevtutil qe System"})


def test_missing_field_never_matches():
    assert not evaluate(det({"s": {"command_line|contains": "x"}}, "s"), {"process_name": "x"})


def test_numbers_and_strings_compare_equal():
    d = det({"s": {"event_id": 1102}}, "s", telemetry="event_log", channel="Security")
    assert evaluate(d, {"channel": "Security", "event_id": "1102"})


def test_condition_and_or_not_parentheses():
    d = det({"a": {"process_name": "a.exe"}, "b": {"command_line|contains": "x"},
             "c": {"user": "SYSTEM"}}, "(a or b) and not c")
    assert evaluate(d, {"process_name": "a.exe", "user": "NW\\j.doe"})
    assert evaluate(d, {"process_name": "z.exe", "command_line": "x", "user": "NW\\j.doe"})
    assert not evaluate(d, {"process_name": "a.exe", "user": "SYSTEM"})


def test_event_log_detection_checks_the_channel():
    d = det({"s": {"event_id": 104}}, "s", telemetry="event_log", channel="System")
    assert evaluate(d, {"channel": "System", "event_id": 104})
    assert not evaluate(d, {"channel": "Application", "event_id": 104})


# --------------------------------------------------------------------------- H6: cleanup tool executed
def test_h6_usboblivion_is_the_high_detection():
    h6 = rule("H6")
    ev = {"process_name": "USBOblivion64.exe", "image": "C:\\Users\\j.doe\\Downloads\\USBOblivion64.exe"}
    assert evaluate(h6.detection("usb_cleaner"), ev)
    assert not evaluate(h6.detection("general_cleaner"), ev)
    assert h6.level_of("usb_cleaner") == "high"


def test_h6_general_cleaner_is_medium():
    h6 = rule("H6")
    assert evaluate(h6.detection("general_cleaner"), {"process_name": "CCleaner64.exe"})
    assert h6.level_of("general_cleaner") == "medium"


def test_h6_ordinary_programs_do_not_match():
    h6 = rule("H6")
    for name in ("notepad.exe", "powershell.exe", "OneDrive.exe"):
        assert not any(evaluate(d, {"process_name": name}) for d in h6.detections)


# --------------------------------------------------------------------------- H7: event log cleared
def test_h7_security_1102_matches_only_from_the_eventlog_provider():
    d = rule("H7").detection("security_log_cleared")
    assert evaluate(d, {"channel": "Security", "event_id": 1102, "provider": "Microsoft-Windows-Eventlog"})
    assert not evaluate(d, {"channel": "Security", "event_id": 1102, "provider": "SomethingElse"})


def test_contains_all_needs_every_value():
    d = det({"s": {"command_line|contains|all": ["EventLogSession", "ClearLog"]}}, "s")
    assert evaluate(d, {"command_line": "x.EventLogSession::GlobalSession.ClearLog('Security')"})
    assert not evaluate(d, {"command_line": "x.EventLogSession::GlobalSession.GetLogNames()"})


# --------------------------------------------------------------------------- stateful logic (H1 first seen, H3 threshold)
def burst(n, every_s=5, start="2026-10-30T21:15:00Z", removable=True, user="NW\\j.doe"):
    t0 = to_utc(start)
    return [{"timestamp": t0 + timedelta(seconds=i * every_s), "file_path": f"F:\\loot\\f{i}.docx",
             "file_name": f"f{i}.docx", "removable": removable, "host": "NW-FIN-WS042", "user": user}
            for i in range(n)]


def test_h3_threshold_both_sides():
    d = rule("H3").detection("bulk_copy_to_usb")
    assert evaluate_stream(d, burst(50)) and not evaluate_stream(d, burst(49))


def test_h3_threshold_counts_per_user():
    d = rule("H3").detection("bulk_copy_to_usb")
    mixed = burst(30, user="NW\\j.doe") + burst(30, user="NW\\a.smith")
    assert evaluate_stream(d, mixed) == []


def test_h3_threshold_follows_the_scoring_config():
    cfg = load_config()
    cfg["thresholds"]["bulk_files"] = 10
    d = next(r for r in load_rules(cfg=cfg) if r.hypothesis == "H3").detection("bulk_copy_to_usb")
    assert evaluate_stream(d, burst(10))


def test_h1_first_seen_uses_the_newest_event_as_now():
    d = rule("H1").detection("first_seen_usb_storage")
    old = {"timestamp": "2026-10-01T09:00:00Z", "device_id": "USBSTOR\\DISK&VEN_X\\AAA&0"}
    new = {"timestamp": "2026-10-30T21:14:00Z", "device_id": "USBSTOR\\DISK&VEN_X\\BBB&0"}
    alerts = evaluate_stream(d, [old, new])
    assert [a["value"] for a in alerts] == ["usbstor\\disk&ven_x\\bbb&0"]


# --------------------------------------------------------------------------- H2 work hours on the configured clock
def test_h2_uses_the_configured_time_zone():
    cfg = load_config()
    cfg["work_hours"]["timezone"] = "America/New_York"
    d = next(r for r in load_rules(cfg=cfg) if r.hypothesis == "H2").detection("usb_storage_off_hours")
    stick = {"device_id": "USBSTOR\\DISK&VEN_X\\AAA&0"}
    assert not evaluate(d, {**stick, "timestamp": "2026-11-16T20:00:00Z"})   # 15:00 New York: work hours
    assert evaluate(d, {**stick, "timestamp": "2026-11-16T12:30:00Z"})       # 07:30 New York: before work


# --------------------------------------------------------------------------- H4, H5, H8 spot checks
def test_h4_extensions_come_from_config():
    cfg = load_config()
    cfg["archive_extensions"] = [".tar.zst"]
    d = next(r for r in load_rules(cfg=cfg) if r.hypothesis == "H4").detection("archive_to_usb")
    assert evaluate(d, {"file_name": "x.tar.zst", "removable": True})
    assert not evaluate(d, {"file_name": "x.zip", "removable": True})


def test_h8_windows_uninstall_is_excluded_but_reg_exe_is_not():
    d = rule("H8").detection("usb_registry_trace_deleted")
    path = "HKLM\\SYSTEM\\ControlSet001\\Enum\\USBSTOR\\Disk&Ven_X\\AAA&0"
    assert not evaluate(d, {"action": "delete", "process_name": "DrvInst.exe", "registry_path": path})
    assert evaluate(d, {"action": "delete", "process_name": "reg.exe", "registry_path": path})


def test_h7_system_104_needs_the_eventlog_provider():
    d = rule("H7").detection("log_cleared_104")
    assert evaluate(d, {"channel": "System", "event_id": 104, "provider": "Microsoft-Windows-Eventlog"})
    assert not evaluate(d, {"channel": "System", "event_id": 104, "provider": "Microsoft-Windows-Kernel-Power"})


@pytest.mark.parametrize("name, cmd, expected", [
    ("wevtutil.exe", "wevtutil cl Security", True),
    ("wevtutil.exe", "wevtutil.exe clear-log System", True),
    ("wevtutil.exe", "wevtutil qe Security /c:5", False),
    ("powershell.exe", "powershell -c Clear-EventLog -LogName Security", True),
    ("powershell.exe", "powershell -c Get-EventLog -LogName Security -Newest 5", False),
])
def test_h7_clearing_commands(name, cmd, expected):
    d = rule("H7").detection("clear_command")
    assert evaluate(d, {"process_name": name, "command_line": cmd}) is expected
