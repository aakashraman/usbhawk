"""Module #4: replaying real event logs through the rules (`usbhawk detections run --evtx`).

normalize_record() turns one parsed EVTX record into the neutral event schema the rules use; run() replays a
timeline through every detection. Records here are written the way pyevtx-rs parses them (Event/System/EventData),
with fictional values (host NW-FIN-WS042, user NW\\j.doe).
"""

from datetime import timedelta

from usbhawk.detections import load_rules
from usbhawk.detections.replay import normalize_record, run
from usbhawk.util import to_utc

T0 = to_utc("2026-11-17T14:00:00Z")
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def rec(channel, eid, data, ts=T0, provider=None, computer="NW-FIN-WS042.corp.example"):
    return {"channel": channel, "event_id": eid, "provider": provider or {
        SYSMON: "Microsoft-Windows-Sysmon", "Security": "Microsoft-Windows-Security-Auditing",
        "System": "Microsoft-Windows-Eventlog"}.get(channel, "x"), "computer": computer, "ts": ts, "data": data}


def proc(image, cmd, ts=T0, user="NW\\j.doe"):
    return rec(SYSMON, 1, {"Image": image, "CommandLine": cmd, "OriginalFileName": image.rsplit("\\", 1)[-1],
                           "ParentImage": "C:\\Windows\\explorer.exe", "User": user}, ts)


def file_create(path, ts=T0):
    return rec(SYSMON, 11, {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                            "TargetFilename": path, "User": "NW\\j.doe"}, ts)


# --------------------------------------------------------------------------- normalisation
def test_sysmon_process_creation():
    e = normalize_record(proc("C:\\Users\\j.doe\\Downloads\\USBOblivion64.exe", "USBOblivion64.exe -enable"))[0]
    assert e["_telemetry"] == "process_creation"
    assert e["process_name"] == "USBOblivion64.exe" and e["parent_name"] == "explorer.exe"
    assert e["host"] == "NW-FIN-WS042.corp.example" and e["timestamp"] == T0


def test_sysmon_file_create_marks_removable_drives():
    usb = normalize_record(file_create("F:\\loot\\q3.zip"))[0]
    local = normalize_record(file_create("C:\\Users\\j.doe\\q3.zip"))[0]
    assert usb["_telemetry"] == "file_event" and usb["file_name"] == "q3.zip" and usb["removable"] is True
    assert local["removable"] is False


def test_declared_removable_drives_override_the_heuristic():
    e = normalize_record(file_create("E:\\evidence\\x.zip"), removable_drives={"F:"})[0]
    assert e["removable"] is False
    assert normalize_record(file_create("f:\\x.zip"), removable_drives={"F:"})[0]["removable"] is True


def test_sysmon_registry_delete():
    e = normalize_record(rec(SYSMON, 12, {"EventType": "DeleteKey", "Image": "C:\\x\\USBOblivion64.exe",
                                          "TargetObject": "HKLM\\System\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_X\\A&0"}))[0]
    assert e["_telemetry"] == "registry_event" and e["action"] == "delete" and e["process_name"] == "USBOblivion64.exe"
    created = normalize_record(rec(SYSMON, 12, {"EventType": "CreateKey", "Image": "x.exe", "TargetObject": "HKLM\\x"}))
    assert created[0]["action"] == "create"


def test_security_6416_is_a_device_connect():
    e = normalize_record(rec("Security", 6416, {"DeviceId": "USBSTOR\\DISK&VEN_X\\AAA&0", "ClassName": "DiskDrive",
                                                "DeviceDescription": "Disk drive", "SubjectUserName": "NW-FIN-WS042$"}))
    kinds = {x["_telemetry"] for x in e}
    assert kinds == {"device_connect", "event_log"}
    dev = next(x for x in e if x["_telemetry"] == "device_connect")
    assert dev["device_id"] == "USBSTOR\\DISK&VEN_X\\AAA&0" and dev["device_class"] == "DiskDrive"


def test_security_4688_is_a_process_creation():
    e = normalize_record(rec("Security", 4688, {"NewProcessName": "C:\\Windows\\System32\\wevtutil.exe",
                                                "CommandLine": "wevtutil cl Security", "SubjectUserName": "j.doe",
                                                "SubjectDomainName": "NW", "ParentProcessName": "C:\\x\\cmd.exe"}))
    p = next(x for x in e if x["_telemetry"] == "process_creation")
    assert p["process_name"] == "wevtutil.exe" and p["user"] == "NW\\j.doe" and p["parent_name"] == "cmd.exe"


def test_log_clear_records_keep_channel_and_provider():
    e = normalize_record(rec("System", 104, {"Channel": "Application"}))[0]
    assert e == {**e, "_telemetry": "event_log", "channel": "System", "event_id": 104,
                 "provider": "Microsoft-Windows-Eventlog"}


def test_unknown_channels_are_ignored():
    assert normalize_record(rec("Application", 1000, {})) == []


# --------------------------------------------------------------------------- replay
def test_replay_fires_the_right_rules():
    rules = load_rules()
    records = ([proc("C:\\x\\USBOblivion64.exe", "USBOblivion64.exe")]
               + [file_create(f"F:\\lab\\f{i}.txt", T0 + timedelta(seconds=3 * i)) for i in range(60)]
               + [file_create("F:\\lab\\docs.zip", T0 + timedelta(minutes=4))]
               + [rec("Security", 1102, {"SubjectUserName": "j.doe", "SubjectDomainName": "NW"},
                      provider="Microsoft-Windows-Eventlog")])
    events = [e for r in records for e in normalize_record(r)]
    hits = {(a["hypothesis"], a["detection"]) for a in run(rules, events)}
    assert {("H6", "usb_cleaner"), ("H3", "bulk_copy_to_usb"), ("H4", "archive_to_usb"),
            ("H7", "security_log_cleared")} <= hits
    assert not any(h == "H8" for h, _d in hits)          # no registry deletes in this timeline


def test_replay_quiet_baseline_has_no_alerts():
    rules = load_rules()
    records = [proc("C:\\Windows\\System32\\notepad.exe", "notepad.exe"),
               file_create("C:\\Users\\j.doe\\Documents\\notes.txt"),
               rec("Security", 4624, {"TargetUserName": "j.doe"})]
    assert run(rules, [e for r in records for e in normalize_record(r)]) == []


def test_replay_first_seen_reports_the_history_it_had():
    rules = load_rules()
    dev = {"DeviceId": "USBSTOR\\DISK&VEN_X\\AAA&0", "ClassName": "DiskDrive", "DeviceDescription": "x"}
    events = [e for r in [rec("Security", 6416, dev, T0), rec("Security", 6416, dev, T0 + timedelta(hours=2))]
              for e in normalize_record(r)]
    fs = [a for a in run(rules, events) if a["detection"] == "first_seen_usb_storage"]
    assert len(fs) == 1 and fs[0]["timestamp"] == T0                # only the first sighting
    assert "history" in fs[0]["why"]


def test_events_jsonl_feeds_the_same_replay(tmp_path):
    """`usbhawk detections run --events file.jsonl`: neutral events, one per line (used by the demo kit)."""
    import json
    from usbhawk.detections.replay import load_events_jsonl
    path = tmp_path / "events.jsonl"
    rows = [{"_telemetry": "process_creation", "timestamp": "2026-10-30T21:39:00Z", "process_name": "USBOblivion64.exe",
             "host": "NW-FIN-WS042"},
            {"_telemetry": "event_log", "timestamp": "2026-10-30T21:40:01Z", "channel": "Security", "event_id": 1102,
             "provider": "Microsoft-Windows-Eventlog"}]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    events = load_events_jsonl([str(path)])
    assert events[0]["timestamp"] == to_utc("2026-10-30T21:39:00Z")
    hits = {(a["hypothesis"], a["detection"]) for a in run(load_rules(), events)}
    assert hits == {("H6", "usb_cleaner"), ("H7", "security_log_cleared")}


def test_events_jsonl_rejects_unknown_telemetry(tmp_path):
    import pytest
    from usbhawk.detections.replay import load_events_jsonl
    path = tmp_path / "bad.jsonl"
    path.write_text('{"_telemetry": "carrier_pigeon", "timestamp": "2026-10-30T21:39:00Z"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="carrier_pigeon"):
        load_events_jsonl([str(path)])


def test_alerts_are_sorted_and_explained():
    rules = load_rules()
    events = [e for r in [proc("C:\\x\\wevtutil.exe", "wevtutil cl Application", T0 + timedelta(minutes=5)),
                          proc("C:\\x\\USBOblivion64.exe", "USBOblivion64.exe", T0)] for e in normalize_record(r)]
    alerts = run(rules, events)
    assert [a["timestamp"] for a in alerts] == sorted(a["timestamp"] for a in alerts)
    assert all(a["why"] and a["level"] and a["title"] for a in alerts)


# --------------------------------------------------------------------------- unreadable logs (live folders)
def _empty_evtx(path):
    """A valid event log with no records (header only), like a freshly cleared log."""
    import struct
    import zlib
    head = bytearray(4096)
    struct.pack_into("<8sQQQIHHHH", head, 0, b"ElfFile\0", 0, 0, 1, 128, 1, 3, 4096, 0)
    struct.pack_into("<I", head, 124, zlib.crc32(bytes(head[:120])))
    path.write_bytes(bytes(head))
    return path


def test_one_unreadable_log_never_stops_the_replay(tmp_path):
    """Found pointing `--evtx` at the live Windows event log folder (winevt/Logs) without admin rights: the first
    unreadable file ended the whole run with a traceback."""
    from usbhawk.detections.replay import load_events
    good = _empty_evtx(tmp_path / "System.evtx")
    bad = tmp_path / "Broken.evtx"
    bad.write_bytes(b"not an event log")
    errors = []
    assert load_events([str(tmp_path)], errors=errors) == []
    assert [f for f, _m in errors] == [str(bad)] and good.exists()


def test_cli_reports_unreadable_logs_and_keeps_going(tmp_path, capsys, monkeypatch):
    from usbhawk.cli import main
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    _empty_evtx(tmp_path / "System.evtx")
    (tmp_path / "Broken.evtx").write_bytes(b"not an event log")
    assert main(["detections", "run", "--evtx", str(tmp_path)]) == 0
    err = capsys.readouterr().err
    assert "skipped" in err and "Broken.evtx" in err and "1 of 2 log files could not be read" in err


def test_cli_fails_clearly_when_no_log_is_readable(tmp_path, capsys, monkeypatch):
    from usbhawk.cli import main
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    (tmp_path / "Broken.evtx").write_bytes(b"not an event log")
    assert main(["detections", "run", "--evtx", str(tmp_path)]) == 2
    assert "none of the 1 log files could be read" in capsys.readouterr().err


# --------------------------------------------------------------------------- telemetry coverage
def test_coverage_names_the_hypotheses_that_could_not_fire():
    """Real PC (test case 3.7): 75,334 events, all plain event-log records, and zero alerts. Without this note a
    responder cannot tell "nothing happened" from "nothing was recorded"."""
    from usbhawk.detections.replay import coverage_gaps
    rules = load_rules()
    only_logs = [{"_telemetry": "event_log", "channel": "Security", "timestamp": T0}]
    gaps = dict(coverage_gaps(rules, only_logs))
    assert gaps == {"device_connect": ["H1", "H2"], "file_event": ["H3", "H4"],
                    "process_creation": ["H5", "H6"], "registry_event": ["H8"]}      # H7 can fire from 1102


def test_coverage_is_silent_when_every_kind_of_telemetry_is_present():
    from usbhawk.detections.replay import coverage_gaps
    kinds = ["device_connect", "file_event", "process_creation", "registry_event"]
    events = [{"_telemetry": k, "timestamp": T0} for k in kinds]
    events += [{"_telemetry": "event_log", "channel": c, "timestamp": T0} for c in ("Security", "System")]
    assert coverage_gaps(load_rules(), events) == []


def test_cli_prints_the_telemetry_gaps(tmp_path, capsys, monkeypatch):
    from usbhawk.cli import main
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    monkeypatch.setenv("COLUMNS", "200")
    _empty_evtx(tmp_path / "System.evtx")
    assert main(["detections", "run", "--evtx", str(tmp_path)]) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "Telemetry gaps:" in out and "H1, H2: no device_connect events" in out and "Sysmon event 11" in out


def test_cli_says_which_alerts_to_look_at_first(tmp_path, capsys, monkeypatch):
    """Owner's question on a real PC run: 'which ones to look at first?'. The table is a timeline; the replay now
    ends with the alerts grouped by level (high first), each with its first time."""
    import json
    from usbhawk.cli import main
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    monkeypatch.setenv("COLUMNS", "250")
    events = tmp_path / "e.jsonl"
    rows = [{"timestamp": f"2026-10-30T21:{16 + i // 30:02d}:{(i * 2) % 60:02d}Z", "_telemetry": "file_event",
             "file_path": f"F:\\Q3\\doc{i}.docx", "file_name": f"doc{i}.docx", "removable": True,
             "host": "NW-FIN-WS042", "user": "NW\\j.doe"} for i in range(55)]
    rows.append({"timestamp": "2026-10-30T21:22:00Z", "_telemetry": "file_event", "file_path": "F:\\Q3\\all.7z",
                 "file_name": "all.7z", "removable": True, "host": "NW-FIN-WS042", "user": "NW\\j.doe"})
    events.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    assert main(["detections", "run", "--events", str(events)]) == 0
    out = capsys.readouterr().out
    assert "Hypothesis" in out and "| Hyp |" not in out and "│ Hyp │" not in out
    tail = " ".join(out[out.index("Look at first"):].split())
    assert tail.index("high H3 bulk_copy_to_usb") < tail.index("medium H4 archive_to_usb")
    # 1.0.2: full dates, since one detection's alerts can span weeks (real case: 2020-10-31 to 2020-11-16)
    assert "H4 archive_to_usb (at 2026-10-30 21:22:00)" in tail
