"""Module #4: replaying real event logs through the rules (`usbthk detections run --evtx`).

normalize_record() turns one parsed EVTX record into the neutral event schema the rules use; run() replays a
timeline through every detection. Records here are written the way pyevtx-rs parses them (Event/System/EventData),
with fictional values (host NW-FIN-WS042, user NW\\j.doe).
"""

from datetime import timedelta

from usbthk.detections import load_rules
from usbthk.detections.replay import normalize_record, run
from usbthk.util import to_utc

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


def test_alerts_are_sorted_and_explained():
    rules = load_rules()
    events = [e for r in [proc("C:\\x\\wevtutil.exe", "wevtutil cl Application", T0 + timedelta(minutes=5)),
                          proc("C:\\x\\USBOblivion64.exe", "USBOblivion64.exe", T0)] for e in normalize_record(r)]
    alerts = run(rules, events)
    assert [a["timestamp"] for a in alerts] == sorted(a["timestamp"] for a in alerts)
    assert all(a["why"] and a["level"] and a["title"] for a in alerts)
