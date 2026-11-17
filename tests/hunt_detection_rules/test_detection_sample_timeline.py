"""Module #4: the insider timeline shown in docs/hunt-detection-rules.md ("Use cases and sample alerts").

Plug in a stick on a Friday evening, copy 64 documents, write a 7z archive, reformat, run USBOblivion (which deletes
the stick's registry keys and clears the Security log). Every hypothesis H1-H8 must fire, in order, exactly as the
documentation shows. If a rule change breaks a documented use case, this test fails before the docs go stale.
Fictional host NW-FIN-WS042, user NW\\j.doe, invented device and file names.
"""

from datetime import timedelta

from usbthk.detections import load_rules
from usbthk.detections.replay import normalize_record, run
from usbthk.util import to_utc

SYSMON = "Microsoft-Windows-Sysmon/Operational"
T = to_utc("2026-10-30T21:14:00Z")
HOST = "NW-FIN-WS042.corp.example"
USER = r"NW\j.doe"
TOOL = r"C:\Users\j.doe\Downloads\USBOblivion64.exe"
STICK = r"USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP\60A44C413D5FF380E95A0B7D&0"


def rec(channel, eid, data, ts, provider=None):
    default = {SYSMON: "Microsoft-Windows-Sysmon", "Security": "Microsoft-Windows-Security-Auditing",
               "System": "Microsoft-Windows-Eventlog"}
    return {"channel": channel, "event_id": eid, "provider": provider or default[channel], "computer": HOST,
            "ts": ts, "data": data}


def proc(image, cmd, ts, parent=r"C:\Windows\explorer.exe"):
    return rec(SYSMON, 1, {"Image": image, "CommandLine": cmd, "OriginalFileName": image.rsplit("\\", 1)[-1],
                           "ParentImage": parent, "User": USER}, ts)


def timeline():
    r = [rec("Security", 6416, {"DeviceId": STICK, "ClassName": "DiskDrive",
                                "DeviceDescription": "USB Mass Storage Device"}, T)]
    r += [rec(SYSMON, 11, {"Image": r"C:\Windows\explorer.exe", "TargetFilename": rf"F:\Q3\board-pack-{i:02d}.docx",
                           "User": USER}, T + timedelta(minutes=2, seconds=4 * i)) for i in range(64)]
    r += [rec(SYSMON, 11, {"Image": r"C:\Program Files\7-Zip\7zG.exe", "TargetFilename": r"F:\Q3\finance-share.7z",
                           "User": USER}, T + timedelta(minutes=8))]
    r += [proc(r"C:\Windows\System32\format.com", "format.com F: /FS:exFAT /Q /Y", T + timedelta(minutes=20))]
    r += [proc(TOOL, "USBOblivion64.exe -enable -auto", T + timedelta(minutes=25))]
    r += [rec(SYSMON, 12, {"EventType": "DeleteKey", "Image": TOOL, "User": USER,
                           "TargetObject": r"HKLM\System\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0"
                                           r"&Rev_PMAP\60A44C413D5FF380E95A0B7D&0"}, T + timedelta(minutes=25, seconds=30))]
    r += [proc(r"C:\Windows\System32\wevtutil.exe", "wevtutil.exe cl Security", T + timedelta(minutes=26), parent=TOOL)]
    r += [rec("Security", 1102, {"SubjectUserName": "j.doe", "SubjectDomainName": "NW"},
              T + timedelta(minutes=26, seconds=1), provider="Microsoft-Windows-Eventlog")]
    return [e for x in r for e in normalize_record(x, removable_drives={"F:"})]


DOCUMENTED = [("H1", "first_seen_usb_storage"), ("H1", "usb_storage_connected"), ("H2", "usb_storage_off_hours"),
              ("H3", "bulk_copy_to_usb"), ("H4", "archive_to_usb"), ("H5", "format_command"), ("H6", "usb_cleaner"),
              ("H8", "usb_registry_trace_deleted"), ("H7", "clear_command"), ("H7", "security_log_cleared")]


def test_every_hypothesis_fires_in_the_documented_order():
    alerts = run(load_rules(), timeline())
    order = []
    for a in alerts:
        key = (a["hypothesis"], a["detection"])
        if key not in order:
            order.append(key)
    assert order == DOCUMENTED
    assert {h for h, _d in order} == {f"H{i}" for i in range(1, 9)}


def test_documented_details():
    alerts = {(a["hypothesis"], a["detection"]): a for a in reversed(run(load_rules(), timeline()))}
    assert alerts[("H3", "bulk_copy_to_usb")]["evidence"]["count"] == 60     # 10-minute bucket 21:10-21:20
    assert "finance-share.7z" in alerts[("H4", "archive_to_usb")]["why"]
    assert alerts[("H6", "usb_cleaner")]["level"] == "high"
    assert "Enum\\USBSTOR" in alerts[("H8", "usb_registry_trace_deleted")]["why"]
