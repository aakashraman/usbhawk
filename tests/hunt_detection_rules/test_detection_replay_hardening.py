"""1.0.1: `detections run` on a real KAPE collection (found on a real case; values here are fictional or public).

  * a damaged log is read around the damage and listed, never dropped or fatal;
  * H2 (off hours) is judged on the host's clock: --tz, else the SYSTEM hive next to the logs, else UTC + warning;
  * Windows logs one plug-in twice (USB device node and USBSTOR disk): the table shows it once, alerts.jsonl keeps both;
  * a disk image passed where a folder belongs prints how to mount it.
"""

import os
import re
import shutil
from datetime import timedelta

from usbhawk.cli import _pair_plug_ins, main
from usbhawk.detections.replay import load_events
from usbhawk.util import to_utc

from conftest import sample

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WIPED = os.path.join(ROOT, "examples", "tamper", "wiped-host")
TIMELINE = os.path.join(ROOT, "examples", "detections", "insider_timeline.jsonl")
T = to_utc("2026-10-30T21:14:00Z")
USB = r"USB\VID_0951&PID_1666\60A44C413D5FF380E95A0B7D"
DISK = r"USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\60A44C413D5FF380E95A0B7D&0"


def alert(hyp, det, why, ts=T):
    return {"timestamp": ts, "hypothesis": hyp, "detection": det, "level": "medium", "why": why}


# --------------------------------------------------------------------------- plug-in pairing
def test_one_plug_in_logged_twice_is_one_row_preferring_the_disk():
    rows = _pair_plug_ins([
        alert("H1", "usb_storage_connected", f"device_id={USB}; device_description=USB Mass Storage Device"),
        alert("H2", "usb_storage_off_hours", f"device_id={USB}"),
        alert("H1", "usb_storage_connected", f"device_id={DISK}; device_description=DataTraveler 3.0"),
        alert("H2", "usb_storage_off_hours", f"device_id={DISK}"),
        alert("H3", "bulk_copy_to_usb", "60 matching events")])
    assert [(a["hypothesis"], n) for a, n in rows] == [("H1", 2), ("H2", 2), ("H3", 1)]
    assert all("USBSTOR" in a["why"] for a, n in rows if n == 2)


def test_different_sticks_or_times_are_never_merged():
    other = DISK.replace("60A44C413D5FF380E95A0B7D", "AA951D0000007252")
    rows = _pair_plug_ins([
        alert("H1", "usb_storage_connected", f"device_id={DISK}"),
        alert("H1", "usb_storage_connected", f"device_id={other}"),
        alert("H1", "usb_storage_connected", f"device_id={USB}", ts=T + timedelta(minutes=5))])
    assert [n for _a, n in rows] == [1, 1, 1]


def test_slow_disk_logged_seconds_after_its_usb_node_is_still_one_row():
    """Real case: an external USB 3.0 hard disk's disk 6416 came 5 s after its USB node 6416."""
    rows = _pair_plug_ins([
        alert("H1", "usb_storage_connected", f"device_id={USB}"),
        alert("H1", "usb_storage_connected", f"device_id={DISK}", ts=T + timedelta(seconds=5))])
    assert [n for _a, n in rows] == [2] and "USBSTOR" in rows[0][0]["why"]


def test_pairing_window_is_bounded_and_never_holds_two_disks():
    rows = _pair_plug_ins([
        alert("H1", "usb_storage_connected", f"device_id={USB}"),
        alert("H1", "usb_storage_connected", f"device_id={DISK}", ts=T + timedelta(seconds=31))])
    assert [n for _a, n in rows] == [1, 1]
    rows = _pair_plug_ins([           # unplugged and plugged again quickly: two plug-ins, two rows
        alert("H1", "usb_storage_connected", f"device_id={DISK}"),
        alert("H1", "usb_storage_connected", f"device_id={DISK}", ts=T + timedelta(seconds=10))])
    assert [n for _a, n in rows] == [1, 1]


def test_table_says_the_row_stands_for_two_log_entries(tmp_path, capsys, monkeypatch):
    """Lab-found: rich read the "[the same plug-in ...]" note as markup and silently dropped it."""
    import json
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    monkeypatch.setenv("COLUMNS", "400")                    # one table line per row, so the note reads whole
    base = {"timestamp": "2026-10-30T21:14:00Z", "_telemetry": "device_connect", "_source": "Security:6416",
            "host": "NW-FIN-WS042"}
    events = tmp_path / "plug_in.jsonl"
    events.write_text("\n".join(json.dumps({**base, "device_id": d, "device_class": c, "device_description": n})
                                for d, c, n in ((USB, "USB", "USB Mass Storage Device"),
                                                (DISK, "DiskDrive", "Kingston DataTraveler 3.0 USB Device")))
                      + "\n", encoding="utf-8")
    assert main(["detections", "run", "--events", str(events), "--tz", "America/New_York",
                 "--out", str(tmp_path / "out")]) == 0
    out = " ".join(re.sub("[|─-╿]", " ", capsys.readouterr().out).split())   # drop table borders
    assert "[the same plug-in is logged again for its USB device node]" in out
    assert "Shown as 2 rows" in out
    assert len((tmp_path / "out" / "alerts.jsonl").read_text().splitlines()) == 4   # SIEM output keeps both


# --------------------------------------------------------------------------- damaged logs
def test_damaged_log_is_listed_and_still_replayed(tmp_path):
    src = sample("Microsoft-Windows-Partition%4Diagnostic.evtx")
    out = tmp_path / "Partition.evtx"
    shutil.copy(src, out)
    raw = bytearray(out.read_bytes())
    raw[4096 + 65536:4096 + 65536 + 8] = bytes(8)          # zero chunk 1's magic
    out.write_bytes(raw)
    errors, damaged = [], []
    load_events([str(out)], None, errors, damaged)
    assert errors == []
    assert len(damaged) == 1 and damaged[0][0] == str(out) and damaged[0][1] >= 1 and damaged[0][2] == 20


def test_not_an_evtx_is_an_error_not_a_crash(tmp_path):
    bad = tmp_path / "Security.evtx"
    bad.write_bytes(b"not an event log")
    errors, damaged = [], []
    assert load_events([str(bad)], None, errors, damaged) == [] and len(errors) == 1


# --------------------------------------------------------------------------- H2 time zone
def test_tz_flag_sets_the_h2_zone(capsys, monkeypatch):
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    assert main(["detections", "run", "--events", TIMELINE, "--tz", "Europe/London"]) == 0
    out = capsys.readouterr().out
    assert "H2 work hours 08:00-18:00 Europe/London (from --tz)" in " ".join(out.split())
    assert "judged in UTC" not in out


def test_host_hive_next_to_the_logs_sets_the_h2_zone(capsys, monkeypatch):
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    main(["detections", "run", "--evtx", WIPED])
    out = " ".join(capsys.readouterr().out.split())
    assert "America/New_York (from host registry: Eastern Standard Time)" in out
    assert "judged in UTC" not in out


def test_no_zone_anywhere_warns_that_h2_is_utc(capsys, monkeypatch):
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    main(["detections", "run", "--events", TIMELINE])
    out = " ".join(capsys.readouterr().out.split())
    assert "08:00-18:00 UTC (default" in out and "judged in UTC" in out


# --------------------------------------------------------------------------- disk images
def test_disk_image_given_to_triage_prints_mount_steps(tmp_path, capsys):
    img = tmp_path / "Case-Triage.vhdx"
    img.write_bytes(b"x")
    assert main(["sessions", "-q", "--triage", str(img)]) == 2
    err = capsys.readouterr().err
    assert "is a disk image (.vhdx)" in err and "Mount-DiskImage" in err and "-Access ReadOnly" in err


def test_e01_and_evtx_paths_get_their_own_hints(tmp_path, capsys):
    img = tmp_path / "laptop.E01"
    img.write_bytes(b"x")
    assert main(["tamper", "-q", "--triage", str(img)]) == 2
    assert "Arsenal Image Mounter" in capsys.readouterr().err
    vhd = tmp_path / "logs.vhdx"
    vhd.write_bytes(b"x")
    assert main(["detections", "run", "--evtx", str(vhd)]) == 2
    assert "usbhawk detections run --evtx F:\\" in capsys.readouterr().err


def test_other_file_given_to_triage_asks_for_the_folder(tmp_path, capsys):
    f = tmp_path / "SYSTEM"
    f.write_bytes(b"x")
    assert main(["devices", "-q", "--triage", str(f)]) == 2
    assert "needs the collection FOLDER" in capsys.readouterr().err
