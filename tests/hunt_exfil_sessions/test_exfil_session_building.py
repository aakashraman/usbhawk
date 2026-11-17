"""Synthetic insider-exfil scenario that exercises every scoring rule end to end."""

import csv

from usbhawk.model import (CONNECT, DISCONNECT, FILE_WRITE, FIRST_INSTALL, LOGOFF, LOGON, Event,
                          Evidence)
from usbhawk.parsers.file_events import load_file_events
from usbhawk.scoring import load_config, score_sessions
from usbhawk.sessions import build_sessions

from conftest import utc

SERIAL = "60A44C413D5FF380E95A0B7D"


def scenario():
    ev = Evidence()
    ev.host.hostname = "NW-FIN-WS042"
    dev = ev.device("0951", "1666", SERIAL, "test")
    dev.device_class = "usbstor"
    dev.drive_letters.add("F:")
    k = dev.key
    # Logon session for j.doe covering the evening
    ev.add(Event(utc(2026, 10, 30, 20, 50), LOGON, "test", user="NW\\j.doe", details={"logon_id": "0x1"}))
    ev.add(Event(utc(2026, 10, 30, 22, 30), LOGOFF, "test", user="NW\\j.doe", details={"logon_id": "0x1"}))
    # First install + connect from three artifacts within a second (must dedupe to one session)
    ev.add(Event(utc(2026, 10, 30, 21, 14, 52), FIRST_INSTALL, "registry:Enum\\USB:0064", k))
    ev.add(Event(utc(2026, 10, 30, 21, 14, 52), CONNECT, "registry:Enum\\USBSTOR:0066", k))
    ev.add(Event(utc(2026, 10, 30, 21, 14, 53), CONNECT, "evtx:Partition/Diagnostic:1006", k,
                 details={"capacity": 30943995904, "vsns": ["8E2C41D7"], "filesystems": ["exFAT"],
                          "partitions": [[0, "0x07", 2048, 60435444]]}))
    # Reformat mid-session: new VSN appears
    ev.add(Event(utc(2026, 10, 30, 21, 38, 0), CONNECT, "evtx:Partition/Diagnostic:1006", k,
                 details={"capacity": 30943995904, "vsns": ["11223344"], "filesystems": ["exFAT"],
                          "partitions": [[0, "0x07", 2048, 60435444]]}))
    ev.add(Event(utc(2026, 10, 30, 21, 41, 7), DISCONNECT, "registry:Enum\\USBSTOR:0067", k))
    ev.add(Event(utc(2026, 10, 30, 21, 41, 8), DISCONNECT, "evtx:Partition/Diagnostic:1006", k,
                 details={"capacity": 0}))
    return ev, dev


def write_mde_csv(tmp_path):
    p = tmp_path / "mde.csv"
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["Timestamp", "ActionType", "FolderPath", "FileSize", "InitiatingProcessAccountName"])
        for i in range(60):
            w.writerow([f"2026-10-30T21:2{i % 10}:{i % 60:02d}Z", "FileCreated",
                        f"F:\\Q4_Forecast\\doc_{i}.xlsx", 12_000_000, "j.doe"])
        w.writerow(["2026-10-30T21:30:00Z", "FileCreated", "F:\\finance_share.7z", 900_000_000, "j.doe"])
        w.writerow(["2026-10-30T21:30:00Z", "FileCreated", "C:\\Users\\j.doe\\notes.txt", 10, "j.doe"])
    return str(p)


def test_one_session_with_dedupe_and_duration():
    ev, _ = scenario()
    sessions = build_sessions(ev)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.start == utc(2026, 10, 30, 21, 14, 52)
    assert s.end == utc(2026, 10, 30, 21, 41, 7)
    assert round(s.duration_seconds) == 26 * 60 + 15
    assert s.first_seen
    assert s.vsns == ["8E2C41D7", "11223344"]
    assert s.users == ["NW\\j.doe"]


def test_full_scoring_with_edr_file_events(tmp_path):
    ev, _ = scenario()
    assert load_file_events(write_mde_csv(tmp_path), ev) == 62
    cfg = load_config(timezone="America/New_York", watchlist_users=["j.doe"],
                      work_hours={"end_hour": 17})   # 17:14 EDT is after a 08-17 day
    s = score_sessions(build_sessions(ev), cfg)[0]
    rules = {r["rule"] for r in s.reasons}
    assert {"first_seen_device", "off_hours", "file_writes", "bulk_transfer", "archive_written",
            "reformat_or_repartition", "watchlist_user"} <= rules
    # the C:\ file must not be attributed to the USB device
    assert all(e.details["path"].startswith("F:") for e in s.file_events)
    assert len(s.file_events) == 61
    assert s.score == 100 and s.severity == "high"


def test_allowlist_pulls_score_down():
    ev, _ = scenario()
    s = score_sessions(build_sessions(ev), load_config(allowlist_serials=[SERIAL]))[0]
    assert any(r["rule"] == "allowlisted_device" for r in s.reasons)
    assert s.score < 50


def test_4663_volume_inference():
    """Security 4663 has no serial; a volume active only during the session is removable."""
    ev, _ = scenario()
    for minute in range(20, 25):
        ev.add(Event(utc(2026, 10, 30, 21, minute), FILE_WRITE, "evtx:Security:4663", user="j.doe",
                     details={"path": r"\Device\HarddiskVolume12\Q4\a.docx", "volume": 12}))
    for hour in (9, 10, 11, 21):   # system volume: busy all day, including during the session
        ev.add(Event(utc(2026, 10, 30, hour, 25), FILE_WRITE, "evtx:Security:4663", user="j.doe",
                     details={"path": r"\Device\HarddiskVolume3\Windows\x.log", "volume": 3}))
    s = build_sessions(ev)[0]
    assert {e.details["volume"] for e in s.file_events} == {12}


def test_orphan_and_missing_disconnect():
    ev = Evidence()
    dev = ev.device("0781", "5530", "ABC", "t")
    dev.device_class = "usbstor"
    ev.add(Event(utc(2026, 1, 1, 10), CONNECT, "t", dev.key))
    ev.add(Event(utc(2026, 1, 5, 10), CONNECT, "t", dev.key))      # >24h later, no disconnect between
    ev.add(Event(utc(2026, 1, 5, 11), DISCONNECT, "t", dev.key))
    s = build_sessions(ev)
    assert len(s) == 2 and s[0].end is None and s[1].end == utc(2026, 1, 5, 11)
