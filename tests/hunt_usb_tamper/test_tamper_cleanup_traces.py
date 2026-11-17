"""Module #3 follow-ups from the USBOblivion lab: traces the cleanup itself leaves behind.

  * MBR volume linking: a UASP disk's volume is named after its MBR disk signature. Reading the signature
    from the Partition/Diagnostic 1006 MBR ties MountedDevices letters and MountPoints2 users to the device.
  * Rule 3 partition_log_gap: the Partition log starts fresh (record 1) or is empty, yet the registry shows
    USB disks arriving after the current Windows build was installed; or record IDs jump.
  * Rule 5 cleanup_tool_execution: BAM recorded a known USB/log cleaner running (USBOblivion survives its
    own wipe there). An orphan last referenced before the tool ran is raised one severity level.
  * expected_artifact_missing: Windows\\INF was collected but setupapi.dev.log is gone.

Fictional host NW-FIN-WS042, user j.doe, SID S-1-5-21-1111111111-2222222222-3333333333-1001.
"""

import os
import struct
from datetime import timedelta

import usbthk.parsers.registry as registry
from usbthk.collect import discover
from usbthk.model import CONNECT, Event
from usbthk.parsers.evtx_logs import parse_partition_diagnostic
from usbthk.model import Evidence
from usbthk.tamper import find_tamper
from usbthk.util import mbr_disk_signature

from conftest import sample, utc
from test_tamper_scenarios import SEEN, SERIAL, by_rule, host, log_cleared, orphan_ref
from test_tamper_usboblivion_lab import FakeHive, FakeKey, mbr_value

SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
INSTALLED = utc(2025, 6, 1, 8, 0)                  # current Windows build installed
TOOL_RAN = SEEN + timedelta(minutes=40)


def mbr_hex(signature: int) -> str:
    mbr = bytearray(512)
    struct.pack_into("<I", mbr, 0x1B8, signature)
    mbr[0x1FE:0x200] = b"\x55\xaa"
    return mbr.hex()


def stored_disk(ev, arrival=SEEN, serial="NA00TEST01"):
    """A UASP USB disk still in Enum, with a registry arrival time (Enum 0066)."""
    dev = ev.device("0BC2", "AB24", f"MSFT30{serial}", "registry:Enum\\USB")
    dev.sources.add("registry:Enum\\SCSI")
    dev.device_class = "uasp"
    ev.add(Event(arrival, CONNECT, "registry:Enum\\SCSI:0066", dev.key))
    return dev


def partition_stats(ev, records, first_id=None, gaps=(), oldest=None, computer="NW-FIN-WS042"):
    ev.parsed.add("evtx:Partition/Diagnostic")
    ev.log_stats["Partition/Diagnostic"] = {
        "records": records, "first_id": first_id, "last_id": (first_id or 0) + records - 1 if records else None,
        "id_gaps": list(gaps), "oldest": oldest, "newest": oldest}
    if records:
        ev.log_computers["Partition/Diagnostic"] = {computer: records}


def bam_run(ev, name="USBOblivion64.exe", ts=TOOL_RAN, sid=SID):
    path = f"\\Device\\HarddiskVolume3\\Users\\j.doe\\Downloads\\{name}"
    ev.executions.append({"path": path, "name": name, "ts": ts, "sid": sid, "user": "j.doe",
                          "source": "registry:BAM"})


# --------------------------------------------------------------------------- MBR volume linking
def test_mbr_signature_is_read_from_the_mbr():
    assert mbr_disk_signature(mbr_hex(0x1A2B3C4D)) == "1a2b3c4d"
    assert mbr_disk_signature(mbr_hex(0)) is None             # GPT protective MBR: no signature
    assert mbr_disk_signature(None) is None


def test_mounted_devices_records_mbr_volumes_with_their_letter():
    ev = Evidence()
    hive = FakeHive({"\\MountedDevices": FakeKey(values=[
        ("\\DosDevices\\F:", mbr_value(0x1A2B3C4D, 0x100000), "REG_BINARY")])})
    registry._parse_mounted_devices(hive, ev)
    assert ev.mbr_volumes == {"{1a2b3c4d-0000-0000-0000-100000000000}":
                              {"signature": "1a2b3c4d", "offset": 0x100000, "letters": {"F:"}}}


def test_mbr_volume_links_letter_and_mountpoints2_user_to_the_disk():
    ev = Evidence()
    dev = stored_disk(ev)
    dev.mbr_signatures.add("1a2b3c4d")
    guid = "{1a2b3c4d-0000-0000-0000-100000000000}"
    ev.mbr_volumes[guid] = {"signature": "1a2b3c4d", "offset": 0x100000, "letters": {"F:"}}
    ev.unlinked.append({"artifact": "MountPoints2", "id_type": "mbr_volume", "id_value": guid,
                        "ref_time": SEEN, "ref_time_scope": "entry", "user": "j.doe", "details": {}})
    registry.link_mbr_volumes(ev)
    assert guid in dev.volume_guids and "F:" in dev.drive_letters and "j.doe" in dev.users
    assert {"registry:MountedDevices", "registry:MountPoints2"} <= dev.sources
    assert ev.unlinked == []                                  # resolved, so no longer unlinked
    mounts = [e for e in ev.events if e.kind == "user_mount"]
    assert len(mounts) == 1 and mounts[0].device_key == dev.key and mounts[0].user == "j.doe"


def test_partition_log_gives_the_disk_signature():
    ev = Evidence()
    parse_partition_diagnostic(sample("Microsoft-Windows-Partition%4Diagnostic.evtx"), ev)
    assert any(d.mbr_signatures for d in ev.devices.values())
    stats = ev.log_stats["Partition/Diagnostic"]
    assert stats["records"] == 40 and stats["first_id"] >= 1 and stats["id_gaps"] == []


# --------------------------------------------------------------------------- rule 3: partition_log_gap
def test_r3_empty_partition_log_with_recent_usb_arrival_is_a_gap():
    ev = host(updates=(INSTALLED,))
    stored_disk(ev)
    partition_stats(ev, records=0)
    f = by_rule(find_tamper(ev))["partition_log_gap"]
    assert len(f) == 1 and f[0].severity == "medium"
    assert "empty" in f[0].why and "MSFT30NA00TEST01" in f[0].why


def test_r3_log_starting_fresh_after_an_arrival_is_a_gap():
    ev = host(updates=(INSTALLED,))
    stored_disk(ev, arrival=SEEN)
    partition_stats(ev, records=12, first_id=1, oldest=SEEN + timedelta(days=3))
    f = by_rule(find_tamper(ev))["partition_log_gap"][0]
    assert "record 1" in f.why and f.evidence["devices"][0]["last_arrival"] == SEEN


def test_r3_rolled_over_log_is_not_a_gap():
    ev = host(updates=(INSTALLED,))
    stored_disk(ev)
    partition_stats(ev, records=500, first_id=4180, oldest=SEEN + timedelta(days=3))   # oldest records dropped
    assert "partition_log_gap" not in by_rule(find_tamper(ev))


def test_r3_arrival_before_the_current_build_is_not_a_gap():
    ev = host(updates=(INSTALLED,))
    stored_disk(ev, arrival=INSTALLED - timedelta(days=30))
    partition_stats(ev, records=0)
    assert "partition_log_gap" not in by_rule(find_tamper(ev))


def test_r3_record_id_jump_is_a_gap():
    ev = host(updates=(INSTALLED,))
    partition_stats(ev, records=60, first_id=1, gaps=[(41, 57)], oldest=INSTALLED)
    f = by_rule(find_tamper(ev))["partition_log_gap"][0]
    assert f.severity == "medium" and "41" in f.why and "57" in f.why


def test_r3_log_from_another_machine_is_skipped():
    ev = host(updates=(INSTALLED,))
    stored_disk(ev)
    partition_stats(ev, records=5, first_id=1, oldest=SEEN + timedelta(days=3), computer="DESKTOP-OTHER1")
    assert "partition_log_gap" not in by_rule(find_tamper(ev))


def test_r3_needs_the_partition_log():
    ev = host(updates=(INSTALLED,))
    stored_disk(ev)
    assert "partition_log_gap" not in by_rule(find_tamper(ev))


# --------------------------------------------------------------------------- rule 5: cleanup_tool_execution
def test_r5_bam_parser_reads_executions():
    ev = Evidence()
    ft = struct.pack("<Q", 134_078_000_000_000_000) + b"\x00" * 16
    path = "\\Device\\HarddiskVolume3\\Users\\j.doe\\Downloads\\USBOblivion64.exe"
    hive = FakeHive({f"\\ControlSet001\\Services\\bam\\State\\UserSettings":
                     FakeKey(subkeys=[FakeKey(SID, values=[(path, ft, "REG_BINARY"),
                                                           ("Version", 1, "REG_DWORD"),
                                                           ("SequenceBlob", ft, "REG_BINARY")])])})
    ev.host.sid_users[SID] = "j.doe"
    registry._parse_bam(hive, "ControlSet001", ev)
    assert len(ev.executions) == 1
    x = ev.executions[0]
    assert x["name"] == "USBOblivion64.exe" and x["user"] == "j.doe" and x["ts"].year == 2025


def test_r5_profile_list_maps_sids_to_users():
    ev = Evidence()
    hive = FakeHive({"\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList": FakeKey(subkeys=[
        FakeKey(SID, values=[("ProfileImagePath", "C:\\Users\\j.doe", "REG_EXPAND_SZ")])])})
    registry._parse_profile_list(hive, ev)
    assert ev.host.sid_users == {SID: "j.doe"}


def test_r5_usboblivion_execution_is_high():
    ev = host()
    bam_run(ev)
    f = by_rule(find_tamper(ev))["cleanup_tool_execution"][0]
    assert f.severity == "high" and "USBOblivion" in f.why and "j.doe" in f.why and f.ts == TOOL_RAN


def test_r5_general_cleaner_is_medium_and_log_clear_after_it_is_noted():
    ev = host()
    bam_run(ev, name="CCleaner64.exe")
    log_cleared(ev, TOOL_RAN + timedelta(seconds=90))
    f = by_rule(find_tamper(ev))["cleanup_tool_execution"][0]
    assert f.severity == "medium" and "cleared" in f.why


def test_r5_ordinary_programs_are_ignored():
    ev = host()
    bam_run(ev, name="notepad.exe")
    bam_run(ev, name="powershell.exe")
    assert find_tamper(ev) == []


def test_r5_cleanup_tool_after_the_reference_raises_the_orphan():
    ev = host()
    orphan_ref(ev)                                   # medium on its own
    bam_run(ev, ts=SEEN + timedelta(days=3))         # far outside the log-clear window, still after use
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert f.severity == "high" and "USBOblivion" in f.why
    assert f.evidence["correlated_cleanup_tool"]["name"] == "USBOblivion64.exe"


def test_r5_cleanup_tool_before_the_reference_does_not_raise():
    ev = host()
    orphan_ref(ev)
    bam_run(ev, ts=SEEN - timedelta(days=1))
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert f.severity == "medium" and f.evidence["correlated_cleanup_tool"] is None


# --------------------------------------------------------------------------- expected_artifact_missing
def test_missing_setupapi_next_to_collected_inf_dir_is_noted(tmp_path):
    inf = tmp_path / "C" / "Windows" / "INF"
    inf.mkdir(parents=True)
    arts = discover(str(tmp_path))
    assert arts.missing == ["setupapi.dev.log"]
    ev = host()
    ev.collection_gaps = list(arts.missing)
    f = by_rule(find_tamper(ev))["expected_artifact_missing"][0]
    assert f.severity == "low" and "setupapi.dev.log" in f.why


def test_present_setupapi_is_not_missing(tmp_path):
    inf = tmp_path / "C" / "Windows" / "INF"
    inf.mkdir(parents=True)
    (inf / "setupapi.dev.log").write_text(">>>  [Device Install]\n", encoding="utf-8")
    assert discover(str(tmp_path)).missing == []
