"""1.0.1: evidence collected from a running PC is often imperfect. Found on a real KAPE collection:

  * a log copied while open had a zeroed chunk, and the whole Security.evtx was dropped;
  * a malformed record ("System": null) crashed the parser for that file;
  * the SYSTEM hive was dirty (newest changes still in SYSTEM.LOG1/.LOG2), so the drive connected just before
    collection looked wiped (a false orphaned_device_reference);
  * logs from Windows.old carried the PC's setup-time name (WIN-...), reported as a host mismatch with no hint.

Each case here is rebuilt from public samples or the fictional wiped host, never from the case itself.
"""

import json
import shutil
import struct

import usbhawk.parsers.evtx_logs as evtx_logs
from usbhawk import collect, tamper
from usbhawk.model import Evidence
from usbhawk.parsers.evtx_logs import iter_evtx_records, parse_partition_diagnostic
from usbhawk.tamper import find_tamper

from conftest import sample
from test_tamper_cleanup_traces import INSTALLED, partition_stats
from test_tamper_scenarios import by_rule, host
from wiped_host_builder import build_wiped_host

CHUNK = 65536
PARTITION = "Microsoft-Windows-Partition%4Diagnostic.evtx"


def damaged_copy(tmp_path, chunk=1):
    """The public Partition/Diagnostic sample (records 1-14 | 15-34 | 35-40 in chunks 0-2) with one chunk's
    header magic zeroed, as a live copy of an open log can be."""
    out = tmp_path / PARTITION
    shutil.copy(sample(PARTITION), out)
    raw = bytearray(out.read_bytes())
    off = 4096 + chunk * CHUNK
    assert raw[off:off + 8] == b"ElfChnk\x00"
    raw[off:off + 8] = bytes(8)
    out.write_bytes(raw)
    return str(out)


def dirty(path):
    """Make a hive dirty the way Windows leaves it: secondary sequence number behind, checksum still valid."""
    raw = bytearray(path.read_bytes())
    primary = struct.unpack_from("<I", raw, 4)[0]
    struct.pack_into("<I", raw, 8, primary - 1)
    checksum = 0
    for (dword,) in struct.iter_unpack("<I", bytes(raw[:508])):
        checksum ^= dword
    struct.pack_into("<I", raw, 508, checksum)
    path.write_bytes(raw)


# --------------------------------------------------------------------------- damaged event logs
def test_a_damaged_chunk_costs_only_that_chunk(tmp_path):
    damage = {}
    recs = list(iter_evtx_records(damaged_copy(tmp_path), damage))
    ids = sorted(r["event_record_id"] for r in recs)
    assert len(recs) == 20 and ids[0] == 1 and ids[-1] == 40          # chunks 0 and 2 survive
    assert not any(15 <= i <= 34 for i in ids)
    assert damage["skipped"] >= 1 and damage["read"] == 20 and damage["first_error"]


def test_damaged_partition_log_is_read_around_the_damage_and_reported(tmp_path):
    ev = Evidence()
    path = damaged_copy(tmp_path)
    parse_partition_diagnostic(path, ev)
    st = ev.log_stats["Partition/Diagnostic"]
    assert st["records"] == 20 and st["id_gaps"] == [(14, 35)] and st["damaged"] >= 1
    assert any("damaged chunk(s)" in w and path in w for w in ev.warnings)
    assert ev.devices                                                   # its 1006 records still give devices


def test_undamaged_log_reports_no_damage():
    ev = Evidence()
    parse_partition_diagnostic(sample(PARTITION), ev)
    assert ev.log_stats["Partition/Diagnostic"]["damaged"] == 0
    assert not any("damaged" in w for w in ev.warnings)


def test_record_id_jump_in_a_damaged_log_is_low_not_deletion():
    ev = host(updates=(INSTALLED,))
    partition_stats(ev, records=20, first_id=1, gaps=[(14, 35)], oldest=INSTALLED)
    ev.log_stats["Partition/Diagnostic"]["damaged"] = 1
    f = by_rule(find_tamper(ev))["partition_log_gap"][0]
    assert f.severity == "low" and "damage rather than deletion" in f.why and f.evidence["damaged"] == 1


def test_malformed_records_are_skipped_not_fatal(monkeypatch):
    good = {"Event": {"System": {"EventID": 1006, "Computer": "NW-FIN-WS042",
                                 "TimeCreated": {"#attributes": {"SystemTime": "2026-10-30T21:14:00Z"}}},
                      "EventData": {"Capacity": 0}}}
    fake = [{"data": '{"Event": {"System": null, "EventData": {"EventID": 1006}}}',
             "event_record_id": 1, "timestamp": "2026-10-30T21:13:00Z"},
            {"data": '{"Event": null, "EventID": 1006}', "event_record_id": 2, "timestamp": "2026-10-30T21:13:30Z"},
            {"data": json.dumps(good), "event_record_id": 3, "timestamp": "2026-10-30T21:14:00Z"}]
    monkeypatch.setattr(evtx_logs, "iter_evtx_records", lambda path, damage=None: iter(fake))
    got = list(evtx_logs._records("x.evtx", {1006}))
    assert len(got) == 2                                    # "System": null kept with an empty System
    assert got[0][1] == {} and got[1][1]["Computer"] == "NW-FIN-WS042"


# --------------------------------------------------------------------------- dirty hives
def test_public_dirty_hive_is_flagged():
    ev = Evidence()
    from usbhawk.parsers.registry import parse_system
    parse_system(sample("SYSTEM_WIN_10_1709"), ev)          # header sequence numbers 4317 / 4316
    assert ev.host.dirty_hives == ["SYSTEM"]
    assert any("is dirty" in w and "rla.exe" in w for w in ev.warnings)


def test_public_clean_hive_is_not_flagged():
    ev = Evidence()
    from usbhawk.parsers.registry import parse_system
    parse_system(sample("SYSTEM"), ev)
    assert ev.host.dirty_hives == [] and not any("is dirty" in w for w in ev.warnings)


def test_orphans_on_a_dirty_system_hive_carry_a_caution(tmp_path):
    clean, messy = tmp_path / "clean", tmp_path / "dirty"
    build_wiped_host(clean)
    build_wiped_host(messy)
    dirty(messy / "Windows/System32/config/SYSTEM")
    (messy / "Windows/System32/config/SYSTEM.LOG1").write_bytes(b"")

    ev = collect.load(collect.discover(str(clean)), verbose=lambda *_: None)
    orphans = [f for f in tamper.find_tamper(ev) if f.rule == "orphaned_device_reference"]
    assert orphans and not any("dirty" in f.why for f in orphans)

    ev = collect.load(collect.discover(str(messy)), verbose=lambda *_: None)
    assert ev.host.dirty_hives == ["SYSTEM"]
    assert any("SYSTEM.LOG1 are next to it" in w for w in ev.warnings)
    orphans = [f for f in tamper.find_tamper(ev) if f.rule == "orphaned_device_reference"]
    assert orphans and all("SYSTEM hive is dirty" in f.why and f.evidence["system_hive_dirty"] for f in orphans)


# --------------------------------------------------------------------------- Windows.old
def test_windows_old_logs_are_labelled_and_explain_setup_time_names(tmp_path):
    build_wiped_host(tmp_path)
    old = tmp_path / "Windows.old/Windows/System32/winevt/Logs"
    old.mkdir(parents=True)
    shutil.copy(sample(PARTITION), old / PARTITION)
    said = []
    ev = collect.load(collect.discover(str(tmp_path)), verbose=said.append)
    assert ev.host.windows_old_logs
    assert any("[Windows.old: previous installation]" in s for s in said)
    mismatch = [f for f in tamper.find_tamper(ev) if f.rule == "evidence_host_mismatch"]
    assert mismatch and any("Windows.old" in f.why for f in mismatch)


def test_no_windows_old_note_without_windows_old(tmp_path):
    build_wiped_host(tmp_path)
    ev = collect.load(collect.discover(str(tmp_path)), verbose=lambda *_: None)
    assert not ev.host.windows_old_logs
    assert not any("Windows.old" in f.why for f in tamper.find_tamper(ev))
