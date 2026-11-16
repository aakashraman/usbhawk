"""One focused test per scoring rule, each with a 'fires' and a 'just below threshold' case.

The end-to-end insider scenario lives in test_sessions_scoring.py; this file pins down each rule's
threshold in isolation so a config or code change that moves a boundary is caught.
Fictional host NW-FIN-WS042, Monday 2026-11-16 15:00 UTC = 10:00 New York (inside work hours,
so off_hours never adds noise here).
"""

from datetime import timedelta

import pytest

from usbthk.model import CONNECT, DISCONNECT, FILE_DELETE, FILE_WRITE, Event, Evidence
from usbthk.scoring import load_config, score_sessions
from usbthk.sessions import build_sessions

from conftest import utc

START = utc(2026, 11, 16, 15, 0)


def make(minutes=5, serial="60A44C413D5FF380E95A0B7D", device_class="usbstor", capacity=None,
         writes=(), deletes=0, vsns_per_connect=None):
    """Build one session. writes = list of (filename, size_bytes)."""
    ev = Evidence()
    ev.host.hostname = "NW-FIN-WS042"
    dev = ev.device("0951", "1666", serial, "test")
    dev.device_class = device_class
    dev.drive_letters.add("F:")
    dev.capacity_bytes = capacity
    if vsns_per_connect:
        for i, vsn in enumerate(vsns_per_connect):
            ev.add(Event(START + timedelta(minutes=i * 15), CONNECT, "evtx:Partition/Diagnostic:1006", dev.key,
                         details={"capacity": 31_000_000_000, "vsns": [vsn], "filesystems": ["exFAT"],
                                  "partitions": [[0, "0x07", 2048, 60435444]]}))
            ev.add(Event(START + timedelta(minutes=i * 15 + 5), DISCONNECT, "registry:Enum\\USBSTOR:0067", dev.key))
    else:
        ev.add(Event(START, CONNECT, "registry:Enum\\USBSTOR:0066", dev.key))
        ev.add(Event(START + timedelta(minutes=minutes), DISCONNECT, "registry:Enum\\USBSTOR:0067", dev.key))
    t = START + timedelta(seconds=30)
    for name, size in writes:
        ev.add(Event(t, FILE_WRITE, "csv:mde", user="j.doe",
                     details={"path": f"F:\\{name}", "drive_letter": "F:", "size": size}))
    for i in range(deletes):
        ev.add(Event(t, FILE_DELETE, "csv:mde", user="j.doe",
                     details={"path": f"F:\\old_{i}.docx", "drive_letter": "F:"}))
    return build_sessions(ev)


def rules(sessions, **cfg):
    cfg.setdefault("timezone", "America/New_York")
    return [{r["rule"] for r in s.reasons} for s in score_sessions(sessions, load_config(**cfg))]


def rules_one(sessions, **cfg):
    out = rules(sessions, **cfg)
    assert len(out) == 1
    return out[0]


# --------------------------------------------------------------------------- baseline
def test_quiet_session_scores_zero():
    s = score_sessions(make(), load_config(timezone="America/New_York"))[0]
    assert s.reasons == [] and s.score == 0 and s.severity == "info"


# --------------------------------------------------------------------------- file activity
def test_file_writes_fires_on_one_write():
    assert "file_writes" in rules_one(make(writes=[("a.docx", 1000)]))


def test_bulk_transfer_by_file_count():
    assert "bulk_transfer" in rules_one(make(writes=[(f"f{i}.docx", 10) for i in range(50)]))
    assert "bulk_transfer" not in rules_one(make(writes=[(f"f{i}.docx", 10) for i in range(49)]))


def test_bulk_transfer_by_bytes():
    assert "bulk_transfer" in rules_one(make(writes=[("big.bin", 500 * 1024 * 1024)]))
    assert "bulk_transfer" not in rules_one(make(writes=[("big.bin", 500 * 1024 * 1024 - 1)]))


@pytest.mark.parametrize("name", ["loot.zip", "x.7z", "y.RAR", "mail.pst", "vault.kdbx", "disk.iso"])
def test_archive_written(name):
    assert "archive_written" in rules_one(make(writes=[(name, 10)]))


def test_archive_not_fired_for_documents():
    assert "archive_written" not in rules_one(make(writes=[("report.docx", 10), ("zip_notes.txt", 10)]))


def test_mass_delete_on_device():
    assert "mass_delete_on_device" in rules_one(make(deletes=50))
    assert "mass_delete_on_device" not in rules_one(make(deletes=49))


# --------------------------------------------------------------------------- device properties
def test_mtp_device():
    assert "mtp_device" in rules_one(make(device_class="mtp"))
    assert "mtp_device" not in rules_one(make(device_class="usbstor"))


def test_high_capacity():
    assert "high_capacity" in rules_one(make(capacity=256_000_000_000))
    assert "high_capacity" not in rules_one(make(capacity=255_999_999_999))


def test_long_session():
    assert "long_session" in rules_one(make(minutes=30))
    assert "long_session" not in rules_one(make(minutes=29))


def test_no_hardware_serial():
    # Windows invents an id like 7&2A1B3C4D&0 when the device has no iSerialNumber.
    assert "no_hardware_serial" in rules_one(make(serial="7&2A1B3C4D&0"))
    assert "no_hardware_serial" not in rules_one(make(serial="60A44C413D5FF380E95A0B7D"))


def test_reformat_between_sessions_via_new_vsn():
    # Two separate connects of the same stick with different volume serials = reformatted in between.
    scored = score_sessions(make(vsns_per_connect=["8E2C41D7", "11223344"]),
                            load_config(timezone="America/New_York"))
    first, second = sorted(scored, key=lambda s: s.start)   # output is sorted by score, not time
    assert "reformat_or_repartition" not in {r["rule"] for r in first.reasons}   # nothing to compare yet
    assert "reformat_or_repartition" in {r["rule"] for r in second.reasons}
    assert second.vsns == ["11223344"]


# --------------------------------------------------------------------------- context lists
def test_watchlist_matches_domain_qualified_user():
    sessions = make(writes=[("a.docx", 10)])
    assert "watchlist_user" in rules_one(sessions, watchlist_users=["J.DOE"])     # case-insensitive
    assert "watchlist_user" not in rules_one(make(writes=[("a.docx", 10)]), watchlist_users=["a.smith"])


def test_allowlist_never_goes_below_zero():
    s = score_sessions(make(), load_config(timezone="America/New_York",
                                           allowlist_serials=["60A44C413D5FF380E95A0B7D"]))[0]
    assert {r["rule"] for r in s.reasons} == {"allowlisted_device"}
    assert s.score == 0


# --------------------------------------------------------------------------- severity bands + contract
@pytest.mark.parametrize("points, severity", [(14, "info"), (15, "low"), (39, "low"),
                                              (40, "medium"), (69, "medium"), (70, "high")])
def test_severity_boundaries(points, severity):
    cfg = load_config(timezone="America/New_York", weights={"file_writes": points})
    s = score_sessions(make(writes=[("a.docx", 10)]), cfg)[0]
    assert s.score == points and s.severity == severity


def test_score_is_capped_at_100():
    cfg = load_config(timezone="America/New_York", weights={"file_writes": 90, "mtp_device": 90})
    s = score_sessions(make(device_class="mtp", writes=[("a.docx", 10)]), cfg)[0]
    assert s.score == 100


def test_disabling_a_rule_with_zero_weight():
    cfg = load_config(timezone="America/New_York", weights={"file_writes": 0})
    s = score_sessions(make(writes=[("a.docx", 10)]), cfg)[0]
    assert "file_writes" not in {r["rule"] for r in s.reasons}


def test_every_point_has_a_reason():
    """Contract from CLAUDE.md: a score without reasons is a bug."""
    sessions = make(minutes=45, device_class="mtp", capacity=512_000_000_000, serial="7&2A1B3C4D&0",
                    writes=[(f"f{i}.docx", 20_000_000) for i in range(60)] + [("out.7z", 10)], deletes=60)
    s = score_sessions(sessions, load_config(timezone="America/New_York", watchlist_users=["j.doe"]))[0]
    assert len(s.reasons) >= 9
    for r in s.reasons:
        assert set(r) == {"rule", "points", "why"}
        assert isinstance(r["points"], int) and r["points"] != 0 and r["why"].strip()
    assert s.score == min(100, sum(r["points"] for r in s.reasons))
