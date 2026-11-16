"""Work-hours timezone handling.

Regression: on Windows there is no system IANA database, so ZoneInfo("America/New_York") fails
unless the `tzdata` package is installed. v0.1 silently fell back to UTC while still labelling
the time as New York, so the off-hours rule fired (or didn't) on the wrong clock.
The times below are chosen so UTC and New York disagree about work hours.
"""

import pytest

from usbthk.model import CONNECT, DISCONNECT, Event, Evidence
from usbthk.scoring import load_config, score_sessions
from usbthk.sessions import build_sessions

from conftest import utc


def one_session(start, end):
    ev = Evidence()
    ev.host.hostname = "NW-FIN-WS042"
    dev = ev.device("0951", "1666", "60A44C413D5FF380E95A0B7D", "test")
    dev.device_class = "usbstor"
    ev.add(Event(start, CONNECT, "registry:Enum\\USBSTOR:0066", dev.key))
    ev.add(Event(end, DISCONNECT, "registry:Enum\\USBSTOR:0067", dev.key))
    return build_sessions(ev)


def off_hours(sessions, tz):
    s = score_sessions(sessions, load_config(timezone=tz))[0]
    return [r for r in s.reasons if r["rule"] == "off_hours"]


def test_afternoon_in_new_york_is_work_hours():
    # Mon 2026-11-16 20:00 UTC = 15:00 EST -> inside 08-18. UTC fallback would wrongly flag it.
    assert off_hours(one_session(utc(2026, 11, 16, 20, 0), utc(2026, 11, 16, 20, 10)),
                     "America/New_York") == []


def test_early_morning_in_new_york_is_off_hours_with_local_time_in_reason():
    # Mon 2026-11-16 12:30 UTC = 07:30 EST -> before 08:00. UTC fallback would miss it.
    hits = off_hours(one_session(utc(2026, 11, 16, 12, 30), utc(2026, 11, 16, 12, 40)),
                     "America/New_York")
    assert len(hits) == 1
    assert "07:30" in hits[0]["why"] and "America/New_York" in hits[0]["why"]


def test_unknown_timezone_fails_loudly():
    with pytest.raises(ValueError, match="Mars/Olympus_Mons"):
        load_config(timezone="Mars/Olympus_Mons")


# Each case is picked so that a wrong zone, a wrong DST offset or a wrong weekday flips the answer.
# Default work hours: 08:00 (inclusive) to 18:00 (exclusive), Monday-Friday.
@pytest.mark.parametrize("start, tz, expect_off, local_text", [
    # DST: spring forward. Mon 2026-03-09 12:30Z = 08:30 EDT (UTC-4). A stale EST offset gives 07:30.
    (utc(2026, 3, 9, 12, 30), "America/New_York", False, None),
    # DST: fall back. Mon 2026-11-02 12:30Z = 07:30 EST (UTC-5). A stale EDT offset gives 08:30.
    (utc(2026, 11, 2, 12, 30), "America/New_York", True, "Mon 2026-11-02 07:30"),
    # Weekday rollover: Sun 2026-11-15 23:30Z is already Mon 08:30 in Tokyo -> work hours.
    (utc(2026, 11, 15, 23, 30), "Asia/Tokyo", False, None),
    # ...and Fri 2026-11-20 23:30Z is Sat 08:30 in Tokyo -> weekend, although Friday in UTC.
    (utc(2026, 11, 20, 23, 30), "Asia/Tokyo", True, "Sat 2026-11-21 08:30"),
    # Half-hour offset: Mon 02:15Z = 07:45 IST (off), Mon 02:45Z = 08:15 IST (in).
    (utc(2026, 11, 16, 2, 15), "Asia/Kolkata", True, "07:45"),
    (utc(2026, 11, 16, 2, 45), "Asia/Kolkata", False, None),
    # Boundaries: 08:00 local is inside (inclusive), 18:00 local is outside (exclusive).
    (utc(2026, 11, 16, 13, 0), "America/New_York", False, None),
    (utc(2026, 11, 16, 23, 0), "America/New_York", True, "18:00"),
])
def test_work_hours_edge_cases(start, tz, expect_off, local_text):
    hits = off_hours(one_session(start, start.replace(minute=start.minute + 5)), tz)
    assert bool(hits) is expect_off
    if local_text:
        assert local_text in hits[0]["why"]


def test_config_file_timezone_and_cli_override(tmp_path):
    cfg_file = tmp_path / "scoring.toml"
    cfg_file.write_text('[work_hours]\ntimezone = "Asia/Tokyo"\n', encoding="utf-8")
    assert load_config(str(cfg_file))["work_hours"]["timezone"] == "Asia/Tokyo"
    # --tz on the command line wins over the file
    assert load_config(str(cfg_file), timezone="America/New_York")["work_hours"]["timezone"] == "America/New_York"


def test_bad_timezone_in_config_file_fails_loudly(tmp_path):
    cfg_file = tmp_path / "scoring.toml"
    cfg_file.write_text('[work_hours]\ntimezone = "Eastern Standard Time"\n', encoding="utf-8")
    # A Windows zone name (what the registry stores) is not an IANA name: must error, not fall back.
    with pytest.raises(ValueError, match="Eastern Standard Time"):
        load_config(str(cfg_file))


def test_shipped_example_config_loads():
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "config", "scoring.toml")
    assert load_config(path)["work_hours"]["timezone"] == "America/New_York"
