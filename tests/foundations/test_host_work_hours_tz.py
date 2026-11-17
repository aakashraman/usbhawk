"""Work-hours timezone auto-detected from the host's own registry.

Timestamps are always stored/output in UTC. Only the off_hours *judgement* needs the employee's
local clock. Priority: --tz > scoring.toml > host registry (TimeZoneKeyName) > UTC with a warning.
"""

from zoneinfo import ZoneInfo

import pytest

from usbthk.cli import main
from usbthk.model import CONNECT, DISCONNECT, Event, Evidence
from usbthk.scoring import apply_host_timezone, load_config, score_sessions
from usbthk.sessions import build_sessions
from usbthk.tzmap import WINDOWS_TO_IANA, windows_to_iana

from conftest import sample, utc


# --------------------------------------------------------------------------- mapping table
@pytest.mark.parametrize("win, iana", [
    ("Eastern Standard Time", "America/New_York"),
    ("Pacific Standard Time", "America/Los_Angeles"),
    ("India Standard Time", "Asia/Kolkata"),
    ("GMT Standard Time", "Europe/London"),
    ("W. Europe Standard Time", "Europe/Berlin"),
    ("AUS Eastern Standard Time", "Australia/Sydney"),
    ("UTC", "Etc/UTC"),
])
def test_common_windows_zones_map_to_iana(win, iana):
    assert windows_to_iana(win) == iana


def test_every_mapped_zone_exists_in_tz_database():
    bad = [f"{w} -> {i}" for w, i in WINDOWS_TO_IANA.items() if not _resolves(i)]
    assert not bad, f"unresolvable IANA names: {bad}"


def _resolves(name):
    try:
        ZoneInfo(name)
        return True
    except Exception:
        return False


def test_unknown_or_unresolved_names_return_none():
    assert windows_to_iana(None) is None
    assert windows_to_iana("") is None
    assert windows_to_iana("@tzres.dll,-112") is None      # StandardName resource ref (Vista+)
    assert windows_to_iana("Mars Standard Time") is None


def test_registry_padding_is_tolerated():
    assert windows_to_iana("  Eastern Standard Time\x00") == "America/New_York"


# --------------------------------------------------------------------------- priority order
def test_host_registry_used_when_nothing_else_given():
    cfg, warning = apply_host_timezone(load_config(), "Eastern Standard Time")
    assert cfg["work_hours"]["timezone"] == "America/New_York"
    assert cfg["work_hours"]["timezone_source"] == "host registry: Eastern Standard Time"
    assert warning is None


def test_cli_tz_beats_host_registry():
    cfg, warning = apply_host_timezone(load_config(timezone="Asia/Tokyo"), "Eastern Standard Time")
    assert cfg["work_hours"]["timezone"] == "Asia/Tokyo"
    assert cfg["work_hours"]["timezone_source"] == "--tz"
    assert warning is None


def test_config_file_beats_host_registry(tmp_path):
    f = tmp_path / "scoring.toml"
    f.write_text('[work_hours]\ntimezone = "Europe/London"\n', encoding="utf-8")
    cfg, _ = apply_host_timezone(load_config(str(f)), "Eastern Standard Time")
    assert cfg["work_hours"]["timezone"] == "Europe/London"
    assert cfg["work_hours"]["timezone_source"] == "config"


@pytest.mark.parametrize("host_tz", [None, "@tzres.dll,-112", "Mars Standard Time"])
def test_falls_back_to_utc_with_warning(host_tz):
    cfg, warning = apply_host_timezone(load_config(), host_tz)
    assert cfg["work_hours"]["timezone"] == "UTC"
    assert cfg["work_hours"]["timezone_source"] == "default"
    assert warning and "UTC" in warning and "--tz" in warning


def test_apply_host_timezone_does_not_mutate_input():
    base = load_config()
    apply_host_timezone(base, "Eastern Standard Time")
    assert base["work_hours"]["timezone"] == "UTC"


# --------------------------------------------------------------------------- scoring end to end
def _session_at(start):
    ev = Evidence()
    ev.host.hostname = "NW-FIN-WS042"
    ev.host.timezone_key = "Eastern Standard Time"
    dev = ev.device("0951", "1666", "60A44C413D5FF380E95A0B7D", "test")
    dev.device_class = "usbstor"
    ev.add(Event(start, CONNECT, "registry:Enum\\USBSTOR:0066", dev.key))
    ev.add(Event(start.replace(minute=start.minute + 5), DISCONNECT, "registry:Enum\\USBSTOR:0067", dev.key))
    return ev, build_sessions(ev)


def test_2pm_new_york_is_not_flagged_when_tz_comes_from_host():
    # Mon 2026-11-16 19:00Z = 14:00 EST. Judged in UTC it would be 19:00 -> false off_hours alarm.
    ev, sessions = _session_at(utc(2026, 11, 16, 19, 0))
    cfg, _ = apply_host_timezone(load_config(), ev.host.timezone_key)
    s = score_sessions(sessions, cfg)[0]
    assert not [r for r in s.reasons if r["rule"] == "off_hours"]


def test_off_hours_reason_shows_utc_local_and_tz_source():
    # Mon 2026-11-16 10:30Z = 05:30 EST -> off hours.
    ev, sessions = _session_at(utc(2026, 11, 16, 10, 30))
    cfg, _ = apply_host_timezone(load_config(), ev.host.timezone_key)
    why = [r for r in score_sessions(sessions, cfg)[0].reasons if r["rule"] == "off_hours"][0]["why"]
    assert "2026-11-16 10:30Z" in why                     # the UTC fact
    assert "05:30 America/New_York" in why                # the local reasoning
    assert "tz from host registry: Eastern Standard Time" in why


# --------------------------------------------------------------------------- real sample + CLI
def test_win7_sample_host_timezone_resolves():
    from usbthk.parsers.registry import parse_system
    ev = Evidence()
    parse_system(sample("SYSTEM"), ev)
    assert windows_to_iana(ev.host.timezone_key) == "America/New_York"


def test_cli_without_tz_uses_host_registry(capsys):
    sample("SYSTEM")  # skip if samples are not downloaded
    from conftest import DATA
    assert main(["sessions", "--triage", DATA]) == 0
    out = capsys.readouterr()
    text = out.out + out.err
    assert "America/New_York" in text and "host registry" in text
