from usbhawk.model import FIRST_INSTALL, Evidence
from usbhawk.parsers.setupapi import parse_setupapi

from conftest import utc

LOG = r""">>>  [Device Install (Hardware initiated) - USB\VID_0951&PID_1666\60A44C413D5FF380E95A0B7D]
>>>  Section start 2026/09/08 09:02:11.482
     ump: Creating Install Process: DrvInst.exe 09:02:11.484
<<<  Section end 2026/09/08 09:02:13.010
>>>  [Device Install (Hardware initiated) - SWD\PRINTENUM\{1234}]
>>>  Section start 2026/09/08 09:05:00.000
"""


def test_setupapi_local_time_to_utc(tmp_path):
    p = tmp_path / "setupapi.dev.log"
    p.write_text(LOG)
    ev = Evidence()
    ev.host.active_bias_minutes = 240          # EDT (UTC-4)
    assert parse_setupapi(str(p), ev) == 1
    e = ev.events[0]
    assert e.kind == FIRST_INSTALL and e.ts == utc(2026, 9, 8, 13, 2, 11)
    assert e.device_key == "VID_0951&PID_1666\\60A44C413D5FF380E95A0B7D"


# ---------------------------------------------------------------- 1.0.2: daylight saving
# Real case: a host in New York collected in November (EST, bias 300) had an install logged on 31 October (EDT).
# Converting with the collection-time bias put it an hour late, which made a ghost "no removal" session.
SUMMER = LOG.replace("2026/09/08 09:02:11", "2026/10/20 13:15:57")


def _parse(tmp_path, text, tz_key, bias):
    p = tmp_path / "setupapi.dev.log"
    p.write_text(text)
    ev = Evidence()
    ev.host.timezone_key, ev.host.active_bias_minutes = tz_key, bias
    parse_setupapi(str(p), ev)
    return ev.events[0]


def test_summer_install_collected_in_winter_uses_summer_offset(tmp_path):
    e = _parse(tmp_path, SUMMER, "Eastern Standard Time", 300)     # collected in EST, logged in EDT
    assert e.ts == utc(2026, 10, 20, 17, 15, 57)                   # 13:15:57 EDT, not 18:15:57
    assert e.details["tz_used"] == "America/New_York" and e.details["tz_assumed_utc"] is False


def test_winter_install_uses_winter_offset(tmp_path):
    e = _parse(tmp_path, SUMMER.replace("2026/10/20", "2026/11/20"), "Eastern Standard Time", 300)
    assert e.ts == utc(2026, 11, 20, 18, 15, 57)


def test_unknown_zone_falls_back_to_active_time_bias(tmp_path):
    e = _parse(tmp_path, SUMMER, "Not A Real Zone", 300)
    assert e.ts == utc(2026, 10, 20, 18, 15, 57)
    assert e.details["tz_used"] == "ActiveTimeBias 300 min"


def test_no_zone_and_no_bias_is_flagged_as_assumed_utc(tmp_path):
    e = _parse(tmp_path, SUMMER, None, None)
    assert e.ts == utc(2026, 10, 20, 13, 15, 57) and e.details["tz_assumed_utc"] is True
