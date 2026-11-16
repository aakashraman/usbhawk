from usbthk.model import FIRST_INSTALL, Evidence
from usbthk.parsers.setupapi import parse_setupapi

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
