"""C:\\Windows\\INF\\setupapi.dev.log - first-time device install (not purged by PnP cleanup).

Timestamps in this log are LOCAL time. We convert with the host's ActiveTimeBias from the
SYSTEM hive (UTC = local + bias). ActiveTimeBias is the bias at collection time, so events on
the other side of a DST change can be off by an hour; the event is tagged accordingly.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from ..model import FIRST_INSTALL, Event, Evidence
from ..util import parse_usb_instance, parse_usbstor_path

HEADER_RE = re.compile(r"^>>>\s+\[Device Install \((?:Hardware initiated|DiInstallDriver|.*?)\) - (?P<id>.+?)\]\s*$")
START_RE = re.compile(r"^>>>\s+Section start (?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?")


def parse_setupapi(path: str, ev: Evidence) -> int:
    bias = ev.host.active_bias_minutes
    n = 0
    pending = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            h = HEADER_RE.match(line)
            if h:
                pending = h.group("id")
                continue
            s = START_RE.match(line)
            if s and pending:
                local = datetime.strptime(s.group("ts"), "%Y/%m/%d %H:%M:%S")
                approx = bias is None
                ts = (local + timedelta(minutes=bias or 0)).replace(tzinfo=timezone.utc)
                dev = _resolve(ev, pending)
                if dev:
                    ev.add(Event(ts=ts, kind=FIRST_INSTALL, source="setupapi.dev.log", device_key=dev.key,
                                 details={"local_time": s.group("ts"), "tz_assumed_utc": approx,
                                          "instance": pending}))
                    n += 1
                pending = None
    return n


def _resolve(ev: Evidence, instance: str):
    usb = parse_usb_instance(instance)
    if usb and instance.upper().startswith("USB\\"):
        return ev.device(*usb, "setupapi.dev.log")
    hit = parse_usbstor_path(instance)
    if hit:
        return ev.find_by_serial(hit[1])
    return None
