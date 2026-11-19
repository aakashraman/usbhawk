"""C:\\Windows\\INF\\setupapi.dev.log - first-time device install (not purged by PnP cleanup).

Timestamps in this log are LOCAL time. We convert with the host's time zone from the SYSTEM hive
(TimeZoneKeyName), with its daylight-saving rules, so an install logged in summer time and collected
in winter is not an hour off. Only when the zone is unknown do we fall back to ActiveTimeBias (the
offset at collection time, UTC = local + bias), and the event says so in details["tz_used"].
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from ..model import FIRST_INSTALL, Event, Evidence
from ..tzmap import windows_to_iana
from ..util import parse_usb_instance, parse_usbstor_path

HEADER_RE = re.compile(r"^>>>\s+\[Device Install \((?:Hardware initiated|DiInstallDriver|.*?)\) - (?P<id>.+?)\]\s*$")
START_RE = re.compile(r"^>>>\s+Section start (?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?")


def local_to_utc(local: datetime, timezone_key: str | None, bias: int | None) -> tuple[datetime, str]:
    """Convert a naive local time from the host to UTC; returns (utc, how it was converted)."""
    iana = windows_to_iana(timezone_key)
    if iana:
        try:
            zone = ZoneInfo(iana)
        except (ZoneInfoNotFoundError, ValueError):
            zone = None
        if zone is not None:
            return local.replace(tzinfo=zone).astimezone(timezone.utc), iana
    if bias is not None:
        return (local + timedelta(minutes=bias)).replace(tzinfo=timezone.utc), f"ActiveTimeBias {bias} min"
    return local.replace(tzinfo=timezone.utc), "assumed UTC"


def parse_setupapi(path: str, ev: Evidence) -> int:
    tz_key, bias = ev.host.timezone_key, ev.host.active_bias_minutes
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
                ts, tz_used = local_to_utc(local, tz_key, bias)
                dev = _resolve(ev, pending)
                if dev:
                    ev.add(Event(ts=ts, kind=FIRST_INSTALL, source="setupapi.dev.log", device_key=dev.key,
                                 details={"local_time": s.group("ts"), "tz_used": tz_used,
                                          "tz_assumed_utc": tz_used == "assumed UTC",
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
