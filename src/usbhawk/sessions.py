"""Build connect -> remove sessions per device and attach users and file activity.

Why sessions and not devices? "A Kingston stick exists" is inventory. "A never-seen Kingston
stick was connected for 26 minutes after hours while 312 files were written to it, then the
volume was reformatted" is a finding. Sessions are the unit an analyst actually triages.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from .model import (CONNECT, DISCONNECT, FILE_DELETE, FILE_READ, FILE_WRITE, FIRST_INSTALL,
                    LOGOFF, LOGON, MTP, OTHER, UASP, USBSTOR, Event, Evidence, Session)
from .util import iso

STORAGE_CLASSES = {USBSTOR, UASP, MTP}
FILE_KINDS = {FILE_WRITE, FILE_READ, FILE_DELETE}


def _direction(e: Event) -> str | None:
    if e.kind in (CONNECT, FIRST_INSTALL):
        return "in"
    if e.kind == DISCONNECT:
        return "out"
    return None


def _dedupe(events: list[Event], seconds: int) -> list[tuple[str, Event, list[str], object]]:
    """Collapse same-direction events from different artifacts that describe the same moment
    (e.g. Enum\\USB 0066, Enum\\USBSTOR 0066 and 1006 all written within a second).
    Returns (direction, representative_event, sources, earliest_ts)."""
    out: list[list] = []
    for e in events:
        d = _direction(e)
        if d is None:
            continue
        if out and out[-1][0] == d and (e.ts - out[-1][3]).total_seconds() <= seconds:
            prev = out[-1]
            prev[2].append(e.source)
            # prefer the event that carries volume details (1006) as the representative
            if e.details.get("vsns") and not prev[1].details.get("vsns"):
                prev[1] = e
            continue
        out.append([d, e, [e.source], e.ts])
    return [tuple(x) for x in out]


def _layout(e: Event):
    if not e.details.get("capacity"):
        return None
    return (tuple(e.details.get("vsns") or ()), tuple(tuple(p) for p in e.details.get("partitions") or ()))


def build_sessions(ev: Evidence, *, include_all_classes: bool = False, dedupe_seconds: int = 10,
                   open_cap_hours: int = 24) -> list[Session]:
    by_dev: dict[str, list[Event]] = defaultdict(list)
    for e in ev.events:
        if e.device_key:
            by_dev[e.device_key].append(e)

    sessions: list[Session] = []
    for key, events in by_dev.items():
        dev = ev.devices.get(key)
        if dev is None:
            continue
        has_disk_events = any(e.source.startswith("evtx:Partition") for e in events)
        if not include_all_classes and dev.device_class not in STORAGE_CLASSES and not has_disk_events:
            continue
        if dev.device_class == OTHER and has_disk_events:
            dev.device_class = USBSTOR
        events.sort(key=lambda e: e.ts)
        first_install = min((e.ts for e in events if e.kind == FIRST_INSTALL), default=None)

        cur: Session | None = None
        last_in = None
        prev_layout = None
        dev_sessions: list[Session] = []

        def open_session(ts, srcs):
            s = Session(session_id="", host=ev.host.hostname, device=dev, start=ts,
                        start_sources=sorted(set(srcs)), connect_events=1)
            dev_sessions.append(s)
            return s

        for direction, e, srcs, ts in _dedupe(events, dedupe_seconds):
            if direction == "in":
                if cur is not None and last_in and ts - last_in > timedelta(hours=open_cap_hours):
                    cur = None  # missing disconnect; start a fresh session
                if cur is None:
                    cur = open_session(ts, srcs)
                else:
                    cur.connect_events += 1
                last_in = ts
                lay = _layout(e)
                if lay is not None:
                    if prev_layout is not None and lay != prev_layout:
                        cur.reasons.append({"_layout_change": iso(e.ts)})
                    prev_layout = lay
                    for v in e.details.get("vsns") or []:
                        if v not in cur.vsns:
                            cur.vsns.append(v)
                    for f in e.details.get("filesystems") or []:
                        if f and f not in cur.filesystems:
                            cur.filesystems.append(f)
                    cur.capacity_bytes = e.details.get("capacity") or cur.capacity_bytes
            else:
                if cur is None:
                    s = Session(session_id="", host=ev.host.hostname, device=dev, start=None, end=ts,
                                end_sources=sorted(set(srcs)))
                    dev_sessions.append(s)
                else:
                    cur.end = ts
                    cur.end_sources = sorted(set(srcs))
                    cur = None

        for s in dev_sessions:
            if first_install and s.start:
                hi = (s.end or s.start) + timedelta(minutes=2)
                s.first_seen = s.start - timedelta(minutes=2) <= first_install <= hi
        sessions.extend(dev_sessions)

    for s in sessions:
        basis = f"{s.host}|{s.device.key}|{iso(s.start) or iso(s.end)}"
        s.session_id = hashlib.sha1(basis.encode()).hexdigest()[:16]

    sessions.sort(key=lambda s: s.start or s.end)
    _attach_users(ev, sessions)
    _attach_files(ev, sessions, open_cap_hours)
    return sessions


def _window(s: Session, cap_hours: int):
    start = s.start or (s.end - timedelta(minutes=1) if s.end else None)
    end = s.end or (s.start + timedelta(hours=cap_hours) if s.start else None)
    return start, end


def _attach_users(ev: Evidence, sessions: list[Session]) -> None:
    logons: dict[str, list] = {}
    for e in sorted((e for e in ev.events if e.kind in (LOGON, LOGOFF)), key=lambda e: e.ts):
        lid = e.details.get("logon_id") or e.user
        if e.kind == LOGON:
            logons.setdefault(lid, [e.user, e.ts, None])
        elif lid in logons and logons[lid][2] is None:
            logons[lid][2] = e.ts
    for s in sessions:
        start, end = _window(s, 24)
        users = []
        if start:
            for user, lon, loff in logons.values():
                if lon <= end and (loff is None or loff >= start) and user not in users:
                    users.append(user)
        for u in sorted(s.device.users):            # MountPoints2 attribution (USBSTOR only)
            tag = f"{u} (MountPoints2)"
            if not any(x.lower().endswith(u.lower()) for x in users):
                users.append(tag)
        s.users = users


def _attach_files(ev: Evidence, sessions: list[Session], cap_hours: int) -> None:
    file_events = [e for e in ev.events if e.kind in FILE_KINDS]
    if not file_events:
        return
    windows = [(s, *_window(s, cap_hours)) for s in sessions if s.start or s.end]

    def inside(ts):
        return [s for s, a, b in windows if a and b and a <= ts <= b]

    # 4663 gives \Device\HarddiskVolumeN, not a serial. A volume whose activity happens
    # (almost) only while a USB session is open is treated as removable.
    vol_in, vol_all = defaultdict(int), defaultdict(int)
    for e in file_events:
        vol = e.details.get("volume")
        if vol is not None:
            vol_all[vol] += 1
            if inside(e.ts):
                vol_in[vol] += 1
    removable_vols = {v for v, n in vol_all.items() if vol_in[v] and vol_in[v] / n >= 0.8}

    for e in file_events:
        hits = inside(e.ts)
        if not hits:
            continue
        vol = e.details.get("volume")
        letter = e.details.get("drive_letter")
        vsn = e.details.get("vsn")
        if vol is not None and vol not in removable_vols:
            continue
        if vsn:
            hits = [s for s in hits if vsn in s.vsns or vsn in s.device.vsns] or []
        elif letter:
            matched = [s for s in hits if letter in s.device.drive_letters]
            hits = matched or [s for s in hits if not s.device.drive_letters and letter != "C:"]
        if not hits:
            continue
        if len({s.device.key for s in hits}) > 1:
            e.details["ambiguous_device"] = True
        for s in hits:
            s.file_events.append(e)
