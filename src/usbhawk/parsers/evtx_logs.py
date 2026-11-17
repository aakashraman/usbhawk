"""Windows event log parsers (Rust-backed `evtx` bindings, fast on large Security logs).

  Microsoft-Windows-Partition/Diagnostic  1006       connect/disconnect, VSN, capacity
  Security                                 6416       device recognised (every plug-in)
                                           4663/4656  removable storage object access
                                           4624/4634/4647/4800/4801  user sessions
  System (UserPnp)                         20001/20003 first-time driver install
  Security / System (Eventlog)             1102 / 104  log cleared (anti-forensics, module #3)
Every record's Computer name is counted in Evidence.log_computers (mixed-host evidence check).
"""

from __future__ import annotations

import json
import logging
import re

from evtx import PyEvtxParser

from ..model import (CONNECT, DISCONNECT, FILE_DELETE, FILE_READ, FILE_WRITE, FIRST_INSTALL,
                     LOG_CLEARED, LOGOFF, LOGON, Event, Evidence)
from ..util import (fs_from_vbr, mbr_disk_signature, mbr_partitions, parse_usb_instance, parse_usbstor_path,
                    to_utc, vsn_from_vbr)

log = logging.getLogger(__name__)

EID_RE = re.compile(r'"EventID":\s*(?:\{[^}]*"#text":\s*)?(\d+)')
INTERACTIVE_LOGON_TYPES = {2, 7, 10, 11}
SKIP_USERS = re.compile(r"^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON|DWM-\d+|UMFD-\d+|-)$|\$$", re.I)

# 4663 AccessList tokens / AccessMask bits
WRITE_TOKENS = ("%%4417", "%%4418", "WriteData", "AppendData", "AddFile", "AddSubdirectory")
DELETE_TOKENS = ("%%1537", "DELETE")
VOLUME_RE = re.compile(r"\\Device\\HarddiskVolume(\d+)", re.I)


def _records(path: str, wanted: set[int], stats: dict | None = None):
    """Yield (event_id, system, eventdata) for records whose EventID is in `wanted`.

    If `stats` is given it is filled with every record's ID and time (wanted or not), for gap detection.
    """
    parser = PyEvtxParser(path)
    ids, times = [], []
    for rec in parser.records_json():
        if stats is not None:
            ids.append(rec.get("event_record_id"))
            times.append(to_utc(rec.get("timestamp")))
        data = rec["data"]
        m = EID_RE.search(data)
        if not m or int(m.group(1)) not in wanted:
            continue
        try:
            evt = json.loads(data)["Event"]
        except (ValueError, KeyError):
            continue
        system = evt.get("System", {})
        body = evt.get("EventData") or evt.get("UserData") or {}
        if not isinstance(body, dict):
            body = {"_raw": body}
        yield int(m.group(1)), system, body, rec.get("timestamp")
    if stats is not None:
        stats.update(_record_stats(ids, times))


def _record_stats(ids, times) -> dict:
    """Record count, first/last EventRecordID, ID jumps and time span of one log file.

    A log that rolled over keeps contiguous IDs that start above 1; a cleared or new log restarts at 1;
    deleted individual records leave jumps in the sequence.
    """
    ids = sorted(i for i in ids if isinstance(i, int))
    times = [t for t in times if t]
    return {"records": len(ids), "first_id": ids[0] if ids else None, "last_id": ids[-1] if ids else None,
            "id_gaps": [(a, b) for a, b in zip(ids, ids[1:]) if b != a + 1],
            "oldest": min(times) if times else None, "newest": max(times) if times else None}


def _ts(system, fallback):
    tc = system.get("TimeCreated", {})
    attrs = tc.get("#attributes", {}) if isinstance(tc, dict) else {}
    return to_utc(attrs.get("SystemTime") or fallback)


def _computer(system) -> str | None:
    c = system.get("Computer")
    return str(c).strip() or None if c else None


def _note_computer(ev: Evidence, log_label: str, system) -> str | None:
    """Count which computer wrote each log, so evidence from another host can be spotted (module #3)."""
    c = _computer(system)
    if c:
        counts = ev.log_computers.setdefault(log_label, {})
        counts[c] = counts.get(c, 0) + 1
    return c


def _provider(system) -> str:
    p = system.get("Provider", {})
    attrs = p.get("#attributes", {}) if isinstance(p, dict) else {}
    return str(attrs.get("Name") or "")


def log_cleared_event(eid: int, system, body, fallback) -> Event | None:
    """Security 1102 ("The audit log was cleared") / System 104 ("The <channel> log file was cleared").

    Both come from provider Microsoft-Windows-Eventlog; ID 104 is reused by other providers, so the
    provider is checked. 104 names the cleared channel; 1102 is always the Security log.
    """
    if _provider(system).lower() != "microsoft-windows-eventlog":
        return None
    data = body.get("LogFileCleared", body) if isinstance(body, dict) else {}
    if not isinstance(data, dict):
        data = {}
    user = str(data.get("SubjectUserName") or "").strip()
    domain = str(data.get("SubjectDomainName") or "").strip()
    channel = "Security" if eid == 1102 else str(data.get("Channel") or system.get("Channel") or "?")
    log_name = "Security" if eid == 1102 else "System"
    return Event(ts=_ts(system, fallback), kind=LOG_CLEARED, source=f"evtx:{log_name}:{eid}",
                 user=(f"{domain}\\{user}" if domain and user else user) or None,
                 details={"channel": channel, "computer": _computer(system),
                          "backup_path": data.get("BackupPath") or None})


# --------------------------------------------------------------------------- Partition/Diagnostic
def parse_partition_diagnostic(path: str, ev: Evidence) -> int:
    n = 0
    ev.parsed.add("evtx:Partition/Diagnostic")
    stats: dict = {}
    for _eid, system, ed, fb in _records(path, {1006}, stats):
        computer = _note_computer(ev, "Partition/Diagnostic", system)
        parent = parse_usb_instance(str(ed.get("ParentId", "")))
        if not parent:
            continue  # internal disk / VM disk
        ts = _ts(system, fb)
        dev = ev.device(*parent, "evtx:Partition/Diagnostic")
        capacity = int(ed.get("Capacity") or 0)
        manuf = str(ed.get("Manufacturer") or "").strip()
        model = str(ed.get("Model") or "").strip()
        if manuf and manuf.upper() != "NULL":
            dev.vendor = dev.vendor or manuf
        if model:
            dev.product = dev.product or model
        if capacity:
            dev.capacity_bytes = max(dev.capacity_bytes or 0, capacity)
        reg_id = str(ed.get("RegistryId") or "").lower()
        if reg_id.startswith("{"):
            dev.disk_ids.add(reg_id)
        details = {"capacity": capacity, "scsi_serial": str(ed.get("SerialNumber") or "").strip(),
                   "bus_type": ed.get("BusType"), "registry_id": reg_id or None, "computer": computer}
        if capacity:
            vsns, fss = [], []
            for i in range(4):
                vbr = ed.get(f"Vbr{i}")
                vsn = vsn_from_vbr(vbr)
                if vsn:
                    vsns.append(vsn)
                    fss.append(fs_from_vbr(vbr))
            details["vsns"] = vsns
            details["filesystems"] = fss
            details["partitions"] = [list(p) for p in mbr_partitions(ed.get("Mbr"))]
            dev.vsns.update(vsns)
            sig = mbr_disk_signature(ed.get("Mbr"))   # names the disk's MBR volumes (UASP linking)
            if sig:
                details["mbr_signature"] = sig
                dev.mbr_signatures.add(sig)
        ev.add(Event(ts=ts, kind=CONNECT if capacity else DISCONNECT,
                     source="evtx:Partition/Diagnostic:1006", device_key=dev.key, details=details))
        n += 1
    # Several Partition logs (e.g. an archived copy) would overwrite each other; keep the first, it is rare.
    ev.log_stats.setdefault("Partition/Diagnostic", stats)
    return n


# --------------------------------------------------------------------------- Security
def parse_security(path: str, ev: Evidence) -> int:
    n = 0
    ev.parsed.add("evtx:Security")
    for eid, system, ed, fb in _records(path, {1102, 6416, 4663, 4656, 4624, 4634, 4647, 4800, 4801}):
        _note_computer(ev, "Security", system)
        ts = _ts(system, fb)
        if eid == 1102:
            e = log_cleared_event(eid, system, ed, fb)
            if e:
                ev.add(e)
                n += 1
        elif eid == 6416:
            n += _on_6416(ev, ts, ed)
        elif eid in (4663, 4656):
            n += _on_object_access(ev, ts, eid, ed)
        else:
            n += _on_logon(ev, ts, eid, ed)
    return n


def _on_6416(ev, ts, ed) -> int:
    dev_id = str(ed.get("DeviceId") or "")
    desc = str(ed.get("DeviceDescription") or "")
    usb = parse_usb_instance(dev_id)
    if usb and dev_id.upper().startswith("USB\\"):
        dev = ev.device(*usb, "evtx:Security:6416")
        dev.description = dev.description or desc or None
        ev.add(Event(ts=ts, kind=CONNECT, source="evtx:Security:6416", device_key=dev.key,
                     details={"class": ed.get("ClassName"), "description": desc}))
        return 1
    hit = parse_usbstor_path(dev_id)
    if hit:
        dev = ev.find_by_serial(hit[1])
        if dev and "WPDBUSENUM" in dev_id.upper() and desc:
            dev.volume_names.add(desc)        # volume-level 6416 carries the volume label
            dev.sources.add("evtx:Security:6416")
    return 0


def _on_object_access(ev, ts, eid, ed) -> int:
    obj = str(ed.get("ObjectName") or "")
    m = VOLUME_RE.search(obj)
    if not m:
        return 0
    access = f"{ed.get('AccessList') or ''} {ed.get('AccessMask') or ''}"
    mask = 0
    try:
        mask = int(str(ed.get("AccessMask") or "0"), 16)
    except ValueError:
        pass
    if any(t in access for t in DELETE_TOKENS) or mask & 0x10000:
        kind = FILE_DELETE
    elif any(t in access for t in WRITE_TOKENS) or mask & 0x6:
        kind = FILE_WRITE
    else:
        kind = FILE_READ
    user = str(ed.get("SubjectUserName") or "") or None
    ev.add(Event(ts=ts, kind=kind, source=f"evtx:Security:{eid}", user=user, details={
        "path": obj, "volume": int(m.group(1)), "process": ed.get("ProcessName"),
        "access": " ".join(access.split()), "failed": eid == 4656,
        "logon_id": ed.get("SubjectLogonId")}))
    return 1


def _on_logon(ev, ts, eid, ed) -> int:
    user = str(ed.get("TargetUserName") or "")
    if not user or SKIP_USERS.search(user):
        return 0
    if eid == 4624:
        try:
            ltype = int(ed.get("LogonType") or 0)
        except ValueError:
            ltype = 0
        if ltype not in INTERACTIVE_LOGON_TYPES:
            return 0
        kind, details = LOGON, {"logon_type": ltype}
    elif eid == 4801:
        kind, details = LOGON, {"logon_type": "unlock"}
    else:
        kind, details = LOGOFF, {"event_id": eid}
    details["logon_id"] = ed.get("TargetLogonId")
    domain = ed.get("TargetDomainName")
    ev.add(Event(ts=ts, kind=kind, source=f"evtx:Security:{eid}",
                 user=f"{domain}\\{user}" if domain else user, details=details))
    return 1


# --------------------------------------------------------------------------- System
def parse_system_log(path: str, ev: Evidence) -> int:
    n = 0
    ev.parsed.add("evtx:System")
    for eid, system, body, fb in _records(path, {104, 20001, 20003}):
        _note_computer(ev, "System", system)
        if eid == 104:
            e = log_cleared_event(eid, system, body, fb)
            if e:
                ev.add(e)
                n += 1
            continue
        blob = json.dumps(body)
        blob = blob.replace("\\\\", "\\")
        usb = parse_usb_instance(blob)
        dev = None
        if usb:
            dev = ev.device(*usb, f"evtx:System:{eid}")
        else:
            hit = parse_usbstor_path(blob)
            dev = ev.find_by_serial(hit[1]) if hit else None
        if dev:
            ev.add(Event(ts=_ts(system, fb), kind=FIRST_INSTALL, source=f"evtx:System:{eid}",
                         device_key=dev.key))
            n += 1
    return n
