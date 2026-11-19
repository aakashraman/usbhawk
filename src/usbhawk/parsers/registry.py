"""Registry parsers for SYSTEM, SOFTWARE and NTUSER.DAT (offline hives via regipy).

Covers the 11 steps of the classic USB device profile:
  1-3  Enum\\USB             VID/PID, iSerialNumber, class (Service)
  4    Enum\\USBSTOR / SCSI  Device ID, FriendlyName, DiskId
  5-6  Properties {83da6326-...} 0064 / 0066 / 0067
  7    Windows Portable Devices  volume name
  8    VolumeInfoCache / MountedDevices  drive letter
  9    MountedDevices        Volume GUID
  10   MountPoints2          user
  11   EMDMgmt               VSN (1006 handled in evtx parser)
"""

from __future__ import annotations

import logging
import os
import re

from regipy.registry import RegistryHive

from ..model import (CONNECT, DISCONNECT, FIRST_INSTALL, HID, LAST_PRESENT, MTP, OTHER,
                     SERVICE_CLASS, UASP, USBSTOR, Event, Evidence)
from ..util import (as_bytes, clean_reg_string, decode_utf16_path, filetime_to_dt, is_mbr_volume_guid,
                    mounted_volume_guid, parse_usb_instance, parse_usbstor_path, strip_lun, to_utc)

log = logging.getLogger(__name__)

PROPS_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
TIME_PROPS = {"0064": FIRST_INSTALL, "0066": CONNECT, "0067": DISCONNECT}
DEVID_RE = re.compile(r"^(?P<type>[^&]+)&Ven_(?P<ven>[^&]*)&Prod_(?P<prod>[^&]*)(?:&Rev_(?P<rev>.*))?$", re.I)
GUID_RE = re.compile(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", re.I)


# --------------------------------------------------------------------------- helpers
def _key(hive: RegistryHive, path: str):
    try:
        return hive.get_key(path)
    except Exception:  # regipy raises RegistryKeyNotFoundException and friends
        return None


def _subkeys(hive, path):
    k = _key(hive, path)
    return list(k.iter_subkeys()) if k else []


HEX_TYPES = {"REG_BINARY", "REG_NONE", "REG_RESOURCE_LIST", "REG_RESOURCE_REQUIREMENTS_LIST"}


def _values(key) -> dict:
    """All values of a key, untrimmed.

    regipy cuts values to 128 bytes / 256 characters by default (trim_values=True), which silently chops
    long device paths such as MountedDevices USBSTOR entries. Binary values are returned as hex strings,
    the same type the rest of the parsers have always received.
    """
    out = {}
    if key is None:
        return out
    try:
        for v in key.iter_values(trim_values=False):
            value = v.value
            if isinstance(value, (bytes, bytearray)) and v.value_type in HEX_TYPES:
                value = bytes(value).hex()
            out[v.name] = value
    except Exception as exc:  # corrupted cells should not kill the run
        log.debug("value read failed: %s", exc)
    return out


def _default_value(key):
    vals = _values(key)
    if not vals:
        return None
    return vals.get("(default)", next(iter(vals.values())))


def _clean_desc(text):
    if isinstance(text, str) and ";" in text:
        return text.split(";")[-1]
    return text


def _last_write(key):
    try:
        return filetime_to_dt(key.header.last_modified)
    except Exception:
        return None


def _control_set(hive) -> str:
    sel = _values(_key(hive, "\\Select"))
    num = sel.get("Current") or 1
    return f"ControlSet{int(num):03d}"


def read_timezone_key(path: str) -> str | None:
    """The host's Windows time zone name (TimeZoneKeyName) from a SYSTEM hive, without parsing anything else."""
    try:
        hive = RegistryHive(path)
        tz = _values(_key(hive, f"\\{_control_set(hive)}\\Control\\TimeZoneInformation"))
        return clean_reg_string(tz.get("TimeZoneKeyName")) or clean_reg_string(tz.get("StandardName"))
    except Exception:
        return None


def _properties(hive, instance_path):
    """Return dict of property-id -> value under the {83da6326} property set."""
    out = {}
    for sub in _subkeys(hive, f"{instance_path}\\Properties\\{PROPS_GUID}"):
        out[sub.name.upper()] = _default_value(sub)
    return out


def _emit_times(ev: Evidence, props: dict, dev_key: str, source: str):
    for pid, kind in TIME_PROPS.items():
        ts = to_utc(props.get(pid))
        if ts:
            ev.add(Event(ts=ts, kind=kind, source=f"{source}:{pid}", device_key=dev_key))


def _note_dirty(hive, path: str, label: str, ev: Evidence) -> None:
    """A hive copied from a running system keeps its newest changes in its transaction logs (.LOG1 / .LOG2) until
    Windows writes them back; the header's two sequence numbers differ until then. Such changes (often the most
    recent USB activity, e.g. a device installed just before collection) are invisible here. Real case: a KAPE
    collection's last-connected drive looked wiped because its keys were still only in SYSTEM.LOG1/.LOG2."""
    try:
        a, b = hive.header.primary_sequence_num, hive.header.secondary_sequence_num
    except Exception:
        return
    if a == b:
        return
    logs = [os.path.basename(path) + x for x in (".LOG1", ".LOG2") if os.path.exists(path + x)]
    have = f" ({' and '.join(logs)} are next to it)" if logs else " (no .LOG1/.LOG2 files next to it)"
    ev.host.dirty_hives.append(label)
    # Name the flag that takes this hive (real case: the NTUSER warning said --system / --software).
    flag = ("--system" if label == "SYSTEM" else "--software" if label == "SOFTWARE"
            else "--ntuser <clean file>=<user>" if label.startswith("NTUSER") else "--system / --software")
    ev.warnings.append(
        f"{label} hive {path} is dirty (sequence numbers {a} and {b}){have}: changes still in its transaction logs "
        f"are not applied, so recent USB activity may be missing and devices may look wiped. Replay them with Eric "
        f"Zimmerman's rla.exe and pass the clean hive with {flag}.")


# --------------------------------------------------------------------------- SYSTEM
def parse_system(path: str, ev: Evidence) -> None:
    hive = RegistryHive(path)
    _note_dirty(hive, path, "SYSTEM", ev)
    cs = _control_set(hive)
    host = ev.host
    host.sources.append(path)
    ev.parsed.add("SYSTEM")
    host.hostname = host.hostname or _values(
        _key(hive, f"\\{cs}\\Control\\ComputerName\\ComputerName")).get("ComputerName")
    tz = _values(_key(hive, f"\\{cs}\\Control\\TimeZoneInformation"))
    host.timezone_key = clean_reg_string(tz.get("TimeZoneKeyName")) or clean_reg_string(tz.get("StandardName"))
    bias = tz.get("ActiveTimeBias")
    if isinstance(bias, int):
        host.active_bias_minutes = bias - (1 << 32) if bias > 0x7FFFFFFF else bias

    _parse_enum_usb(hive, cs, ev)
    _parse_enum_storage(hive, cs, "USBSTOR", ev)
    _parse_enum_storage(hive, cs, "SCSI", ev)
    _parse_mounted_devices(hive, ev)
    _parse_device_migration(hive, ev)
    _parse_feature_updates(hive, ev)
    _parse_bam(hive, cs, ev)


def _parse_bam(hive, cs, ev: Evidence):
    """Background Activity Moderator: last execution time per program per user SID (Windows 10 1709+).

    Cleanup tools rarely wipe it: USBOblivion's own run survives here (module #3, rule 5).
    """
    for base in (f"\\{cs}\\Services\\bam\\State\\UserSettings", f"\\{cs}\\Services\\bam\\UserSettings"):
        for sid_key in _subkeys(hive, base):
            for path, data in _values(sid_key).items():
                raw = as_bytes(data)
                if not path.startswith("\\") or raw is None or len(raw) < 8:
                    continue            # skip Version / SequenceNumber and non-path values
                ts = filetime_to_dt(raw[:8])
                if ts is None:
                    continue
                ev.executions.append({"path": path, "name": path.rsplit("\\", 1)[-1], "ts": ts,
                                      "sid": sid_key.name, "user": ev.host.sid_users.get(sid_key.name),
                                      "source": "registry:BAM"})


# A composite device (service usbccgp: keyboard + mouse receivers, phones with MTP + ADB, webcams) has no class of
# its own; its interfaces under VID_x&PID_y&MI_nn carry the drivers. The most telling interface wins.
COMPOSITE_PRIORITY = (MTP, USBSTOR, HID)


def _parse_enum_usb(hive, cs, ev: Evidence):
    base = f"\\{cs}\\Enum\\USB"
    interfaces: dict[tuple[str, str], list[tuple[str, str]]] = {}    # (VID, PID) -> [(instance name, service)]
    parents: list[tuple] = []                                         # (device, ParentIdPrefix)
    for vp in _subkeys(hive, base):
        m = re.match(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(&MI_[0-9A-F]{2})?", vp.name, re.I)
        if not m:
            continue  # root hubs and other non-VID entries
        if m.group(3):    # an interface of a composite device: remember its driver for the parent
            for inst in vp.iter_subkeys():
                svc = _values(inst).get("Service")
                if svc:
                    interfaces.setdefault((m.group(1).upper(), m.group(2).upper()), []).append(
                        (inst.name.upper(), str(svc)))
            continue
        for inst in vp.iter_subkeys():
            ipath = f"{base}\\{vp.name}\\{inst.name}"
            vals = _values(inst)
            dev = ev.device(m.group(1), m.group(2), inst.name, "registry:Enum\\USB")
            service = vals.get("Service")
            dev.service = dev.service or service
            dev.description = dev.description or _clean_desc(vals.get("DeviceDesc"))
            if service:
                cls = SERVICE_CLASS.get(str(service).upper())
                if cls and dev.device_class == OTHER:
                    dev.device_class = cls
            parents.append((dev, vals.get("ParentIdPrefix")))
            _emit_times(ev, _properties(hive, ipath), dev.key, "registry:Enum\\USB")

    for dev, prefix in parents:
        if dev.device_class != OTHER:
            continue
        kids = interfaces.get((dev.vid.upper(), dev.pid.upper()), [])
        if prefix:        # the interfaces' instance names start with the parent's ParentIdPrefix
            kids = [k for k in kids if k[0].startswith(str(prefix).upper() + "&")]
        found = {SERVICE_CLASS.get(svc.upper()) for _name, svc in kids}
        cls = next((c for c in COMPOSITE_PRIORITY if c in found), None)
        if cls:
            dev.device_class = cls


def _parse_enum_storage(hive, cs, branch: str, ev: Evidence):
    base = f"\\{cs}\\Enum\\{branch}"
    for devid in _subkeys(hive, base):
        for inst in devid.iter_subkeys():
            ipath = f"{base}\\{devid.name}\\{inst.name}"
            props = _properties(hive, ipath)
            parent = parse_usb_instance(str(props.get("000A") or ""))
            dev = None
            if parent:
                dev = ev.device(*parent, f"registry:Enum\\{branch}")
            elif branch == "USBSTOR":
                dev = ev.find_by_serial(strip_lun(inst.name))
                if dev is None:
                    ev.warnings.append(f"USBSTOR instance {devid.name}\\{inst.name} has no matching Enum\\USB parent")
                    continue
            else:
                continue  # SCSI entry that is not USB-attached (internal disk, VM disk, CD-ROM)
            dev.sources.add(f"registry:Enum\\{branch}")
            vals = _values(inst)
            dev.device_id = dev.device_id or devid.name
            dev.friendly_name = dev.friendly_name or vals.get("FriendlyName")
            mm = DEVID_RE.match(devid.name)
            if mm:
                dev.vendor = dev.vendor or mm.group("ven").replace("_", " ").strip() or None
                dev.product = dev.product or mm.group("prod").replace("_", " ").strip() or None
            if branch == "USBSTOR" and dev.device_class == OTHER:
                dev.device_class = USBSTOR
            if branch == "SCSI" and dev.device_class in (OTHER, USBSTOR):
                dev.device_class = UASP
            disk_id = _values(_key(hive, f"{ipath}\\Device Parameters\\Partmgr")).get("DiskId")
            if disk_id:
                dev.disk_ids.add(str(disk_id).lower())
            _emit_times(ev, props, dev.key, f"registry:Enum\\{branch}")


def _unlinked(artifact: str, id_type: str, id_value: str, ref_time=None, scope=None, user=None,
              **details) -> dict:
    """One normalised 'reference to a device we could not find in Enum' (see model.Evidence.unlinked)."""
    return {"artifact": artifact, "id_type": id_type, "id_value": id_value, "ref_time": ref_time,
            "ref_time_scope": scope if ref_time else None, "user": user,
            "details": {k: v for k, v in details.items() if v is not None}}


def _ident_to_id(ident) -> tuple[str, str, dict]:
    """Turn _resolve()'s unresolved identifier into (id_type, id_value, extra details)."""
    if isinstance(ident, tuple) and len(ident) == 2:          # (device_id, serial) from a USBSTOR path
        return "usb_serial", ident[1], {"device_id": ident[0]}
    if isinstance(ident, tuple) and len(ident) == 3:          # (vid, pid, serial) from a USB instance
        return "usb_serial", ident[2], {"vid": ident[0], "pid": ident[1]}
    return "", "", {}


def _parse_mounted_devices(hive, ev: Evidence):
    key = _key(hive, "\\MountedDevices")
    key_lw = _last_write(key) if key is not None else None   # values have no own timestamp
    for name, data in _values(key).items():
        g = GUID_RE.search(name)
        if g and name.startswith("\\??\\Volume"):
            ev.known_volume_guids.add(g.group(0).lower())
        derived = mounted_volume_guid(data)     # MBR signature+offset or DMIO:ID: (no device path)
        if derived:
            ev.known_volume_guids.add(derived)
            if is_mbr_volume_guid(derived):     # remember it so link_mbr_volumes() can tie it to a disk
                vol = ev.mbr_volumes.setdefault(derived, {"signature": derived[1:9], "letters": set(),
                                                          "offset": int.from_bytes(as_bytes(data)[4:12], "little")})
                if name.upper().startswith("\\DOSDEVICES\\"):
                    vol["letters"].add(name[-2:].upper())
        text = decode_utf16_path(data)
        if not text:
            continue
        hit = parse_usbstor_path(text)
        dev = ev.find_by_serial(hit[1]) if hit else None
        if dev is None:
            usb = parse_usb_instance(text)
            dev = ev.devices.get(f"VID_{usb[0]}&PID_{usb[1]}\\{usb[2]}") if usb else None
        if dev is None:
            if hit:
                ev.unlinked.append(_unlinked("MountedDevices", "usb_serial", hit[1], key_lw, "parent_key",
                                             value=name, device_id=hit[0]))
            continue
        dev.sources.add("registry:MountedDevices")
        if name.upper().startswith("\\DOSDEVICES\\"):
            dev.drive_letters.add(name[-2:].upper())
        g = GUID_RE.search(name)
        if g and name.startswith("\\??\\Volume"):
            dev.volume_guids.add(g.group(0).lower())


def _parse_device_migration(hive, ev: Evidence):
    """Devices archived by Windows during feature-update cleanup (LastPresentDate)."""
    for root in ("\\Setup\\Upgrade\\PnP\\CurrentControlSet\\Control\\DeviceMigration\\Devices",):
        for bus in _subkeys(hive, root):
            if bus.name.upper() not in ("USB", "USBSTOR", "SCSI"):
                continue
            for devid in bus.iter_subkeys():
                for inst in devid.iter_subkeys():
                    vals = _values(inst)
                    ts = to_utc(vals.get("LastPresentDate"))
                    ident = f"{bus.name}\\{devid.name}\\{inst.name}"
                    ev.migrated.append({"id": ident, "last_present": ts, "values": {
                        k: v for k, v in vals.items() if isinstance(v, (str, int))}})
                    usb = parse_usb_instance(ident) if bus.name.upper() == "USB" else None
                    if usb and ts:
                        dev = ev.device(*usb, "registry:DeviceMigration")
                        ev.add(Event(ts=ts, kind=LAST_PRESENT, source="registry:DeviceMigration",
                                     device_key=dev.key))


SOURCE_OS_RE = re.compile(r"^Source OS \(Updated on (\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2})\)$", re.I)


def _parse_feature_updates(hive, ev: Evidence):
    """SYSTEM\\Setup\\Source OS (Updated on M/D/YYYY HH:MM:SS) keys: one per feature update.

    Each key describes the build that was *replaced*: its InstallTime is when that build was installed,
    and the key name is when it was replaced. Both are moments Windows may have purged Enum\\USB.
    The key-name date carries no zone; it is treated as UTC (approximate to within a day).
    """
    from datetime import datetime, timezone
    for sub in _subkeys(hive, "\\Setup"):
        m = SOURCE_OS_RE.match(sub.name)
        if not m:
            continue
        vals = _values(sub)
        build = vals.get("CurrentBuild") or "?"
        try:
            replaced = datetime.strptime(m.group(1), "%m/%d/%Y %H:%M:%S").replace(tzinfo=timezone.utc)
            ev.host.feature_updates.append({"ts": replaced, "source": f"SYSTEM\\Setup\\{sub.name} (build {build} replaced)"})
        except ValueError:
            pass
        installed = filetime_to_dt(vals.get("InstallTime")) if isinstance(vals.get("InstallTime"), int) else None
        if installed is None and isinstance(vals.get("InstallDate"), int):
            installed = datetime.fromtimestamp(vals["InstallDate"], tz=timezone.utc)
        if installed:
            ev.host.feature_updates.append({"ts": installed, "source": f"SYSTEM\\Setup\\{sub.name} InstallTime (build {build} installed)"})


# --------------------------------------------------------------------------- SOFTWARE
def parse_software(path: str, ev: Evidence) -> None:
    hive = RegistryHive(path)
    _note_dirty(hive, path, "SOFTWARE", ev)
    ev.host.sources.append(path)
    ev.parsed.add("SOFTWARE")
    cv = _values(_key(hive, "\\Microsoft\\Windows NT\\CurrentVersion"))
    ev.host.os_product = ev.host.os_product or cv.get("ProductName")
    ev.host.os_build = ev.host.os_build or str(cv.get("CurrentBuild") or "") or None
    if cv.get("InstallTime"):
        ev.host.install_time = filetime_to_dt(cv["InstallTime"])
    elif isinstance(cv.get("InstallDate"), int):
        from datetime import datetime, timezone
        ev.host.install_time = datetime.fromtimestamp(cv["InstallDate"], tz=timezone.utc)
    if ev.host.install_time:
        ev.host.feature_updates.append({"ts": ev.host.install_time,
                                        "source": f"SOFTWARE CurrentVersion InstallTime (build {ev.host.os_build or '?'})"})

    _parse_wpd(hive, ev)
    _parse_volume_info_cache(hive, ev)
    _parse_emdmgmt(hive, ev)
    _parse_profile_list(hive, ev)


def _parse_profile_list(hive, ev: Evidence):
    """SID -> user name, so BAM executions (keyed by SID) can name the user."""
    for sub in _subkeys(hive, "\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"):
        path = clean_reg_string(_values(sub).get("ProfileImagePath"))
        if path:
            ev.host.sid_users[sub.name] = path.rstrip("\\").rsplit("\\", 1)[-1]
    for x in ev.executions:                 # SYSTEM (BAM) is parsed before SOFTWARE
        x["user"] = x["user"] or ev.host.sid_users.get(x["sid"])


def _resolve(ev: Evidence, text: str):
    hit = parse_usbstor_path(text)
    if hit:
        dev = ev.find_by_serial(hit[1])
        if dev:
            return dev, hit
    usb = parse_usb_instance(text)
    if usb:
        dev = ev.devices.get(f"VID_{usb[0]}&PID_{usb[1]}\\{usb[2]}")
        if dev:
            return dev, usb
    for g in GUID_RE.findall(text):
        dev = ev.find_by_disk_id(g)
        if dev:
            return dev, g
    return None, hit or usb


def _parse_wpd(hive, ev: Evidence):
    base = "\\Microsoft\\Windows Portable Devices\\Devices"
    for sub in _subkeys(hive, base):
        name = _values(sub).get("FriendlyName")
        dev, ident = _resolve(ev, sub.name)
        if dev is None:
            id_type, id_value, extra = _ident_to_id(ident)
            if not id_type:                      # no device identity in the key name (e.g. SWD only)
                id_type, id_value = "wpd_key", sub.name
            ev.unlinked.append(_unlinked("WindowsPortableDevices", id_type, id_value, _last_write(sub),
                                         "entry", key=sub.name,
                                         friendly_name=name if isinstance(name, str) else None, **extra))
            continue
        dev.sources.add("registry:WindowsPortableDevices")
        if dev.device_class == OTHER and "USB#VID" in sub.name.upper():
            dev.device_class = MTP
        if isinstance(name, str) and name:
            if re.fullmatch(r"[A-Z]:\\?", name.strip(), re.I):
                dev.drive_letters.add(name.strip()[:2].upper())
            else:
                dev.volume_names.add(name)


def _parse_volume_info_cache(hive, ev: Evidence):
    for sub in _subkeys(hive, "\\Microsoft\\Windows Search\\VolumeInfoCache"):
        label = _values(sub).get("VolumeLabel")
        if label:
            ev.label_by_letter[sub.name.upper()[:2]] = label


def _parse_emdmgmt(hive, ev: Evidence):
    for sub in _subkeys(hive, "\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt"):
        tail = sub.name.rsplit("}", 1)[-1] if "}" in sub.name else sub.name
        label, _, vsn_dec = tail.rpartition("_")
        vsn = f"{int(vsn_dec):08X}" if vsn_dec.isdigit() else None
        dev, ident = _resolve(ev, sub.name)
        if dev is None:
            id_type, id_value, extra = _ident_to_id(ident)
            if not id_type:                      # label + VSN only: cannot be tied to a USB device
                id_type, id_value = "volume_label", label
            ev.unlinked.append(_unlinked("EMDMgmt", id_type, id_value, _last_write(sub), "entry",
                                         key=sub.name, volume_name=label or None, vsn=vsn, **extra))
            continue
        dev.sources.add("registry:EMDMgmt")
        if vsn:
            dev.vsns.add(vsn)
        if label:
            dev.volume_names.add(label)


# --------------------------------------------------------------------------- NTUSER
def parse_ntuser(path: str, ev: Evidence, user: str) -> None:
    hive = RegistryHive(path)
    _note_dirty(hive, path, f"NTUSER.DAT ({user})", ev)
    ev.parsed.add("NTUSER")
    base = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
    guid_to_dev = {g: d for d in ev.devices.values() for g in d.volume_guids}
    for sub in _subkeys(hive, base):
        lw = _last_write(sub)
        g = sub.name.lower()
        if g in guid_to_dev:
            dev = guid_to_dev[g]
            dev.users.add(user)
            dev.sources.add("registry:MountPoints2")
            if lw:
                ev.add(Event(ts=lw, kind="user_mount", source="registry:MountPoints2",
                             device_key=dev.key, user=user, details={"volume_guid": g}))
        elif sub.name.startswith("##"):
            ev.network_shares.append({"user": user, "share": sub.name.replace("#", "\\"),
                                      "last_write": lw})
        elif GUID_RE.fullmatch(sub.name) and is_mbr_volume_guid(g):
            # MBR-derived GUID (signature + offset): kept, typed apart, so link_mbr_volumes() can attribute
            # the user once the 1006 MBR signature is known. Its absence from MountedDevices proves nothing.
            ev.unlinked.append(_unlinked("MountPoints2", "mbr_volume", g, lw, "entry", user=user))
        elif GUID_RE.fullmatch(sub.name) and g not in ev.known_volume_guids:
            # Mount Manager volume the user mounted that SYSTEM\MountedDevices no longer knows about
            ev.unlinked.append(_unlinked("MountPoints2", "volume_guid", g, lw, "entry", user=user))


def link_mbr_volumes(ev: Evidence) -> None:
    """Tie MBR-style volumes to the disk whose MBR signature the Partition/Diagnostic log recorded.

    Runs after all parsers. A UASP/MBR USB disk has no device path in MountedDevices, only
    signature + offset; this restores its drive letter, volume GUID and MountPoints2 users.
    """
    by_sig = {s: d for d in ev.devices.values() for s in d.mbr_signatures}
    if not by_sig:
        return
    for guid, vol in ev.mbr_volumes.items():
        dev = by_sig.get(vol["signature"])
        if dev:
            dev.volume_guids.add(guid)
            dev.drive_letters.update(vol["letters"])
            dev.sources.add("registry:MountedDevices")
    keep = []
    for u in ev.unlinked:
        dev = by_sig.get(u["id_value"][1:9]) if u.get("id_type") == "mbr_volume" else None
        if dev is None:
            keep.append(u)
            continue
        dev.volume_guids.add(u["id_value"])
        dev.sources.add("registry:MountPoints2")
        if u.get("user"):
            dev.users.add(u["user"])
        if u.get("ref_time"):
            ev.add(Event(ts=u["ref_time"], kind="user_mount", source="registry:MountPoints2",
                         device_key=dev.key, user=u.get("user"), details={"volume_guid": u["id_value"]}))
    ev.unlinked = keep


def link_drive_letters(ev: Evidence) -> None:
    """Step 8 via VolumeInfoCache: map volume labels we know to drive letters."""
    for letter, label in ev.label_by_letter.items():
        for dev in ev.devices.values():
            if label in dev.volume_names:
                dev.drive_letters.add(letter)
                dev.sources.add("registry:VolumeInfoCache")
