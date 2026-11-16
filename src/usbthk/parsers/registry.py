"""Registry parsers for SYSTEM, SOFTWARE and NTUSER.DAT (offline hives via regipy).

Covers the FOR500 profiling steps:
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
import re

from regipy.registry import RegistryHive

from ..model import (CONNECT, DISCONNECT, FIRST_INSTALL, LAST_PRESENT, MTP, OTHER,
                     SERVICE_CLASS, UASP, USBSTOR, Event, Evidence)
from ..util import (clean_reg_string, decode_utf16_path, filetime_to_dt, parse_usb_instance,
                    parse_usbstor_path, strip_lun, to_utc)

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


def _values(key) -> dict:
    out = {}
    if key is None:
        return out
    try:
        for v in key.iter_values():
            out[v.name] = v.value
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


# --------------------------------------------------------------------------- SYSTEM
def parse_system(path: str, ev: Evidence) -> None:
    hive = RegistryHive(path)
    cs = _control_set(hive)
    host = ev.host
    host.sources.append(path)
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


def _parse_enum_usb(hive, cs, ev: Evidence):
    base = f"\\{cs}\\Enum\\USB"
    for vp in _subkeys(hive, base):
        if "&MI_" in vp.name.upper() or not vp.name.upper().startswith("VID_"):
            continue  # skip interface children of composite devices and root hubs
        m = re.match(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", vp.name, re.I)
        if not m:
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
            _emit_times(ev, _properties(hive, ipath), dev.key, "registry:Enum\\USB")


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


def _parse_mounted_devices(hive, ev: Evidence):
    key = _key(hive, "\\MountedDevices")
    for name, data in _values(key).items():
        g = GUID_RE.search(name)
        if g and name.startswith("\\??\\Volume"):
            ev.known_volume_guids.add(g.group(0).lower())
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
                ev.unlinked.append({"artifact": "MountedDevices", "value": name,
                                    "serial": hit[1], "device_id": hit[0]})
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


# --------------------------------------------------------------------------- SOFTWARE
def parse_software(path: str, ev: Evidence) -> None:
    hive = RegistryHive(path)
    ev.host.sources.append(path)
    cv = _values(_key(hive, "\\Microsoft\\Windows NT\\CurrentVersion"))
    ev.host.os_product = ev.host.os_product or cv.get("ProductName")
    ev.host.os_build = ev.host.os_build or str(cv.get("CurrentBuild") or "") or None
    if cv.get("InstallTime"):
        ev.host.install_time = filetime_to_dt(cv["InstallTime"])
    elif isinstance(cv.get("InstallDate"), int):
        from datetime import datetime, timezone
        ev.host.install_time = datetime.fromtimestamp(cv["InstallDate"], tz=timezone.utc)

    _parse_wpd(hive, ev)
    _parse_volume_info_cache(hive, ev)
    _parse_emdmgmt(hive, ev)


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
            ev.unlinked.append({"artifact": "WindowsPortableDevices", "key": sub.name,
                                "friendly_name": name, "last_write": _last_write(sub)})
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
        dev, _ = _resolve(ev, sub.name)
        if dev is None:
            ev.unlinked.append({"artifact": "EMDMgmt", "key": sub.name, "volume_name": label or None,
                                "vsn": vsn})
            continue
        dev.sources.add("registry:EMDMgmt")
        if vsn:
            dev.vsns.add(vsn)
        if label:
            dev.volume_names.add(label)


# --------------------------------------------------------------------------- NTUSER
def parse_ntuser(path: str, ev: Evidence, user: str) -> None:
    hive = RegistryHive(path)
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
        elif GUID_RE.fullmatch(sub.name) and g not in ev.known_volume_guids:
            # Volume the user mounted that SYSTEM\MountedDevices no longer knows about
            ev.unlinked.append({"artifact": "MountPoints2", "user": user, "volume_guid": g,
                                "last_write": lw})


def link_drive_letters(ev: Evidence) -> None:
    """Step 8 via VolumeInfoCache: map volume labels we know to drive letters."""
    for letter, label in ev.label_by_letter.items():
        for dev in ev.devices.values():
            if label in dev.volume_names:
                dev.drive_letters.add(letter)
                dev.sources.add("registry:VolumeInfoCache")
