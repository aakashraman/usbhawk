"""Low-level helpers: FILETIME, serial normalisation, MBR/VBR decoding."""

from __future__ import annotations

import re
import struct
from datetime import datetime, timedelta, timezone

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Matches the parent USB instance id, e.g. USB\VID_0781&PID_5530\200608767007B7C08A6A
# (also the '#'-separated form used inside WPD / MountedDevices paths)
USB_INSTANCE_RE = re.compile(
    r"USB[\\#]VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(?:&(?!MI_)[^\\#]*)?[\\#]([^\\#\s\"{]+)", re.I)
# Serial embedded in device paths like ..._??_USBSTOR#Disk&Ven_X&Prod_Y&Rev_Z#SERIAL&0#{guid}
USBSTOR_PATH_RE = re.compile(r"USBSTOR[#\\]([^#\\]+)[#\\]([^#\\]+?)(?:&\d+)?(?:[#\\]|$)", re.I)


def filetime_to_dt(value: int | bytes | None) -> datetime | None:
    """Convert a Windows FILETIME (int or 8 little-endian bytes) to an aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        if len(value) < 8:
            return None
        value = struct.unpack("<Q", bytes(value[:8]))[0]
    if not value:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=value / 10)
    except OverflowError:
        return None


def to_utc(value) -> datetime | None:
    """Coerce regipy/evtx timestamp representations to aware UTC datetimes."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, bytes, bytearray)):
        return filetime_to_dt(value)
    text = str(value).strip().replace(" UTC", "")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    # evtx emits 7 fractional digits; Python accepts at most 6
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


def strip_lun(instance: str) -> str:
    """USBSTOR instance names carry a LUN suffix: SERIAL&0 -> SERIAL."""
    head, sep, tail = instance.rpartition("&")
    return head if sep and tail.isdigit() else instance


def is_windows_generated_serial(serial: str) -> bool:
    """Windows invents an id when a device has no iSerialNumber; the 2nd char is '&'."""
    return len(serial) > 1 and serial[1] == "&"


def device_key(vid: str, pid: str, serial: str) -> str:
    """Canonical device key used everywhere in the toolkit."""
    return f"VID_{vid.upper()}&PID_{pid.upper()}\\{serial.upper()}"


def parse_usb_instance(text: str):
    """Return (vid, pid, serial) from any string containing a USB parent instance id."""
    m = USB_INSTANCE_RE.search(text or "")
    if not m:
        return None
    return m.group(1).upper(), m.group(2).upper(), m.group(3).upper()


def parse_usbstor_path(text: str):
    """Return (device_id, serial) from USBSTOR registry/device paths."""
    m = USBSTOR_PATH_RE.search(text or "")
    if not m:
        return None
    return m.group(1), strip_lun(m.group(2)).upper()


_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{2})+$")


def as_bytes(data) -> bytes | None:
    """regipy returns REG_BINARY either as bytes or as a hex string; normalise to bytes."""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    if isinstance(data, str) and _HEX_RE.match(data):
        return bytes.fromhex(data)
    return None


def clean_reg_string(value) -> str | None:
    """REG_SZ values sometimes come back as raw UTF-16 bytes with trailing garbage."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-16le", errors="ignore")
    return str(value).split("\x00", 1)[0].strip() or None


def decode_utf16_path(data) -> str | None:
    """MountedDevices data for USBSTOR volumes is a UTF-16LE device path."""
    data = as_bytes(data)
    if data is None:
        return None
    if data[:2] in (b"_\x00", b"\\\x00", b"#\x00"):
        try:
            return bytes(data).decode("utf-16le", errors="replace").rstrip("\x00")
        except Exception:  # pragma: no cover - defensive
            return None
    return None


def vsn_from_vbr(vbr_hex: str | None) -> str | None:
    """Volume Serial Number (as LNK/JumpList tools show it) from a VBR hex blob."""
    if not vbr_hex:
        return None
    try:
        vbr = bytes.fromhex(vbr_hex)
    except ValueError:
        return None
    if len(vbr) < 0x5A:
        return None
    if vbr[3:11] == b"NTFS    ":
        return vbr[0x48:0x4C][::-1].hex().upper()
    if vbr[3:11] == b"EXFAT   ":
        return vbr[0x64:0x68][::-1].hex().upper()
    if vbr[0x52:0x5A] == b"FAT32   ":
        return vbr[0x43:0x47][::-1].hex().upper()
    if vbr[0x36:0x3B] in (b"FAT12", b"FAT16"):
        return vbr[0x27:0x2B][::-1].hex().upper()
    return None


def fs_from_vbr(vbr_hex: str | None) -> str | None:
    if not vbr_hex:
        return None
    try:
        vbr = bytes.fromhex(vbr_hex)
    except ValueError:
        return None
    if vbr[3:11] == b"NTFS    ":
        return "NTFS"
    if vbr[3:11] == b"EXFAT   ":
        return "exFAT"
    if vbr[0x52:0x5A] == b"FAT32   ":
        return "FAT32"
    if vbr[0x36:0x3B] in (b"FAT12", b"FAT16"):
        return vbr[0x36:0x3B].decode()
    return None


def mbr_partitions(mbr_hex: str | None):
    """Yield (index, type_byte, start_lba, sector_count) for primary MBR entries."""
    if not mbr_hex:
        return
    mbr = bytes.fromhex(mbr_hex)
    if len(mbr) < 512:
        return
    for i in range(4):
        e = mbr[0x1BE + i * 16: 0x1BE + (i + 1) * 16]
        if e[4]:
            start, count = struct.unpack("<II", e[8:16])
            yield i, f"0x{e[4]:02X}", start, count
