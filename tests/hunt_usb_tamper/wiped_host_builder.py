"""A fictional wiped host, written as REAL Windows artifacts: registry hives (regf), an empty event log (evtx).

Used by scripts/make_examples.py (examples/tamper/wiped-host/) and by the tamper demo tests, so the demo, the docs and
the tests describe the same evidence. Nothing here is from a real machine: host NW-LEG-WS031, user NW\\m.ortiz, SID
S-1-5-21-1111111111-2222222222-3333333333-1104, invented serials and GUIDs.

The story (all times UTC, Thursday 2026-10-29, the host is in New York):
  * 17:58  m.ortiz connects a Samsung T7 (a USB 3 / UASP disk) and removes it at 18:31.
  * 18:05  a SanDisk Ultra labelled CASE-FILES is mounted (ReadyBoost EMDMgmt entry).
  * 18:21  a Kingston DataTraveler 3.0 labelled BACKUP is mounted (Windows Portable Devices, MountPoints2).
  * 18:42  m.ortiz runs USBOblivion. It deletes the sticks' Enum keys and MountedDevices values, empties the
           Partition/Diagnostic log and deletes setupapi.dev.log, but, as in the lab (docs/hunt-usb-tamper.md),
           it leaves BAM, EMDMgmt, Windows Portable Devices and MountPoints2 behind, and it does not touch the
           UASP disk.
  * Benign twins: a Verbatim stick last seen in November 2025 and a SanDisk Cruzer Blade archived under
    DeviceMigration were both removed by Windows itself, during the feature update of 2026-03-02.

The writer is deliberately small: one hive = one tree of keys and values, laid out in 4 KB hive bins with
'lh' subkey lists, one shared security descriptor, ASCII names and no big-data cells. Output is byte-for-byte
deterministic, so the committed demo files can be checked against this generator.
"""

from __future__ import annotations

import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- value types
REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 1, 2, 3, 4, 7, 11
DEVPROP_FILETIME, DEVPROP_STRING = 0xFFFF0010, 0xFFFF0012       # device property values under Properties\{...}

_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def utc(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def filetime(dt: datetime) -> int:
    d = dt - _EPOCH
    return (d.days * 86400 + d.seconds) * 10**7 + d.microseconds * 10


def _sz(text: str) -> bytes:
    return (text + "\0").encode("utf-16-le")


class Key:
    """A registry key: name, last-write time, values (name, type, raw bytes) and subkeys."""

    def __init__(self, name: str, last_write: datetime):
        self.name, self.last_write = name, last_write
        self.values: list[tuple[str, int, bytes]] = []
        self.subkeys: dict[str, Key] = {}

    def key(self, path: str, last_write: datetime | None = None) -> "Key":
        """Get or create a descendant; new keys get `last_write` (default: this key's)."""
        k = self
        for part in path.split("\\"):
            if part.upper() not in k.subkeys:
                k.subkeys[part.upper()] = Key(part, last_write or k.last_write)
            k = k.subkeys[part.upper()]
        if last_write:
            k.last_write = last_write
        return k

    def sz(self, name, text, expand=False):
        self.values.append((name, REG_EXPAND_SZ if expand else REG_SZ, _sz(text)))
        return self

    def dword(self, name, n):
        self.values.append((name, REG_DWORD, struct.pack("<I", n)))
        return self

    def qword(self, name, n):
        self.values.append((name, REG_QWORD, struct.pack("<Q", n)))
        return self

    def binary(self, name, data: bytes):
        self.values.append((name, REG_BINARY, data))
        return self

    def multi_sz(self, name, items):
        self.values.append((name, REG_MULTI_SZ, b"".join(_sz(x) for x in items) + b"\0\0"))
        return self

    def prop_time(self, dt: datetime):
        self.values.append(("", DEVPROP_FILETIME, struct.pack("<Q", filetime(dt))))
        return self

    def prop_string(self, text):
        self.values.append(("", DEVPROP_STRING, _sz(text)))
        return self


# --------------------------------------------------------------------------- regf writer
_BIN = 4096


class _Cells:
    """Hive-bin storage: allocated cells (negative size), never crossing a 4 KB bin boundary."""

    def __init__(self, stamp: int):
        self.buf = bytearray()
        self.bin_end = 0
        self.stamp = stamp

    def alloc(self, payload: bytes) -> int:
        size = (4 + len(payload) + 7) & ~7
        if self.bin_end - len(self.buf) < size:
            self._new_bin(size)
        off = len(self.buf)
        self.buf += struct.pack("<i", -size) + payload + bytes(size - 4 - len(payload))
        return off

    def patch(self, off: int, fmt: str, rel: int, *vals):
        struct.pack_into(fmt, self.buf, off + 4 + rel, *vals)

    def _close_bin(self):
        rest = self.bin_end - len(self.buf)
        if rest:
            self.buf += struct.pack("<i", rest) + bytes(rest - 4)     # free cell up to the bin's end

    def _new_bin(self, need: int):
        if self.buf:
            self._close_bin()
        start = len(self.buf)
        size = max(_BIN, -(-(need + 32) // _BIN) * _BIN)
        self.buf += b"hbin" + struct.pack("<IIIIQI", start, size, 0, 0, self.stamp if not start else 0, 0)
        self.bin_end = start + size

    def finish(self) -> bytes:
        self._close_bin()
        return bytes(self.buf)


def _sid(text: str) -> bytes:
    parts = [int(x) for x in text.split("-")[2:]]
    return struct.pack("<BB", 1, len(parts) - 1) + parts[0].to_bytes(6, "big") + b"".join(
        struct.pack("<I", p) for p in parts[1:])


def _security_descriptor() -> bytes:
    """Self-relative SD: owner Administrators, group SYSTEM, DACL granting Everyone full control (inherited)."""
    owner, group, everyone = _sid("S-1-5-32-544"), _sid("S-1-5-18"), _sid("S-1-1-0")
    ace = struct.pack("<BBHI", 0, 0x02, 8 + len(everyone), 0x000F003F) + everyone
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(ace), 1, 0) + ace
    o = 20
    g = o + len(owner)
    d = g + len(group)
    return struct.pack("<BBHIIII", 1, 0, 0x8004, o, g, 0, d) + owner + group + acl


def _lh_hash(name: str) -> int:
    h = 0
    for ch in name.upper():
        h = (h * 37 + ord(ch)) & 0xFFFFFFFF
    return h


def write_hive(root: Key, path: Path, file_name: str, stamp: datetime) -> None:
    ts = filetime(stamp)
    cells = _Cells(ts)
    keys = [0]

    def nk(key: Key, parent: int, is_root: bool) -> int:
        keys[0] += 1
        name = key.name.encode("ascii")
        off = cells.alloc(b"nk" + bytes(74) + name)
        if is_root:
            sk_holder.append(cells.alloc(b"sk" + bytes(18) + sd))
        # values: data cells (data > 4 bytes) -> vk cells -> value list
        vks = []
        for vname, vtype, data in key.values:
            assert len(data) <= 16344, "big-data values are not supported by this writer"
            if len(data) <= 4:
                size, doff = len(data) | 0x80000000, int.from_bytes(data.ljust(4, b"\0"), "little")
            else:
                size, doff = len(data), cells.alloc(data)
            n = vname.encode("ascii")
            vks.append(cells.alloc(b"vk" + struct.pack("<HIIIHH", len(n), size, doff, vtype, 1 if n else 0, 0) + n))
        vlist = cells.alloc(b"".join(struct.pack("<I", v) for v in vks)) if vks else 0xFFFFFFFF
        subs = sorted(key.subkeys.values(), key=lambda k: k.name.upper())
        children = [(nk(s, off, False), _lh_hash(s.name)) for s in subs]
        slist = (cells.alloc(b"lh" + struct.pack("<H", len(children)) +
                             b"".join(struct.pack("<II", o, h) for o, h in children)) if children else 0xFFFFFFFF)
        flags = 0x2C if is_root else 0x20               # KEY_HIVE_ENTRY | KEY_NO_DELETE | KEY_COMP_NAME
        cells.patch(off, "<2sHQ4sIIIIIIIIIIIIIIHH", 0, b"nk", flags, filetime(key.last_write), bytes(4),
                    parent, len(children), 0, slist, 0xFFFFFFFF, len(vks), vlist, sk_holder[0], 0xFFFFFFFF,
                    max((len(s.name) * 2 for s in subs), default=0), 0,
                    max((len(v[0]) * 2 for v in key.values), default=0),
                    max((len(v[2]) for v in key.values), default=0), 0, len(name), 0)
        return off

    sd = _security_descriptor()
    sk_holder: list[int] = []
    root_off = nk(root, 0, True)
    sk = sk_holder[0]
    cells.patch(sk, "<2sHIIII", 0, b"sk", 0, sk, sk, keys[0], len(sd))
    body = cells.finish()

    head = bytearray(4096)
    struct.pack_into("<4sIIQIIIIIII", head, 0, b"regf", 1, 1, ts, 1, 5, 0, 1, root_off, len(body), 1)
    head[48:48 + 64] = file_name[-31:].encode("utf-16-le").ljust(64, b"\0")
    check = 0
    for (dw,) in struct.iter_unpack("<I", bytes(head[:508])):
        check ^= dw
    check = 1 if check == 0 else 0xFFFFFFFE if check == 0xFFFFFFFF else check
    struct.pack_into("<I", head, 508, check)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(head) + body)


def write_empty_evtx(path: Path) -> None:
    """An event log file with a valid header and no records (what a wiped log looks like to a parser)."""
    head = bytearray(4096)
    struct.pack_into("<8sQQQIHHHH", head, 0, b"ElfFile\0", 0, 0, 1, 128, 1, 3, 4096, 0)
    struct.pack_into("<I", head, 120, 0)                                  # flags: clean
    struct.pack_into("<I", head, 124, zlib.crc32(bytes(head[:120])))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(head))


# --------------------------------------------------------------------------- the scenario
HOST = "NW-LEG-WS031"
USER = "m.ortiz"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1104"
PROPS = "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"
DISK_CLASS = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"

INSTALL_PREVIOUS = utc("2024-02-12T13:05:00Z")      # build 19044 installed
FEATURE_UPDATE = utc("2026-03-02T09:14:55Z")        # 19044 -> 19045; Windows archives / purges old USB devices
T7_FIRST = utc("2026-09-15T14:30:12Z")
T7_ARRIVAL = utc("2026-10-29T17:58:12Z")
T7_REMOVAL = utc("2026-10-29T18:31:40Z")
SANDISK_SEEN = utc("2026-10-29T18:05:31Z")
KINGSTON_SEEN = utc("2026-10-29T18:21:07Z")
VOLUME_SEEN = utc("2026-10-29T18:21:30Z")
USBOBLIVION_RUN = utc("2026-10-29T18:42:10Z")
VERBATIM_SEEN = utc("2025-11-14T12:30:10Z")
CRUZER_LAST_PRESENT = utc("2026-02-20T16:45:00Z")
HIVE_SAVED = utc("2026-10-29T19:10:00Z")             # when the triage was collected

T7 = ("04E8", "4001", "N7T00042CF19")
SANDISK = ("Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00", "4C530001230601108811", "CASE-FILES", 0x5A3C91E2)
KINGSTON = ("Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP", "60A44C413D5FF380E95A2F11", "BACKUP")
VERBATIM = ("Disk&Ven_Verbatim&Prod_STORE_N_GO&Rev_1.00", "07B21A9C3E5D4F81", "PHOTOS")
CRUZER = ("0781", "5567", "4C531001450817118421")
ORPHAN_VOLUME = "{7c1e5a2b-91d4-11f0-a6b2-806e6f6e6963}"
C_VOLUME = "{2b8dca72-672e-11e7-bce1-806e6f6e6963}"


def _system() -> Key:
    root = Key("ROOT", FEATURE_UPDATE)
    root.key("Select").dword("Current", 1).dword("Default", 1).dword("Failed", 0).dword("LastKnownGood", 1)
    cs = root.key("ControlSet001")
    cs.key("Control\\ComputerName\\ComputerName").sz("ComputerName", HOST)
    cs.key("Control\\TimeZoneInformation").sz("TimeZoneKeyName", "Eastern Standard Time").dword("ActiveTimeBias", 240)

    # The UASP disk USBOblivion does not clean (lab-observed): Enum\USB parent + Enum\SCSI disk
    vid, pid, serial = T7
    usb = cs.key(f"Enum\\USB\\VID_{vid}&PID_{pid}\\{serial}", T7_REMOVAL)
    usb.sz("DeviceDesc", "@uaspstor.inf,%uaspstor.devicedesc%;UAS Mass Storage Device").sz("Service", "UASPStor")
    usb.multi_sz("HardwareID", [f"USB\\VID_{vid}&PID_{pid}&REV_0100", f"USB\\VID_{vid}&PID_{pid}"])
    scsi = cs.key("Enum\\SCSI\\Disk&Ven_Samsung&Prod_PSSD_T7&Rev_0\\7&2f1b3a9c&0&000000", T7_REMOVAL)
    scsi.sz("FriendlyName", "Samsung PSSD T7 SCSI Disk Device").sz("Service", "disk")
    for base in (usb, scsi):
        base.key(f"{PROPS}\\0064").prop_time(T7_FIRST)
        base.key(f"{PROPS}\\0066").prop_time(T7_ARRIVAL)
        base.key(f"{PROPS}\\0067").prop_time(T7_REMOVAL)
    scsi.key(f"{PROPS}\\000A").prop_string(f"USB\\VID_{vid}&PID_{pid}\\{serial}")

    # BAM: USBOblivion's own run survives (rule 5); notepad for contrast
    bam = cs.key(f"Services\\bam\\State\\UserSettings\\{SID}", USBOBLIVION_RUN)
    bam.dword("Version", 1).dword("SequenceNumber", 7)
    for exe, when in ((f"\\Device\\HarddiskVolume3\\Windows\\System32\\notepad.exe", utc("2026-10-29T17:40:05Z")),
                      (f"\\Device\\HarddiskVolume3\\Users\\{USER}\\Downloads\\USBOblivion64.exe", USBOBLIVION_RUN)):
        bam.binary(exe, struct.pack("<Q", filetime(when)) + bytes(16))

    # MountedDevices: only the system volume is left (USBOblivion deleted the sticks' values)
    c = struct.pack("<I", 0x5D1C2E7A) + struct.pack("<Q", 0x100000)
    root.key("MountedDevices", USBOBLIVION_RUN).binary("\\DosDevices\\C:", c).binary(f"\\??\\Volume{C_VOLUME}", c)

    # Feature-update history and Windows' own archive of devices it removed
    when = f"{FEATURE_UPDATE.month}/{FEATURE_UPDATE.day}/{FEATURE_UPDATE:%Y %H:%M:%S}"   # M/D/YYYY, as Windows writes it
    root.key(f"Setup\\Source OS (Updated on {when})", FEATURE_UPDATE) \
        .sz("CurrentBuild", "19044").sz("ProductName", "Windows 10 Enterprise").qword("InstallTime", filetime(INSTALL_PREVIOUS))
    v, p, s = CRUZER
    root.key("Setup\\Upgrade\\PnP\\CurrentControlSet\\Control\\DeviceMigration\\Devices\\USB\\"
             f"VID_{v}&PID_{p}\\{s}", FEATURE_UPDATE) \
        .binary("LastPresentDate", struct.pack("<Q", filetime(CRUZER_LAST_PRESENT))).sz("DeviceDesc", "USB Mass Storage Device")
    return root


def _software() -> Key:
    root = Key("ROOT", FEATURE_UPDATE)
    cv = root.key("Microsoft\\Windows NT\\CurrentVersion")
    cv.sz("ProductName", "Windows 10 Enterprise").sz("CurrentBuild", "19045").sz("DisplayVersion", "22H2")
    cv.qword("InstallTime", filetime(FEATURE_UPDATE)).dword("InstallDate", int(FEATURE_UPDATE.timestamp()))
    cv.key(f"ProfileList\\{SID}").sz("ProfileImagePath", f"C:\\Users\\{USER}", expand=True)

    dev_id, serial, label, vsn = SANDISK
    cv.key(f"EMDMgmt\\_??_USBSTOR#{dev_id}#{serial}&0#{DISK_CLASS}{label}_{vsn}", SANDISK_SEEN) \
        .dword("LastTestedTime", 0).dword("CacheSizeInMB", 0)

    wpd = root.key("Microsoft\\Windows Portable Devices\\Devices")
    for (dev_id, serial, label), when in ((KINGSTON, KINGSTON_SEEN), (VERBATIM, VERBATIM_SEEN)):
        wpd.key(f"SWD#WPDBUSENUM#_??_USBSTOR#{dev_id.upper()}#{serial}&0#{DISK_CLASS.upper()}", when) \
            .sz("FriendlyName", label)
    return root


def _ntuser() -> Key:
    root = Key("ROOT", HIVE_SAVED)
    mp2 = root.key("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2", VOLUME_SEEN)
    mp2.key(C_VOLUME, INSTALL_PREVIOUS).key("Shell", INSTALL_PREVIOUS)
    mp2.key(ORPHAN_VOLUME, VOLUME_SEEN).key("Shell", VOLUME_SEEN)
    return root


SETUPAPI_APP_LOG = """[Device Install Log]
     OS Version = 10.0.19045
     Service Pack = 0.0
     Suite = 0x0100
     ProductType = 1
     Architecture = amd64
"""


def build_wiped_host(dest: Path) -> list[str]:
    """Write the triage folder; return the files written (relative, '/'-separated), sorted."""
    dest = Path(dest)
    cfg = dest / "Windows" / "System32" / "config"
    write_hive(_system(), cfg / "SYSTEM", "\\SystemRoot\\System32\\Config\\SYSTEM", HIVE_SAVED)
    write_hive(_software(), cfg / "SOFTWARE", "\\SystemRoot\\System32\\Config\\SOFTWARE", HIVE_SAVED)
    write_hive(_ntuser(), dest / "Users" / USER / "NTUSER.DAT", f"\\??\\C:\\Users\\{USER}\\ntuser.dat", HIVE_SAVED)
    write_empty_evtx(dest / "Windows" / "System32" / "winevt" / "Logs" / "Microsoft-Windows-Partition%4Diagnostic.evtx")
    inf = dest / "Windows" / "INF"
    inf.mkdir(parents=True, exist_ok=True)
    (inf / "setupapi.app.log").write_bytes(SETUPAPI_APP_LOG.replace("\n", "\r\n").encode("ascii"))
    return sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
