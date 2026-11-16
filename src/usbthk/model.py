"""Normalised data model shared by every module in the toolkit.

Parsers turn raw artifacts into two things:
  * Device  - everything we know about one physical USB device on one host
  * Event   - a timestamped fact (connect, disconnect, file write, logon...)
The session builder and the scorers only ever see these objects, so new
artifact sources (EDR exports, Velociraptor, Linux) just need a new parser.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from .util import iso

# Event kinds
CONNECT = "connect"
DISCONNECT = "disconnect"
FIRST_INSTALL = "first_install"      # 0064 / setupapi / 20001
LAST_PRESENT = "last_present"        # DeviceMigration LastPresentDate
FILE_WRITE = "file_write"
FILE_READ = "file_read"
FILE_DELETE = "file_delete"
LOGON = "logon"
LOGOFF = "logoff"

# Device classes
USBSTOR = "usbstor"
UASP = "uasp"
MTP = "mtp"
HID = "hid"
OTHER = "other"

SERVICE_CLASS = {
    "USBSTOR": USBSTOR,
    "UASPSTOR": UASP,
    "WUDFWPDMTP": MTP,
    "WUDFWPDFS": MTP,
    "HIDUSB": HID,
}


@dataclass
class Device:
    key: str                                   # VID_xxxx&PID_yyyy\SERIAL
    vid: str
    pid: str
    serial: str
    device_class: str = OTHER
    service: str | None = None
    description: str | None = None
    device_id: str | None = None               # Disk&Ven_..&Prod_..&Rev_..
    friendly_name: str | None = None
    vendor: str | None = None
    product: str | None = None
    capacity_bytes: int | None = None
    windows_generated_serial: bool = False
    disk_ids: set[str] = field(default_factory=set)
    volume_names: set[str] = field(default_factory=set)
    drive_letters: set[str] = field(default_factory=set)
    volume_guids: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    vsns: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k, v in d.items():
            if isinstance(v, set):
                d[k] = sorted(v)
        return d


@dataclass
class Event:
    ts: datetime
    kind: str
    source: str                                # artifact that produced it
    device_key: str | None = None
    user: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"ts": iso(self.ts), "kind": self.kind, "source": self.source,
                "device_key": self.device_key, "user": self.user, "details": self.details}


@dataclass
class HostInfo:
    hostname: str | None = None
    os_product: str | None = None
    os_build: str | None = None
    timezone_key: str | None = None
    active_bias_minutes: int | None = None     # local = UTC - bias
    install_time: datetime | None = None       # last major install/feature update
    sources: list[str] = field(default_factory=list)


@dataclass
class Evidence:
    """Everything parsed from one host."""
    host: HostInfo = field(default_factory=HostInfo)
    devices: dict[str, Device] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Artifacts that reference a device we could not link to Enum\USB. These are the
    # raw material for tamper/cleanup detection (module #3).
    unlinked: list[dict[str, Any]] = field(default_factory=list)
    migrated: list[dict[str, Any]] = field(default_factory=list)      # DeviceMigration entries
    network_shares: list[dict[str, Any]] = field(default_factory=list)
    label_by_letter: dict[str, str] = field(default_factory=dict)      # VolumeInfoCache
    known_volume_guids: set[str] = field(default_factory=set)          # all MountedDevices GUIDs

    def device(self, vid: str, pid: str, serial: str, source: str) -> Device:
        from .util import device_key, is_windows_generated_serial
        key = device_key(vid, pid, serial)
        dev = self.devices.get(key)
        if dev is None:
            dev = Device(key=key, vid=vid.upper(), pid=pid.upper(), serial=serial.upper(),
                         windows_generated_serial=is_windows_generated_serial(serial))
            self.devices[key] = dev
        dev.sources.add(source)
        return dev

    def find_by_serial(self, serial: str) -> Device | None:
        serial = serial.upper()
        for dev in self.devices.values():
            if dev.serial == serial:
                return dev
        return None

    def find_by_disk_id(self, disk_id: str) -> Device | None:
        disk_id = disk_id.lower()
        for dev in self.devices.values():
            if disk_id in dev.disk_ids:
                return dev
        return None

    def add(self, event: Event) -> None:
        if event.ts is not None:
            self.events.append(event)


@dataclass
class Session:
    session_id: str
    host: str | None
    device: Device
    start: datetime | None = None
    end: datetime | None = None
    start_sources: list[str] = field(default_factory=list)
    end_sources: list[str] = field(default_factory=list)
    connect_events: int = 0
    vsns: list[str] = field(default_factory=list)
    filesystems: list[str] = field(default_factory=list)
    capacity_bytes: int | None = None
    users: list[str] = field(default_factory=list)
    file_events: list[Event] = field(default_factory=list)
    first_seen: bool = False
    score: int = 0
    severity: str = "info"
    reasons: list[dict[str, Any]] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.start and self.end:
            return (self.end - self.start).total_seconds()
        return None
