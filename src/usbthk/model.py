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
LOG_CLEARED = "log_cleared"          # Security 1102 / System 104 (Microsoft-Windows-Eventlog)

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
    mbr_signatures: set[str] = field(default_factory=set)      # disk signature from the 1006 MBR, 8 hex
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
    # Every moment Windows (re)installed or upgraded itself: [{"ts": datetime, "source": str}].
    # Feature updates can purge Enum\USB, so these explain missing device keys (module #3).
    feature_updates: list[dict[str, Any]] = field(default_factory=list)
    sid_users: dict[str, str] = field(default_factory=dict)    # SOFTWARE ProfileList: SID -> user name
    sources: list[str] = field(default_factory=list)


@dataclass
class Evidence:
    """Everything parsed from one host."""
    host: HostInfo = field(default_factory=HostInfo)
    devices: dict[str, Device] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Artifacts that reference a device we could not link to Enum\USB. These are the
    # raw material for tamper/cleanup detection (module #3). Every entry has:
    #   artifact        MountedDevices | WindowsPortableDevices | EMDMgmt | MountPoints2
    #   id_type         usb_serial | volume_guid | volume_label | wpd_key | mbr_volume (only the first
    #                   two identify something tamper detection can reason about; mbr_volume is an
    #                   MBR-derived volume GUID, never stored in MountedDevices, so its absence proves nothing)
    #   id_value        the identifier itself
    #   ref_time        when the artifact last referenced it (UTC) or None
    #   ref_time_scope  "entry" (the entry's own key) | "parent_key" (an upper bound) | None
    #   user, details
    unlinked: list[dict[str, Any]] = field(default_factory=list)
    migrated: list[dict[str, Any]] = field(default_factory=list)      # DeviceMigration entries
    network_shares: list[dict[str, Any]] = field(default_factory=list)
    label_by_letter: dict[str, str] = field(default_factory=dict)      # VolumeInfoCache
    known_volume_guids: set[str] = field(default_factory=set)          # all MountedDevices GUIDs
    parsed: set[str] = field(default_factory=set)                      # artifact types parsed: SYSTEM, ...
    log_computers: dict[str, dict[str, int]] = field(default_factory=dict)  # log -> {Computer: records}
    # MBR-style volumes MountedDevices still letters: GUID -> {"signature": 8 hex, "offset": int, "letters": set}
    mbr_volumes: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Per-log record statistics: label -> {"records", "first_id", "last_id", "id_gaps", "oldest", "newest"}
    log_stats: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Program executions (BAM): {"path", "name", "ts", "sid", "user", "source"}
    executions: list[dict[str, Any]] = field(default_factory=list)
    # Files a triage folder should contain but does not (e.g. setupapi.dev.log next to a collected INF dir)
    collection_gaps: list[str] = field(default_factory=list)

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
