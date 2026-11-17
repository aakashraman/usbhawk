"""Test helper: write a fictional fleet with the REAL per-host writers of modules #2 and #3.

Each host gets the files `usbhawk sessions --out` / `usbhawk tamper --out` produce (devices.jsonl, sessions.jsonl,
tamper.jsonl), so the graph is tested against the exact output format, not a hand-made imitation.
Fictional hosts NW-FIN-WS042, NW-HR-WS007, NW-ENG-LT113; users NW\\j.doe, NW\\a.smith, NW\\k.lee.
"""

from __future__ import annotations

from datetime import timedelta

from usbhawk.model import FILE_WRITE, Event, Evidence, Session
from usbhawk.output import write_devices, write_findings, write_jsonl
from usbhawk.tamper import Finding
from usbhawk.util import to_utc

T0 = to_utc("2026-10-30T21:14:00Z")
KINGSTON = ("0951", "1666", "60A44C413D5FF380E95A0B7D")


class HostRun:
    def __init__(self, name: str):
        self.ev = Evidence()
        self.ev.host.hostname = name
        self.name = name
        self.sessions: list[Session] = []
        self.findings: list[Finding] = []

    def stick(self, vid="0951", pid="1666", serial="60A44C413D5FF380E95A0B7D", *, cls="usbstor", vsns=(),
              volume_names=(), capacity=31_000_000_000, product="DataTraveler 3.0", vendor="Kingston", reg_users=()):
        dev = self.ev.device(vid, pid, serial, "registry:Enum\\USB")
        dev.device_class, dev.product, dev.vendor, dev.capacity_bytes = cls, product, vendor, capacity
        dev.vsns.update(vsns)
        dev.volume_names.update(volume_names)
        dev.users.update(reg_users)
        return dev

    def session(self, dev, start=T0, minutes=20, users=("NW\\j.doe",), score=0, severity="info", writes=0):
        s = Session(session_id=f"{self.name}-{len(self.sessions)}", host=self.name, device=dev, start=start,
                    end=start + timedelta(minutes=minutes), users=list(users), score=score, severity=severity,
                    vsns=sorted(dev.vsns))
        s.file_events = [Event(start + timedelta(seconds=i), FILE_WRITE, "test", dev.key,
                               details={"path": f"F:\\Q3\\doc{i:02d}.docx", "size": 1000}) for i in range(writes)]
        self.sessions.append(s)
        return s

    def wiped(self, serial: str, when=T0):
        """A module #3 finding: this stick's Enum keys were deleted on this host."""
        self.findings.append(Finding(
            "orphaned_device_reference", "high",
            f"USB serial {serial} still appears in evtx:Partition/Diagnostic but is missing from Enum\\USB/USBSTOR/SCSI; "
            f"the device keys were likely deleted (e.g. USBOblivion or manual cleanup).",
            {"id_type": "usb_serial", "id_value": serial, "device_key": None, "last_reference": when}, when, self.name))

    def write(self, root) -> str:
        d = root / self.name
        d.mkdir(parents=True, exist_ok=True)
        write_devices(self.ev, str(d / "devices.jsonl"))
        write_jsonl(self.sessions, str(d / "sessions.jsonl"))
        if self.findings:
            write_findings(self.findings, str(d / "tamper.jsonl"))
        return str(d)


def write_fleet(root, *hosts: HostRun) -> list[str]:
    return [h.write(root) for h in hosts]
