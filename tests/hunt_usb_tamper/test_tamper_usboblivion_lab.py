"""Regressions found in the module #3 lab test (USBOblivion on a Windows 10 VM, 2026-11-16).

Each test reproduces one real-world failure with fictional values (no lab data is committed):

  A  regipy trims REG_BINARY values to 128 bytes unless told not to, so a USBSTOR device path in
     MountedDevices lost the end of its serial and the stick looked "missing from Enum".
  B  MBR disks get volume GUIDs derived from the disk signature + partition offset
     ({SSSSSSSS-0000-0000-OOOO-OOOOOOOOOOOO}); dynamic disks store "DMIO:ID:" + the volume GUID.
     Neither is listed as a \\??\\Volume{...} name, so the host's own C: drive, a mounted evidence image
     and a USB disk still in Enum were all reported as orphaned volumes.
  C  A log clear was tied to an orphan whose last reference came *after* the clear (Explorer recreated a
     MountPoints2 key after the cleanup). Cleanup follows use, so only a later clear can correlate.
"""

import struct
import uuid
from datetime import timedelta

import usbthk.parsers.registry as registry
from usbthk.model import Evidence
from usbthk.tamper import find_tamper
from usbthk.util import decode_utf16_path, is_mbr_volume_guid, mounted_volume_guid, parse_usbstor_path

from test_tamper_scenarios import SEEN, by_rule, host, log_cleared, wiped_device

SERIAL = "4C530001230601105525"          # fictional, 20 chars: long enough to cross the 128-byte cut
USBSTOR_PATH = (f"_??_USBSTOR#Disk&Ven_Generic&Prod_Mass_Storage&Rev_1100#{SERIAL}&0#"
                "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")
SIG = 0x1A2B3C4D                         # fictional MBR disk signature
DYN = uuid.UUID("0a1b2c3d-4e5f-4061-8273-a4b5c6d7e8f9")   # fictional dynamic-volume GUID


# --------------------------------------------------------------------------- fakes for regipy objects
class FakeValue:
    def __init__(self, name, value, value_type):
        self.name, self.value, self.value_type = name, value, value_type


class FakeHeader:
    last_modified = None                  # _last_write() tolerates a missing timestamp


class FakeKey:
    """Behaves like regipy: REG_BINARY comes back as a hex string cut to 256 chars unless trim_values=False."""

    def __init__(self, name="", values=(), subkeys=()):
        self.name, self._values, self._subkeys, self.header = name, list(values), list(subkeys), FakeHeader()

    def iter_values(self, trim_values=True):
        for name, raw, vt in self._values:
            if vt == "REG_BINARY":
                yield FakeValue(name, raw.hex()[:256] if trim_values else raw, vt)
            else:
                yield FakeValue(name, raw, vt)

    def iter_subkeys(self):
        return iter(self._subkeys)


class FakeHive:
    def __init__(self, keys):
        self.keys = keys

    def get_key(self, path):
        if path not in self.keys:
            raise KeyError(path)
        return self.keys[path]


def mbr_value(sig, offset):
    return struct.pack("<IQ", sig, offset)


# --------------------------------------------------------------------------- A: full-length values
def test_a_registry_values_are_read_untrimmed():
    raw = USBSTOR_PATH.encode("utf-16le")
    assert len(raw) > 128
    key = FakeKey(values=[("\\??\\Volume{aaaaaaaa-1111-11f0-b4a1-000c29aabbcc}", raw, "REG_BINARY")])
    value = registry._values(key)["\\??\\Volume{aaaaaaaa-1111-11f0-b4a1-000c29aabbcc}"]
    assert isinstance(value, str)                        # still a hex string, as downstream code expects
    assert parse_usbstor_path(decode_utf16_path(value))[1] == SERIAL


# --------------------------------------------------------------------------- B: derived volume GUIDs
def test_b_mbr_signature_and_offset_give_the_volume_guid():
    assert mounted_volume_guid(mbr_value(SIG, 0x100000)) == "{1a2b3c4d-0000-0000-0000-100000000000}"
    assert mounted_volume_guid(mbr_value(SIG, 0x10000)) == "{1a2b3c4d-0000-0000-0000-010000000000}"
    assert mounted_volume_guid(mbr_value(SIG, 0x7E00)) == "{1a2b3c4d-0000-0000-007e-000000000000}"
    assert mounted_volume_guid(mbr_value(SIG, 0x100000).hex()) == "{1a2b3c4d-0000-0000-0000-100000000000}"


def test_b_dynamic_disk_value_gives_the_volume_guid():
    assert mounted_volume_guid(b"DMIO:ID:" + DYN.bytes_le) == "{%s}" % DYN


def test_b_device_paths_and_junk_give_no_guid():
    assert mounted_volume_guid(USBSTOR_PATH.encode("utf-16le")) is None
    assert mounted_volume_guid(b"\x01\x02") is None
    assert mounted_volume_guid(None) is None


def test_b_mbr_style_guids_are_recognised():
    assert is_mbr_volume_guid("{1a2b3c4d-0000-0000-0000-100000000000}")
    assert is_mbr_volume_guid("{1A2B3C4D-0000-0000-007E-000000000000}")
    assert not is_mbr_volume_guid("{0d5c3b2a-1f1e-11f0-b4a1-000c29aabbcc}")   # Mount Manager GUID


def test_b_mounted_devices_letters_make_their_volumes_known():
    ev = Evidence()
    hive = FakeHive({"\\MountedDevices": FakeKey(values=[
        ("\\DosDevices\\C:", mbr_value(SIG, 0x100000), "REG_BINARY"),
        ("\\DosDevices\\G:", b"DMIO:ID:" + DYN.bytes_le, "REG_BINARY"),
    ])})
    registry._parse_mounted_devices(hive, ev)
    assert {"{1a2b3c4d-0000-0000-0000-100000000000}", "{%s}" % DYN} <= ev.known_volume_guids


def test_b_mountpoints2_only_reports_mount_manager_guids(monkeypatch):
    """MBR-derived GUIDs are always kept (typed mbr_volume, ignored by tamper) so link_mbr_volumes() can
    attribute the user once the disk signature is known; a vanished Mount Manager GUID is a volume_guid."""
    ev = Evidence()
    ev.known_volume_guids.add("{1a2b3c4d-0000-0000-0000-100000000000}")     # still lettered (C:)
    base = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
    subs = [FakeKey("{1a2b3c4d-0000-0000-0000-100000000000}"),                # known
            FakeKey("{9f8e7d6c-0000-0000-0000-010000000000}"),                # MBR-derived, not lettered
            FakeKey("{0d5c3b2a-1f1e-11f0-b4a1-000c29aabbcc}")]                # MountMgr GUID, gone
    monkeypatch.setattr(registry, "RegistryHive", lambda _path: FakeHive({base: FakeKey(subkeys=subs)}))
    registry.parse_ntuser("NTUSER.DAT", ev, "j.doe")
    types = {u["id_value"]: u["id_type"] for u in ev.unlinked}
    assert types == {"{1a2b3c4d-0000-0000-0000-100000000000}": "mbr_volume",
                     "{9f8e7d6c-0000-0000-0000-010000000000}": "mbr_volume",
                     "{0d5c3b2a-1f1e-11f0-b4a1-000c29aabbcc}": "volume_guid"}


def test_b_tamper_ignores_mbr_derived_volumes():
    ev = host()
    ev.unlinked.append({"artifact": "MountPoints2", "id_type": "mbr_volume",
                        "id_value": "{9f8e7d6c-0000-0000-0000-010000000000}", "ref_time": SEEN,
                        "ref_time_scope": "entry", "user": "j.doe", "details": {}})
    assert find_tamper(ev) == []


# --------------------------------------------------------------------------- C: correlation direction
def test_c_log_clear_before_the_last_reference_does_not_raise():
    ev = host()
    wiped_device(ev)
    log_cleared(ev, SEEN - timedelta(hours=2))
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert f.severity == "medium"
    assert f.evidence["correlated_log_clear"] is None
