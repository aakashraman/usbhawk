"""Device classes from real registry layouts, and the setupapi.dev.log archives Windows 11 writes.

Found on a real Windows 11 PC (release test case 3.8): its keyboards and mice are composite USB devices (service
usbccgp) whose interfaces (VID_x&PID_y&MI_nn) carry the HidUsb driver, so they were filed as "other"; the same
layout hides phones whose MTP interface sits next to an ADB one. The hives here are written with the regf writer
from wiped_host_builder.py, with fictional values.
"""

from usbhawk import collect
from usbhawk.model import Evidence
from usbhawk.parsers import registry
from wiped_host_builder import Key, utc, write_hive

T = utc("2026-10-29T18:00:00Z")


def _composite(root: Key, vid, pid, serial, prefix, interfaces):
    base = f"ControlSet001\\Enum\\USB\\VID_{vid}&PID_{pid}"
    root.key(f"{base}\\{serial}").sz("Service", "usbccgp").sz("DeviceDesc", "USB Composite Device") \
        .sz("ParentIdPrefix", prefix)
    for n, svc in enumerate(interfaces):
        root.key(f"{base}&MI_{n:02d}\\{prefix}&{n:04d}").sz("Service", svc)


def _classes(tmp_path, build) -> dict:
    root = Key("ROOT", T)
    root.key("Select").dword("Current", 1)
    build(root)
    path = tmp_path / "SYSTEM"
    write_hive(root, path, "\\SystemRoot\\System32\\Config\\SYSTEM", T)
    ev = Evidence()
    registry.parse_system(str(path), ev)
    return {d.serial: d.device_class for d in ev.devices.values()}


def test_composite_keyboard_and_mouse_are_hid(tmp_path):
    got = _classes(tmp_path, lambda r: _composite(r, "046D", "C52B", "NWRECEIVER01", "7&1A2B3C&0",
                                                  ["HidUsb", "HidUsb", "HidUsb"]))
    assert got == {"NWRECEIVER01": "hid"}


def test_composite_phone_with_mtp_and_adb_is_mtp(tmp_path):
    got = _classes(tmp_path, lambda r: _composite(r, "04E8", "6860", "R58NW0000001", "6&9F8E7D&0",
                                                  ["WUDFWpdMtp", "WINUSB"]))
    assert got == {"R58NW0000001": "mtp"}


def test_a_webcam_stays_other(tmp_path):
    got = _classes(tmp_path, lambda r: _composite(r, "30C9", "0001", "NWCAM0000001", "6&5A5A5A&0",
                                                  ["usbvideo", "WINUSB"]))
    assert got == {"NWCAM0000001": "other"}


def test_interfaces_belong_to_their_own_parent_only(tmp_path):
    """Two parents with the same VID/PID: each takes only the interfaces named after its ParentIdPrefix."""
    def build(r):
        _composite(r, "04E8", "6860", "R58NW0000001", "6&111111&0", ["WUDFWpdMtp"])
        base = "ControlSet001\\Enum\\USB\\VID_04E8&PID_6860"
        r.key(f"{base}\\R58NW0000002").sz("Service", "usbccgp").sz("ParentIdPrefix", "6&222222&0")
        r.key(f"{base}&MI_00\\6&222222&0&0000").sz("Service", "HidUsb")
    assert _classes(tmp_path, build) == {"R58NW0000001": "mtp", "R58NW0000002": "hid"}


def test_plain_storage_and_direct_mtp_are_unchanged(tmp_path):
    def build(r):
        r.key("ControlSet001\\Enum\\USB\\VID_0951&PID_1666\\NWSTICK00001").sz("Service", "USBSTOR")
        r.key("ControlSet001\\Enum\\USB\\VID_18D1&PID_4EE1\\NWPIXEL00001").sz("Service", "WUDFWpdMtp")
    assert _classes(tmp_path, build) == {"NWSTICK00001": "usbstor", "NWPIXEL00001": "mtp"}


# --------------------------------------------------------------------------- setupapi.dev.log archives
def _inf(tmp_path, *names):
    inf = tmp_path / "C" / "Windows" / "INF"
    inf.mkdir(parents=True)
    for n in names:
        (inf / n).write_text("[Device Install Log]\n", encoding="ascii")
    return collect.discover(str(tmp_path))


def test_rotated_setupapi_archives_are_all_read(tmp_path):
    arts = _inf(tmp_path, "setupapi.dev.log", "setupapi.dev.20260906_163851.log", "setupapi.dev.20261014_083452.log")
    assert len(arts.setupapi) == 3 and arts.missing == []


def test_archives_without_the_current_log_still_count_as_missing(tmp_path):
    """A cleaner that deletes the live setupapi.dev.log may leave the archives: that is still the gap rule 5 means."""
    arts = _inf(tmp_path, "setupapi.dev.20260906_163851.log")
    assert arts.missing == ["setupapi.dev.log"]
