from usbhawk.util import (decode_utf16_path, filetime_to_dt, is_windows_generated_serial,
                         mbr_partitions, parse_usb_instance, parse_usbstor_path, strip_lun,
                         vsn_from_vbr)

from conftest import utc


def test_filetime_bytes_and_int():
    assert filetime_to_dt(bytes.fromhex("006E0AB4B368DD01")) == utc(2026, 10, 30, 21, 14, 52)
    assert filetime_to_dt(134378684920000000) == utc(2026, 10, 30, 21, 14, 52)
    assert filetime_to_dt(0) is None


def _vbr(oem=None, at=None, serial=b"\xD7\x41\x2C\x8E", fs_label=None, label_at=None):
    v = bytearray(512)
    if oem:
        v[3:11] = oem
    if fs_label:
        v[label_at:label_at + len(fs_label)] = fs_label
    v[at:at + len(serial)] = serial
    return v.hex()


def test_vsn_offsets_all_filesystems():
    assert vsn_from_vbr(_vbr(b"EXFAT   ", 0x64)) == "8E2C41D7"
    assert vsn_from_vbr(_vbr(b"NTFS    ", 0x48, b"\xD7\x41\x2C\x8E\x11\x22\x33\x44")) == "8E2C41D7"
    assert vsn_from_vbr(_vbr(None, 0x43, fs_label=b"FAT32   ", label_at=0x52)) == "8E2C41D7"
    assert vsn_from_vbr(_vbr(None, 0x27, fs_label=b"FAT16   ", label_at=0x36)) == "8E2C41D7"
    assert vsn_from_vbr("") is None


def test_mbr_partition_entry():
    m = bytearray(512)
    m[0x1BE:0x1CE] = bytes.fromhex("0020210007FEFFFF00080000F42B9A03")
    assert list(mbr_partitions(m.hex())) == [(0, "0x07", 2048, 60435444)]


def test_identifier_parsing():
    assert parse_usb_instance(r"USB\VID_0951&PID_1666\60A44C413D5FF380E95A0B7D") == (
        "0951", "1666", "60A44C413D5FF380E95A0B7D")
    # WPD / MountedDevices style with '#'
    assert parse_usb_instance("WPDBUSENUMROOT#UMB#..#USB#VID_18D1&PID_4EE1#0A1B2C3D#{6ac27878}")[2] == "0A1B2C3D"
    # composite interface children are not devices
    assert parse_usb_instance(r"USB\VID_0E0F&PID_0003&MI_00\7&1234&0&0000") is None
    md = "_??_USBSTOR#Disk&Ven_HP&Prod_v100w&Rev_1024#AA951D0000007252&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
    assert parse_usbstor_path(md) == ("Disk&Ven_HP&Prod_v100w&Rev_1024", "AA951D0000007252")
    assert strip_lun("AA951D0000007252&0") == "AA951D0000007252"
    assert is_windows_generated_serial("7&2A3B5C1D&0")
    assert not is_windows_generated_serial("AA951D0000007252")


def test_mounted_devices_hex_string_decode():
    raw = "_??_USBSTOR#Disk&Ven_X&Prod_Y#SER123&0#{guid}".encode("utf-16le")
    assert decode_utf16_path(raw.hex()).startswith("_??_USBSTOR")
    assert decode_utf16_path("3ea0be5c0000100000000000") is None   # MBR disk signature, not a path
