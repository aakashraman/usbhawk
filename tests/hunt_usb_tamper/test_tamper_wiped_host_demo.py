"""The fictional wiped host (examples/tamper/wiped-host): real regf hives and an emptied evtx, built by
wiped_host_builder.py, must produce every tamper finding the demo README documents, for the documented reasons."""

import struct

from regipy.registry import RegistryHive

from usbhawk import collect, tamper
from wiped_host_builder import (CRUZER, FEATURE_UPDATE, HOST, KINGSTON, ORPHAN_VOLUME, SANDISK, T7, USBOBLIVION_RUN,
                                USER, VERBATIM, build_wiped_host)


def findings(folder):
    ev = collect.load(collect.discover(str(folder)), verbose=lambda *_: None)
    return ev, tamper.find_tamper(ev)


def test_builder_is_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    files = build_wiped_host(a)
    assert files == build_wiped_host(b) == [
        "Users/m.ortiz/NTUSER.DAT", "Windows/INF/setupapi.app.log", "Windows/System32/config/SOFTWARE",
        "Windows/System32/config/SYSTEM", "Windows/System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx"]
    for f in files:
        assert (a / f).read_bytes() == (b / f).read_bytes(), f


def test_hives_are_valid_regf_and_read_back_like_windows_hives(tmp_path):
    build_wiped_host(tmp_path)
    raw = (tmp_path / "Windows/System32/config/SYSTEM").read_bytes()
    check = 0
    for (dw,) in struct.iter_unpack("<I", raw[:508]):
        check ^= dw
    assert raw[:4] == b"regf" and struct.unpack_from("<I", raw, 508)[0] == check        # header checksum
    assert len(raw) % 4096 == 0 and raw[4096:4100] == b"hbin"
    hive = RegistryHive(str(tmp_path / "Windows/System32/config/SYSTEM"))
    vid, pid, serial = T7
    props = ("\\ControlSet001\\Enum\\SCSI\\Disk&Ven_Samsung&Prod_PSSD_T7&Rev_0\\7&2f1b3a9c&0&000000\\Properties\\"
             "{83da6326-97a6-4088-9453-a1923f573b29}")
    parent = next(hive.get_key(props + "\\000A").iter_values(trim_values=False))
    arrival = next(hive.get_key(props + "\\0066").iter_values(trim_values=False))
    assert parent.value == f"USB\\VID_{vid}&PID_{pid}\\{serial}"                        # DEVPROP string, as on Windows
    assert arrival.value_type == "REG_FILETIME" and arrival.value.year == 2026        # DEVPROP FILETIME
    sel = {v.name: v.value for v in hive.get_key("\\Select").iter_values()}
    assert sel["Current"] == 1                                                        # inline DWORD


def test_wiped_host_raises_every_documented_finding(tmp_path):
    build_wiped_host(tmp_path)
    ev, found = findings(tmp_path)
    assert ev.host.hostname == HOST and not ev.warnings
    got = [(f.rule, f.severity, f.evidence.get("id_value") or f.evidence.get("tool") or f.evidence.get("artifact")
            or f.evidence.get("log")) for f in found]
    assert got == [
        ("orphaned_device_reference", "high", SANDISK[1]),           # EMDMgmt entry, medium -> high (tool after it)
        ("orphaned_device_reference", "high", KINGSTON[1]),          # Portable Devices entry, medium -> high
        ("cleanup_tool_execution", "high", "USBOblivion"),           # BAM
        ("orphaned_device_reference", "medium", ORPHAN_VOLUME),      # MountPoints2 volume, low -> medium
        ("partition_log_gap", "medium", "Partition/Diagnostic"),     # empty log, UASP disk arrived after the build
        ("expected_artifact_missing", "low", "setupapi.dev.log"),    # INF collected, setupapi.dev.log gone
        ("explained_by_feature_update", "info", VERBATIM[1]),        # last seen before the feature update
        ("explained_by_feature_update", "info", CRUZER[2]),          # archived in DeviceMigration
    ]


def test_wiped_host_reasons_name_the_user_tool_and_timing(tmp_path):
    build_wiped_host(tmp_path)
    _ev, found = findings(tmp_path)
    by = {(f.rule, f.evidence.get("id_value") or f.evidence.get("tool")): f for f in found}
    tool = by[("cleanup_tool_execution", "USBOblivion")]
    assert tool.ts == USBOBLIVION_RUN and tool.evidence["user"] == USER
    sandisk = by[("orphaned_device_reference", SANDISK[1])]
    assert "registry:EMDMgmt" in sandisk.why and "USBOblivion was run by m.ortiz" in sandisk.why
    assert sandisk.evidence["correlated_cleanup_tool"]["name"] == "USBOblivion64.exe"
    volume = by[("orphaned_device_reference", ORPHAN_VOLUME)]
    assert volume.evidence["user"] == USER and "registry:MountPoints2" in volume.why
    gap = next(f for f in found if f.rule == "partition_log_gap")
    assert gap.evidence["records"] == 0 and gap.evidence["current_build_installed"] == FEATURE_UPDATE
    assert [d["device"] for d in gap.evidence["devices"]] == [f"VID_{T7[0]}&PID_{T7[1]}\\{T7[2]}"]


def test_without_the_system_hive_orphan_checks_are_skipped_not_guessed(tmp_path):
    build_wiped_host(tmp_path)
    arts = collect.ArtifactSet(software=str(tmp_path / "Windows/System32/config/SOFTWARE"))
    found = tamper.find_tamper(collect.load(arts, verbose=lambda *_: None))
    assert [(f.rule, f.severity) for f in found] == [("orphan_checks_skipped", "info")]
    assert "3 referenced device(s)" in found[0].why
