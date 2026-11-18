"""Real collections hold more than one file per hive name: KAPE and Velociraptor also copy config\\RegBack (0-byte
placeholders since Windows 10 1803) and may copy Windows.old. Only the live hive in Windows\\System32\\config may be
used. Before this was fixed, an empty RegBack\\SYSTEM replaced the real hive and every device finding was lost."""

import shutil

from usbhawk import collect, tamper
from wiped_host_builder import HOST, build_wiped_host

CFG = "Windows/System32/config"


def _touch(path, data=b""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _findings(folder):
    ev = collect.load(collect.discover(str(folder)), verbose=lambda *_: None)
    return ev, [(f.rule, f.severity) for f in tamper.find_tamper(ev)]


def test_kape_layout_with_empty_regback_uses_the_live_hives(tmp_path):
    plain, kape = tmp_path / "plain", tmp_path / "kape"
    build_wiped_host(plain)
    shutil.copytree(plain, kape / "C")                       # KAPE: <tdest>\C\Windows\...
    for name in ("SYSTEM", "SOFTWARE"):
        _touch(kape / "C" / CFG / "RegBack" / name)           # the 0-byte RegBack placeholders KAPE collects
    arts = collect.discover(str(kape))
    assert arts.system.replace("\\", "/").endswith(f"C/{CFG}/SYSTEM")
    assert arts.software.replace("\\", "/").endswith(f"C/{CFG}/SOFTWARE")
    assert sorted(why for _p, why in arts.skipped) == ["empty file", "empty file"]
    ev, got = _findings(kape)
    assert ev.host.hostname == HOST
    assert got == _findings(plain)[1] and ("cleanup_tool_execution", "high") in got


def test_older_copies_never_replace_the_live_hive(tmp_path):
    build_wiped_host(tmp_path)
    live = (tmp_path / CFG / "SYSTEM").read_bytes()
    _touch(tmp_path / CFG / "RegBack" / "SYSTEM", live)                           # non-empty backup (pre-1803)
    _touch(tmp_path / "Windows.old" / CFG / "SYSTEM", live)                      # previous installation
    arts = collect.discover(str(tmp_path))
    assert arts.system.replace("\\", "/").endswith(f"/{CFG}/SYSTEM") and "Windows.old" not in arts.system
    reasons = sorted(why for _p, why in arts.skipped)
    assert reasons == ["RegBack backup copy (older than the live hive)", "Windows.old (a previous Windows installation)"]


def test_a_backup_is_used_when_it_is_the_only_copy(tmp_path):
    build_wiped_host(tmp_path / "src")
    hive = (tmp_path / "src" / CFG / "SYSTEM").read_bytes()
    _touch(tmp_path / "case" / CFG / "RegBack" / "SYSTEM", hive)
    arts = collect.discover(str(tmp_path / "case"))
    assert arts.system and "RegBack" in arts.system and not arts.skipped


def test_hand_copied_flat_folder_still_works(tmp_path):
    build_wiped_host(tmp_path / "src")
    flat = tmp_path / "flat"
    for rel in (f"{CFG}/SYSTEM", f"{CFG}/SOFTWARE"):
        _touch(flat / rel.rsplit("/", 1)[1], (tmp_path / "src" / rel).read_bytes())
    arts = collect.discover(str(flat))
    assert arts.system and arts.software and not arts.skipped


def test_velociraptor_layout_with_encoded_names(tmp_path):
    """Velociraptor keeps the drive in an encoded folder (C%3A) and encodes '%' in file names as %25."""
    build_wiped_host(tmp_path / "src")
    up = tmp_path / "collection" / "uploads" / "auto" / "C%3A"
    shutil.copytree(tmp_path / "src", up)
    logs = up / "Windows/System32/winevt/Logs"
    (logs / "Microsoft-Windows-Partition%4Diagnostic.evtx").rename(logs / "Microsoft-Windows-Partition%254Diagnostic.evtx")
    arts = collect.discover(str(tmp_path / "collection"))
    assert arts.system and arts.software and len(arts.partition_diag) == 1
    assert [u for _p, u in arts.ntuser] == ["m.ortiz"]
    assert _findings(tmp_path / "collection")[1] == _findings(tmp_path / "src")[1]
