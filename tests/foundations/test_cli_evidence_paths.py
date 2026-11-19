"""A file named on the command line must exist (1.0.2).

Real case: after replaying a dirty hive with rla.exe, `--system clean-hives\\SYSTEM` pointed at a file that did not
exist (rla names its output after the source path: F_C_Windows_System32_config_SYSTEM). The run warned, went on
without SYSTEM as "unknown-host" and skipped every orphan check. Now it stops and suggests the file rla wrote.
"""

import pathlib
import shutil

from usbhawk.cli import main

ROOT = pathlib.Path(__file__).resolve().parents[2]
WIPED = ROOT / "examples" / "tamper" / "wiped-host"
HIVE = WIPED / "Windows" / "System32" / "config" / "SYSTEM"


def test_missing_system_hive_stops_and_suggests_the_rla_name(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    clean = tmp_path / "clean-hives"
    clean.mkdir()
    shutil.copy(HIVE, clean / "F_C_Windows_System32_config_SYSTEM")
    rc = main(["tamper", "--triage", str(WIPED), "--system", str(clean / "SYSTEM")])
    err = capsys.readouterr().err
    assert rc == 2
    assert f"--system file not found: {clean / 'SYSTEM'}" in err
    assert f'did you mean: --system "{clean / "F_C_Windows_System32_config_SYSTEM"}"' in err
    assert "rla.exe names a replayed hive" in err
    assert "loading artifacts" not in err                     # nothing was run on half the evidence


def test_every_missing_file_is_listed_and_ntuser_user_is_not_part_of_the_path(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    rc = main(["sessions", "--triage", str(WIPED), "--software", str(tmp_path / "SOFTWARE"),
               "--ntuser", f"{tmp_path / 'NTUSER.DAT'}=j.doe"])
    err = capsys.readouterr().err
    assert rc == 2
    assert f"--software file not found: {tmp_path / 'SOFTWARE'}" in err
    assert f"--ntuser file not found: {tmp_path / 'NTUSER.DAT'}" in err and "=j.doe" not in err
    assert "did you mean" not in err                          # nothing similar in that folder


def test_existing_explicit_hive_is_used(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    clean = tmp_path / "clean-hives"
    clean.mkdir()
    shutil.copy(HIVE, clean / "F_C_Windows_System32_config_SYSTEM")
    rc = main(["tamper", "--triage", str(WIPED), "--system", str(clean / "F_C_Windows_System32_config_SYSTEM")])
    out = capsys.readouterr()
    assert rc == 0
    assert "file not found" not in out.err and "unknown-host" not in out.out
