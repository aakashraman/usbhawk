"""Regression tests on public sample artifacts (MIT licensed):
  * regipy test hives            https://github.com/mkorman90/regipy
  * Partition-4DiagnosticParser  https://github.com/theAtropos4n6/Partition-4DiagnosticParser
Fetch them with:  python scripts/fetch_test_samples.py
"""

from usbthk.model import Evidence
from usbthk.parsers.evtx_logs import parse_partition_diagnostic
from usbthk.parsers.registry import link_drive_letters, parse_ntuser, parse_software, parse_system
from usbthk.scoring import load_config, score_sessions
from usbthk.sessions import build_sessions

from conftest import sample


def test_win7_full_registry_profile():
    ev = Evidence()
    parse_system(sample("SYSTEM"), ev)
    parse_software(sample("SOFTWARE"), ev)
    parse_ntuser(sample("NTUSER.DAT"), ev, "testuser")
    link_drive_letters(ev)
    d = ev.devices["VID_03F0&PID_3207\\AA951D0000007252"]
    assert d.device_class == "usbstor"
    assert d.device_id == "Disk&Ven_HP&Prod_v100w&Rev_1024"
    assert d.friendly_name == "HP v100w USB Device"
    assert d.drive_letters == {"E:"}
    assert d.volume_guids == {"{eba74da6-5bb2-11e0-95d1-000c2971073c}"}
    assert d.volume_names == {"SECRETPLANS"}
    assert d.vsns == {"B84479ED"}                      # EMDMgmt decimal 3091495405 -> hex
    assert ev.host.timezone_key == "Eastern Standard Time"


def test_win10_uasp_linked_via_parent_property():
    ev = Evidence()
    parse_system(sample("SYSTEM_WIN_10_1709"), ev)
    uasp = [d for d in ev.devices.values() if d.device_class == "uasp"]
    assert {(d.vendor, d.product) for d in uasp} == {("SanDisk", "Extreme SSD"), ("PHD 3.0", "Silicon-Power")}
    assert all(d.disk_ids for d in uasp)
    cruzer = ev.devices["VID_0781&PID_5530\\200608767007B7C08A6A"]
    assert cruzer.device_class == "usbstor" and cruzer.friendly_name == "SanDisk Cruzer USB Device"


def test_partition_diagnostic_detects_reformat():
    ev = Evidence()
    assert parse_partition_diagnostic(sample("Microsoft-Windows-Partition%4Diagnostic.evtx"), ev) == 30
    patriot = ev.devices["VID_13FE&PID_6300\\0701935D84A40B14"]
    assert {"C8B91B23", "54F63E46", "6ECA9A94", "DAFBDA6E"} <= patriot.vsns
    sessions = score_sessions(build_sessions(ev), load_config())
    flagged = [s for s in sessions if s.device is patriot
               and any(r["rule"] == "reformat_or_repartition" for r in s.reasons)]
    assert flagged, "Patriot stick was repartitioned/reformatted and must be flagged"
