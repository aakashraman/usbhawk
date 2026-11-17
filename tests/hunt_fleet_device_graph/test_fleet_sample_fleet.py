"""Module #1: the fictional fleet shown in docs/hunt-fleet-device-graph.md ("Use cases and sample output").

Four hosts: a Kingston stick with a high-risk session on Finance travels to HR and Engineering; a SanDisk wiped with
USBOblivion on Ops is still recorded on HR; a new stick appears on HR; two cheap sticks share a fake serial.
All six fleet hunts must fire, with the details the documentation shows.
"""

from datetime import timedelta

from usbthk.graph import build_fleet

from fleet_builder import T0, HostRun, write_fleet

FIN, HR, ENG, OPS = "NW-FIN-WS042", "NW-HR-WS007", "NW-ENG-LT113", "NW-OPS-WS019"


def documented_fleet(root):
    fin, hr, eng, ops = HostRun(FIN), HostRun(HR), HostRun(ENG), HostRun(OPS)
    fin.session(fin.stick(vsns={"8E2C41D7"}, volume_names={"Q3-BOARD"}), score=85, severity="high", writes=61,
                users=[r"NW\j.doe"])
    hr.session(hr.stick(vsns={"8E2C41D7"}), start=T0 + timedelta(days=1), users=[r"NW\a.smith"])
    eng.session(eng.stick(), start=T0 + timedelta(days=3), users=[r"NW\k.lee"])
    ops.wiped("4C530001230601105525")
    hr.session(hr.stick("0781", "5581", "4C530001230601105525", product="Ultra", vendor="SanDisk"),
               start=T0 - timedelta(days=2), users=[r"NW\a.smith"])
    ops.session(ops.stick("13FE", "6300", "0701935D84A40B14", product="Rage", vendor="Patriot"),
                start=T0 - timedelta(days=120), users=[r"NW\m.ortiz"])
    eng.session(eng.stick("0951", "1642", "001CC0EC3477F9B0C7C41D3D", product="DataTraveler G4"),
                start=T0 + timedelta(days=4), users=[r"NW\k.lee"])
    fin.session(fin.stick("FFFF", "5678", "0123456789ABCDEF", product="USB Disk", vendor="Generic", vsns={"AAAA1111"}),
                users=[r"NW\j.doe"])
    ops.session(ops.stick("FFFF", "5678", "0123456789ABCDEF", product="USB Disk", vendor="Generic", vsns={"BBBB2222"}),
                users=[r"NW\m.ortiz"])
    return build_fleet(write_fleet(root, fin, hr, eng, ops))


def test_all_six_fleet_hunts_fire(tmp_path):
    rules = [f.rule for f in documented_fleet(tmp_path).hunt()]
    assert {"wiped_here_seen_there", "exfil_device_spread", "device_on_many_hosts", "device_shared_by_users",
            "new_to_fleet", "serial_collision"} == set(rules)
    assert rules[:2] == ["wiped_here_seen_there", "exfil_device_spread"]             # the two highs come first


def test_documented_details(tmp_path):
    by = {}
    for f in documented_fleet(tmp_path).hunt():
        by.setdefault(f.rule, f)
    assert "NW-HR-WS007 still holds its history" in by["wiped_here_seen_there"].why
    assert by["exfil_device_spread"].evidence["also_on"] == [ENG, HR]
    assert by["device_on_many_hosts"].evidence["confidence"] == "high"
    assert by["device_shared_by_users"].evidence["users"] == ["a.smith", "j.doe", "k.lee"]
    assert "0123456789ABCDEF" in by["serial_collision"].why


def test_documented_pivot(tmp_path):
    rows = documented_fleet(tmp_path).find_device("60A44C41")[0].per_host()
    assert [(r["host"], r["max_score"], r["writes"]) for r in rows] == [(FIN, 85, 61), (HR, 0, 0), (ENG, 0, 0)]
