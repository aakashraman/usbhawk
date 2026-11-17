"""Module #1: fleet hunts G1-G6, each tested on both sides of its threshold.

G1 device_on_many_hosts   G2 device_shared_by_users   G3 exfil_device_spread   G4 wiped_here_seen_there
G5 new_to_fleet           G6 serial_collision
"""

from datetime import timedelta

from usbthk.graph import build_fleet

from fleet_builder import T0, HostRun, write_fleet

WS042, WS007, LT113 = "NW-FIN-WS042", "NW-HR-WS007", "NW-ENG-LT113"


def hunt(tmp_path, *hosts, **kw):
    f = build_fleet(write_fleet(tmp_path, *hosts))
    out = {}
    for x in f.hunt(**kw):
        out.setdefault(x.rule, []).append(x)
    return out


def on_hosts(names, user_of=None, **stick):
    hosts = []
    for n in names:
        h = HostRun(n)
        dev = h.stick(**stick)
        h.session(dev, users=[user_of(n)] if user_of else ["NW\\j.doe"])
        hosts.append(h)
    return hosts


# --------------------------------------------------------------------------- G1
def test_g1_fires_at_the_threshold_and_not_below(tmp_path):
    three = hunt(tmp_path / "a", *on_hosts([WS042, WS007, LT113]))
    two = hunt(tmp_path / "b", *on_hosts([WS042, WS007]))
    assert three["device_on_many_hosts"][0].severity == "medium" and "device_on_many_hosts" not in two
    f = three["device_on_many_hosts"][0]
    assert {WS042, WS007, LT113} == set(f.evidence["hosts"]) and "60A44C413D5FF380E95A0B7D" in f.why


def test_g1_threshold_is_configurable(tmp_path):
    assert "device_on_many_hosts" in hunt(tmp_path, *on_hosts([WS042, WS007]), min_hosts=2)


# --------------------------------------------------------------------------- G2
def test_g2_shared_between_users(tmp_path):
    users = {WS042: "NW\\j.doe", WS007: "NW\\a.smith"}
    shared = hunt(tmp_path / "a", *on_hosts([WS042, WS007], user_of=users.get))
    same = hunt(tmp_path / "b", *on_hosts([WS042, WS007]))
    assert set(shared["device_shared_by_users"][0].evidence["users"]) == {"a.smith", "j.doe"}
    assert "device_shared_by_users" not in same


def test_g2_mountpoints2_label_is_the_same_user(tmp_path):
    """Lab-found: module #2 writes users attributed via MountPoints2 as 'name (MountPoints2)'."""
    a = HostRun(WS042)
    dev = a.stick(reg_users=["j.doe (MountPoints2)"])
    a.session(dev, users=["NW\\j.doe"])
    a.session(dev, users=["j.doe (MountPoints2)"], start=T0 + timedelta(days=1))
    assert "device_shared_by_users" not in hunt(tmp_path, a)


def test_g2_domain_spelling_and_machine_accounts_do_not_count(tmp_path):
    spellings = {WS042: "NW\\j.doe", WS007: "J.DOE", LT113: "NW-ENG-LT113$"}
    out = hunt(tmp_path, *on_hosts([WS042, WS007, LT113], user_of=spellings.get))
    assert "device_shared_by_users" not in out


# --------------------------------------------------------------------------- G3
def test_g3_high_risk_session_and_the_stick_went_elsewhere(tmp_path):
    a, b = HostRun(WS042), HostRun(WS007)
    a.session(a.stick(), score=85, severity="high", writes=12)
    b.session(b.stick(), start=T0 + timedelta(days=2), users=["NW\\a.smith"])
    f = hunt(tmp_path, a, b)["exfil_device_spread"][0]
    assert f.severity == "high" and f.evidence["high_risk_on"] == [WS042] and f.evidence["also_on"] == [WS007]


def test_g3_needs_a_second_host(tmp_path):
    a = HostRun(WS042)
    a.session(a.stick(), score=85, severity="high")
    assert "exfil_device_spread" not in hunt(tmp_path, a)


def test_g3_needs_a_high_risk_session(tmp_path):
    a, b = HostRun(WS042), HostRun(WS007)
    a.session(a.stick(), score=40, severity="medium")
    b.session(b.stick())
    assert "exfil_device_spread" not in hunt(tmp_path, a, b)


# --------------------------------------------------------------------------- G4
def test_g4_wiped_on_one_host_history_on_another(tmp_path):
    a, b = HostRun(WS042), HostRun(WS007)
    a.wiped("60A44C413D5FF380E95A0B7D")
    b.session(b.stick())
    f = hunt(tmp_path, a, b)["wiped_here_seen_there"][0]
    assert f.severity == "high" and f.evidence["wiped_on"] == [WS042] and f.evidence["history_on"] == [WS007]
    assert f"{WS007} still holds its history" in f.why and "seen on one host" not in f.why


def test_g4_the_wiping_host_is_not_counted_as_history(tmp_path):
    """Module #3 often still knows the wiped stick on the wiping host (Partition log): that is not 'elsewhere'."""
    a, b = HostRun(WS042), HostRun(WS007)
    a.wiped("60A44C413D5FF380E95A0B7D")
    survivor = a.stick(cls="other", vsns={"8E2C41D7"})
    survivor.sources = {"evtx:Partition/Diagnostic"}
    b.session(b.stick())
    f = hunt(tmp_path, a, b)["wiped_here_seen_there"][0]
    assert f.evidence["wiped_on"] == [WS042] and f.evidence["history_on"] == [WS007]


def test_g4_only_the_wiping_host_knows_the_stick(tmp_path):
    a = HostRun(WS042)
    a.wiped("60A44C413D5FF380E95A0B7D")
    survivor = a.stick(cls="other", vsns={"8E2C41D7"})
    survivor.sources = {"evtx:Partition/Diagnostic"}
    assert "wiped_here_seen_there" not in hunt(tmp_path, a)


def test_g4_wiped_but_nowhere_else(tmp_path):
    a, b = HostRun(WS042), HostRun(WS007)
    a.wiped("60A44C413D5FF380E95A0B7D")
    b.session(b.stick(serial="AA951D0000007252"))
    assert "wiped_here_seen_there" not in hunt(tmp_path, a, b)


# --------------------------------------------------------------------------- G5
def test_g5_new_to_the_fleet(tmp_path):
    a, b = HostRun(WS042), HostRun(WS007)
    a.session(a.stick(serial="AA951D0000007252"), start=T0 - timedelta(days=200))      # old stick, sets history
    b.session(b.stick(), start=T0)                                                     # brand-new stick
    out = hunt(tmp_path, a, b)
    new = [f for f in out.get("new_to_fleet", []) if "60A44C41" in f.why]
    old = [f for f in out.get("new_to_fleet", []) if "AA951D00" in f.why]
    assert new and new[0].severity == "low" and not old


def test_g5_needs_enough_fleet_history(tmp_path):
    """With only 10 days of data every stick would look 'new': stay quiet instead."""
    a, b = HostRun(WS042), HostRun(WS007)
    a.session(a.stick(serial="AA951D0000007252"), start=T0 - timedelta(days=10))
    b.session(b.stick(), start=T0)
    assert "new_to_fleet" not in hunt(tmp_path, a, b)


def test_g5_not_for_a_stick_seen_on_several_hosts(tmp_path):
    assert "new_to_fleet" not in hunt(tmp_path, *on_hosts([WS042, WS007]))


# --------------------------------------------------------------------------- G6
def test_g6_same_serial_different_vendor_product(tmp_path):
    a, b = HostRun(WS042), HostRun(WS007)
    a.session(a.stick("0951", "1666", "ABCDEF0123456789AB"))
    b.session(b.stick("13FE", "6300", "ABCDEF0123456789AB"))
    f = hunt(tmp_path, a, b)["serial_collision"][0]
    assert f.severity == "info" and "ABCDEF0123456789AB" in f.why


def test_g6_fake_serial_shared_by_different_sticks(tmp_path):
    a, b = HostRun(WS042), HostRun(WS007)
    a.session(a.stick("FFFF", "5678", "0123456789ABCDEF", vsns={"AAAA1111"}))
    b.session(b.stick("FFFF", "5678", "0123456789ABCDEF", vsns={"BBBB2222"}))
    out = hunt(tmp_path, a, b)
    assert out["serial_collision"][0].evidence["reason"] == "weak_serial"
    assert "device_on_many_hosts" not in hunt(tmp_path / "x", a, b, min_hosts=2)


# --------------------------------------------------------------------------- general
def test_findings_are_explained_and_sorted(tmp_path):
    a, b, c = HostRun(WS042), HostRun(WS007), HostRun(LT113)
    a.session(a.stick(), score=85, severity="high", users=["NW\\j.doe"])
    b.session(b.stick(), users=["NW\\a.smith"])
    c.session(c.stick(), users=["NW\\k.lee"])
    f = build_fleet(write_fleet(tmp_path, a, b, c))
    findings = f.hunt()
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    assert [order[x.severity] for x in findings] == sorted(order[x.severity] for x in findings)
    assert all(x.why and x.evidence.get("confidence") for x in findings)
    assert {x.rule for x in findings} >= {"exfil_device_spread", "device_on_many_hosts", "device_shared_by_users"}
