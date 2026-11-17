"""Module #1: is it the same stick on two hosts? Identity resolution across a fleet.

A real hardware serial identifies a stick everywhere (high confidence). Windows-generated serials (7&...&0) only
exist on one host, and cheap sticks share fake serials (0123456789ABCDEF), so those are matched by volume serial
(medium) or volume name + capacity (low), and never by the serial alone.
"""

import pytest

from usbthk.graph import build_fleet, is_weak_serial

from fleet_builder import HostRun, write_fleet


def fleet(tmp_path, *hosts, **kw):
    return build_fleet(write_fleet(tmp_path, *hosts), **kw)


def clusters_with(f, serial_fragment):
    return [c for c in f.clusters if any(serial_fragment.lower() in r.key.lower() for r in c.records)]


@pytest.mark.parametrize("serial, weak", [
    ("60A44C413D5FF380E95A0B7D", False), ("AA951D0000007252", False),
    ("0123456789ABCDEF", True), ("123456789", True), ("0000000000000000", True), ("AAAAAAAAAAAA", True),
    ("1234", True), ("FFFFFFFFFFFF", True),
])
def test_weak_serials_are_recognised(serial, weak):
    assert is_weak_serial(serial) is weak


def test_real_serial_links_hosts_with_high_confidence(tmp_path):
    a, b = HostRun("NW-FIN-WS042"), HostRun("NW-HR-WS007")
    a.stick(vsns={"8E2C41D7"})
    b.stick(vsns={"11223344"})                        # reformatted in between: different VSN, same hardware
    f = fleet(tmp_path, a, b)
    [c] = clusters_with(f, "60A44C41")
    assert c.hosts == {"NW-FIN-WS042", "NW-HR-WS007"} and c.confidence == "high" and c.basis == {"serial"}


def test_windows_generated_serials_join_on_volume_serial(tmp_path):
    a, b = HostRun("NW-FIN-WS042"), HostRun("NW-ENG-LT113")
    a.stick("1B1C", "1F1F", "7&1A2B3C4D&0", vsns={"5E6F7A8B"}, volume_names={"BACKUP"})
    b.stick("1B1C", "1F1F", "7&99887766&0", vsns={"5E6F7A8B"}, volume_names={"BACKUP"})
    f = fleet(tmp_path, a, b)
    [c] = clusters_with(f, "1B1C&PID_1F1F")
    assert c.hosts == {"NW-FIN-WS042", "NW-ENG-LT113"} and c.confidence == "medium" and "vsn" in c.basis


def test_windows_generated_serials_join_on_name_and_capacity_with_low_confidence(tmp_path):
    a, b = HostRun("NW-FIN-WS042"), HostRun("NW-ENG-LT113")
    a.stick("1B1C", "1F1F", "7&1A2B3C4D&0", vsns={"AAAA1111"}, volume_names={"PAYROLL-Q3"}, capacity=16_000_000_000)
    b.stick("1B1C", "1F1F", "7&99887766&0", vsns={"BBBB2222"}, volume_names={"PAYROLL-Q3"}, capacity=16_000_000_000)
    f = fleet(tmp_path, a, b)
    [c] = clusters_with(f, "1B1C&PID_1F1F")
    assert len(c.hosts) == 2 and c.confidence == "low" and c.basis == {"name+capacity"}


def test_windows_generated_serials_alone_never_join(tmp_path):
    a, b = HostRun("NW-FIN-WS042"), HostRun("NW-ENG-LT113")
    a.stick("1B1C", "1F1F", "7&1A2B3C4D&0", vsns={"AAAA1111"}, volume_names={"A"})
    b.stick("1B1C", "1F1F", "7&1A2B3C4D&0", vsns={"BBBB2222"}, volume_names={"B"})   # same text, host-local
    f = fleet(tmp_path, a, b)
    assert len(clusters_with(f, "1B1C&PID_1F1F")) == 2


def test_fake_serial_is_not_trusted_without_volume_evidence(tmp_path):
    a, b = HostRun("NW-HR-WS007"), HostRun("NW-ENG-LT113")
    a.stick("FFFF", "5678", "0123456789ABCDEF", vsns={"AAAA1111"}, volume_names={"HR"})
    b.stick("FFFF", "5678", "0123456789ABCDEF", vsns={"BBBB2222"}, volume_names={"ENG"})
    f = fleet(tmp_path, a, b)
    assert len(clusters_with(f, "0123456789ABCDEF")) == 2


def test_fake_serial_with_shared_volume_serial_does_join(tmp_path):
    a, b = HostRun("NW-HR-WS007"), HostRun("NW-ENG-LT113")
    a.stick("FFFF", "5678", "0123456789ABCDEF", vsns={"CAFE1234"})
    b.stick("FFFF", "5678", "0123456789ABCDEF", vsns={"CAFE1234"})
    f = fleet(tmp_path, a, b)
    [c] = clusters_with(f, "0123456789ABCDEF")
    assert len(c.hosts) == 2 and c.confidence == "medium"


def test_two_real_serials_are_never_merged_by_a_shared_volume_serial(tmp_path):
    """A cloned image gives two different sticks the same VSN; real serials prove they are different."""
    a, b = HostRun("NW-FIN-WS042"), HostRun("NW-HR-WS007")
    a.stick(serial="60A44C413D5FF380E95A0B7D", vsns={"8E2C41D7"})
    b.stick(serial="AA951D0000007252", vsns={"8E2C41D7"})
    f = fleet(tmp_path, a, b)
    assert len(f.clusters) == 2


def test_only_storage_devices_by_default(tmp_path):
    hosts = [HostRun(n) for n in ("NW-FIN-WS042", "NW-HR-WS007", "NW-ENG-LT113")]
    for h in hosts:
        h.stick("0E0F", "0002", "6&2AB01149&0&2", cls="other", vsns=(), volume_names=(), capacity=None,
                product="VMware Virtual USB Hub")
    roots = write_fleet(tmp_path, *hosts)
    assert build_fleet(roots).clusters == []
    assert len(build_fleet(roots, all_classes=True).clusters) == 3       # host-local serials: three clusters


def test_device_known_only_from_a_partition_log_still_counts(tmp_path):
    """Module #3 orphans have no Enum class; volume evidence makes them storage."""
    a = HostRun("NW-FIN-WS042")
    dev = a.stick(cls="other", vsns={"8E2C41D7"})
    dev.sources = {"evtx:Partition/Diagnostic"}
    f = fleet(tmp_path, a)
    assert len(f.clusters) == 1
