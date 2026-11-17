"""Module #3: tamper / cleanup detection, scenarios S1-S8 on synthetic evidence.

Idea: Windows records a USB device in places that are easy to wipe (Enum\\USB, USBSTOR, SCSI) and places
that usually survive (Partition/Diagnostic log, MountedDevices, WPD, EMDMgmt, MountPoints2,
DeviceMigration). A device that survives but is gone from Enum was removed either by Windows (a feature
update, which leaves DeviceMigration/update-history traces) or by someone (USBOblivion, manual deletion).

Fictional host NW-FIN-WS042, user j.doe. Reference time for the "wiped" stick: Fri 2026-10-30 21:14Z.
"""

from usbhawk.model import CONNECT, LAST_PRESENT, LOG_CLEARED, Event, Evidence
from usbhawk.tamper import find_tamper

from conftest import utc

SERIAL = "60A44C413D5FF380E95A0B7D"
SEEN = utc(2026, 10, 30, 21, 14)
UPDATE_BEFORE = utc(2026, 3, 1, 9, 0)
UPDATE_AFTER = utc(2026, 11, 5, 3, 0)


def host(updates=(UPDATE_BEFORE,), parsed=("SYSTEM", "SOFTWARE")):
    ev = Evidence()
    ev.host.hostname = "NW-FIN-WS042"
    ev.parsed.update(parsed)
    ev.host.feature_updates = [{"ts": t, "source": "test update"} for t in updates]
    return ev


def present_device(ev, serial="AA951D0000007252"):
    """A stick that is still fully recorded in Enum (nothing wiped)."""
    dev = ev.device("03F0", "3207", serial, "registry:Enum\\USB")
    dev.sources.update({"registry:Enum\\USBSTOR", "registry:MountedDevices", "evtx:Partition/Diagnostic"})
    dev.device_class = "usbstor"
    ev.add(Event(SEEN, CONNECT, "registry:Enum\\USBSTOR:0066", dev.key))
    return dev


def wiped_device(ev, computer="NW-FIN-WS042.corp.example"):
    """A stick only the Partition/Diagnostic log still remembers: its Enum keys are gone."""
    dev = ev.device("0951", "1666", SERIAL, "evtx:Partition/Diagnostic")
    ev.add(Event(SEEN, CONNECT, "evtx:Partition/Diagnostic:1006", dev.key,
                 details={"capacity": 31_000_000_000, "computer": computer}))
    return dev


def orphan_ref(ev, artifact="WindowsPortableDevices", ref_time=SEEN, scope="entry", serial=SERIAL):
    ev.unlinked.append({"artifact": artifact, "id_type": "usb_serial", "id_value": serial,
                        "ref_time": ref_time, "ref_time_scope": scope if ref_time else None,
                        "user": None, "details": {}})


def log_cleared(ev, when, channel="Security", eid=1102, user="NW\\j.doe"):
    ev.add(Event(when, LOG_CLEARED, f"evtx:{'Security' if eid == 1102 else 'System'}:{eid}", user=user,
                 details={"channel": channel, "computer": "NW-FIN-WS042"}))


def by_rule(findings):
    out = {}
    for f in findings:
        out.setdefault(f.rule, []).append(f)
    return out


# --------------------------------------------------------------------------- S1 clean
def test_s1_clean_host_has_no_findings():
    ev = host()
    present_device(ev)
    assert find_tamper(ev) == []


# --------------------------------------------------------------------------- S2 wiped
def test_s2_device_only_in_partition_log_is_orphaned():
    ev = host()
    wiped_device(ev)
    f = by_rule(find_tamper(ev))["orphaned_device_reference"]
    assert len(f) == 1 and f[0].severity == "medium"
    assert SERIAL in f[0].why and "Enum" in f[0].why
    assert f[0].evidence["last_reference"] == SEEN
    assert "evtx:Partition/Diagnostic" in f[0].evidence["surviving_sources"]


def test_s2_unlinked_wpd_reference_is_orphaned():
    ev = host()
    orphan_ref(ev)
    f = by_rule(find_tamper(ev))["orphaned_device_reference"]
    assert len(f) == 1 and f[0].severity == "medium"
    assert f[0].evidence["artifact"] == "WindowsPortableDevices"


# --------------------------------------------------------------------------- S3 explained by update
def test_s3_feature_update_after_last_reference_explains_it():
    ev = host(updates=(UPDATE_BEFORE, UPDATE_AFTER))
    wiped_device(ev)
    orphan_ref(ev)
    rules = by_rule(find_tamper(ev))
    assert "orphaned_device_reference" not in rules
    explained = rules["explained_by_feature_update"]
    assert len(explained) == 2 and all(f.severity == "info" for f in explained)
    assert all(f.evidence["feature_update"] == UPDATE_AFTER for f in explained)


# --------------------------------------------------------------------------- S4 DeviceMigration
def test_s4_device_in_device_migration_is_explained():
    ev = host()
    dev = ev.device("0951", "1666", SERIAL, "registry:DeviceMigration")
    ev.add(Event(SEEN, LAST_PRESENT, "registry:DeviceMigration", dev.key))
    rules = by_rule(find_tamper(ev))
    assert "orphaned_device_reference" not in rules
    assert rules["explained_by_feature_update"][0].evidence["device_migration"] is True


def test_s4_unlinked_reference_matching_device_migration_is_explained():
    ev = host()
    ev.migrated.append({"id": f"USBSTOR\\Disk&Ven_Kingston&Prod_DT\\{SERIAL}&0",
                        "last_present": SEEN, "values": {}})
    orphan_ref(ev)
    rules = by_rule(find_tamper(ev))
    assert "orphaned_device_reference" not in rules
    assert "explained_by_feature_update" in rules


# --------------------------------------------------------------------------- S5 log cleared
def test_s5_security_log_cleared_is_high():
    ev = host()
    log_cleared(ev, utc(2026, 10, 30, 22, 0))
    f = by_rule(find_tamper(ev))["log_cleared"]
    assert len(f) == 1 and f[0].severity == "high"
    assert "Security" in f[0].why and "j.doe" in f[0].why
    assert f[0].ts == utc(2026, 10, 30, 22, 0)


def test_s5_system_log_and_partition_log_cleared_are_high():
    ev = host()
    log_cleared(ev, utc(2026, 10, 30, 22, 0), channel="System", eid=104)
    log_cleared(ev, utc(2026, 10, 30, 22, 1), channel="Microsoft-Windows-Partition/Diagnostic", eid=104)
    assert [f.severity for f in by_rule(find_tamper(ev))["log_cleared"]] == ["high", "high"]


def test_s5_other_log_cleared_is_medium():
    ev = host()
    log_cleared(ev, utc(2026, 10, 30, 22, 0), channel="Application", eid=104)
    assert by_rule(find_tamper(ev))["log_cleared"][0].severity == "medium"


# --------------------------------------------------------------------------- S6 wipe + log clear
def test_s6_orphan_near_log_clear_is_raised_to_high():
    ev = host()
    wiped_device(ev)
    log_cleared(ev, utc(2026, 10, 31, 8, 0))      # within 24 h of the last reference
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert f.severity == "high"
    assert f.evidence["correlated_log_clear"] == utc(2026, 10, 31, 8, 0)
    assert "cleared" in f.why


def test_s6_log_clear_days_later_does_not_raise():
    ev = host()
    wiped_device(ev)
    log_cleared(ev, utc(2026, 11, 10, 8, 0))      # 10 days later: unrelated
    assert by_rule(find_tamper(ev))["orphaned_device_reference"][0].severity == "medium"


# --------------------------------------------------------------------------- S7 weak timestamps
def test_s7_no_timestamp_with_updates_on_record_is_low_confidence():
    ev = host(updates=(UPDATE_BEFORE,))
    orphan_ref(ev, artifact="MountedDevices", ref_time=None)
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert f.severity == "low" and "no timestamp" in f.why


def test_s7_no_timestamp_and_no_updates_on_record_stays_medium():
    ev = host(updates=())
    orphan_ref(ev, artifact="MountedDevices", ref_time=None)
    assert by_rule(find_tamper(ev))["orphaned_device_reference"][0].severity == "medium"


def test_s7_parent_key_time_is_only_an_upper_bound():
    # MountedDevices values have no own timestamp; the key's last-write is >= the entry's real time.
    ev = host(updates=(UPDATE_BEFORE,))
    orphan_ref(ev, artifact="MountedDevices", ref_time=SEEN, scope="parent_key")
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert f.severity == "low" and "upper bound" in f.why


def test_s7_parent_key_time_before_update_still_explains():
    # If the update happened after the key's last write, it also happened after the entry.
    ev = host(updates=(UPDATE_AFTER,))
    orphan_ref(ev, artifact="MountedDevices", ref_time=SEEN, scope="parent_key")
    assert "explained_by_feature_update" in by_rule(find_tamper(ev))


# --------------------------------------------------------------------------- S8 mixed-host evidence
def test_s8_foreign_log_device_is_not_an_orphan_and_mismatch_is_reported():
    ev = host()
    wiped_device(ev, computer="DESKTOP-GOGB42D")
    ev.log_computers["Partition/Diagnostic"] = {"DESKTOP-GOGB42D": 35}
    rules = by_rule(find_tamper(ev))
    assert "orphaned_device_reference" not in rules
    mm = rules["evidence_host_mismatch"]
    assert len(mm) == 1 and mm[0].severity == "info"
    assert "DESKTOP-GOGB42D" in mm[0].why and "NW-FIN-WS042" in mm[0].why


def test_s8_mixed_log_reads_as_a_renamed_host_not_another_machine():
    """Real case (NIST CFReDS Data Leakage, Win7): most records carry the host's name, a few the base image's name.

    Saying "this log comes from another machine" there is wrong; the finding must say the log is mixed, and the
    host's own records must still count (a device seen in them is a native reference).
    """
    ev = host()
    ev.log_computers["System"] = {"NW-FIN-WS042": 1132, "TPL-WIN7-BASE": 508}
    wiped_device(ev, computer="NW-FIN-WS042")
    rules = by_rule(find_tamper(ev))
    mm = rules["evidence_host_mismatch"]
    assert len(mm) == 1 and mm[0].evidence["own_records"] == 1132
    assert "1132 records from NW-FIN-WS042" in mm[0].why and "renamed" in mm[0].why
    assert "comes from another machine" not in mm[0].why
    assert "orphaned_device_reference" in rules                     # the host's own records still count


def test_s8_fqdn_of_same_host_is_not_a_mismatch():
    ev = host()
    ev.log_computers["Security"] = {"nw-fin-ws042.corp.example": 900}
    assert find_tamper(ev) == []


# --------------------------------------------------------------------------- guards
def test_no_system_hive_means_no_orphan_checks():
    """Without SYSTEM we cannot know what Enum contains; never call that 'wiped'."""
    ev = host(parsed=("SOFTWARE",))
    wiped_device(ev)
    orphan_ref(ev)
    rules = by_rule(find_tamper(ev))
    assert "orphaned_device_reference" not in rules
    assert rules["orphan_checks_skipped"][0].severity == "info"


def test_mountpoints2_volume_orphan_is_low():
    """A volume GUID the user mounted that MountedDevices no longer knows: could be USB, could be a VHD."""
    ev = host()
    ev.unlinked.append({"artifact": "MountPoints2", "id_type": "volume_guid",
                        "id_value": "{11111111-2222-3333-4444-555555555555}", "ref_time": SEEN,
                        "ref_time_scope": "entry", "user": "j.doe", "details": {}})
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert f.severity == "low" and "j.doe" in f.why


def test_volume_label_only_references_are_ignored():
    """EMDMgmt entries without a device path (label + VSN only) cannot be tied to a USB device."""
    ev = host()
    ev.unlinked.append({"artifact": "EMDMgmt", "id_type": "volume_label", "id_value": "WR_Q__",
                        "ref_time": SEEN, "ref_time_scope": "entry", "user": None,
                        "details": {"vsn": "AC036525"}})
    assert find_tamper(ev) == []


def test_findings_sorted_most_severe_first_and_every_finding_explained():
    ev = host()
    wiped_device(ev)
    log_cleared(ev, utc(2026, 11, 10, 8, 0), channel="Application", eid=104)
    orphan_ref(ev, artifact="MountedDevices", ref_time=None)
    findings = find_tamper(ev)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    assert [order[f.severity] for f in findings] == sorted(order[f.severity] for f in findings)
    for f in findings:
        assert f.rule and f.why.strip() and isinstance(f.evidence, dict)
        d = f.to_dict()
        assert d["event"]["dataset"] == "usbhawk.tamper" and d["usbhawk"]["rule"] == f.rule
