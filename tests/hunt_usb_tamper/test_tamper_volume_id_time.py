"""Orphaned volume GUIDs carry the time Windows created them (1.0.2).

Mount Manager makes time-based (version 1) GUIDs for removable volumes, so an orphaned MountPoints2 entry still
says when its volume was first mounted. Real case: one orphan matched a stick's reformat to the second, and five
others were created within 1 ms of each other while no plug-in started (one plug-in makes one volume).
All GUIDs here are built for the test; the node is a made-up MAC.
"""

import uuid
from datetime import datetime, timedelta, timezone

from usbhawk.tamper import find_tamper
from usbhawk.util import guid_v1_time

from test_tamper_scenarios import SEEN, by_rule, host

GREGORIAN = datetime(1582, 10, 15, tzinfo=timezone.utc)
NODE = 0x0A1B2C3D4E5F


def v1_guid(when: datetime, clock_seq: int = 0x2A10) -> str:
    ticks = (when - GREGORIAN) // timedelta(microseconds=1) * 10
    u = uuid.UUID(fields=(ticks & 0xFFFFFFFF, (ticks >> 32) & 0xFFFF, ((ticks >> 48) & 0x0FFF) | 0x1000,
                          0x80 | (clock_seq >> 8) & 0x3F, clock_seq & 0xFF, NODE))
    return "{" + str(u) + "}"


def orphan_volume(ev, guid, user="j.doe"):
    ev.unlinked.append({"artifact": "MountPoints2", "id_type": "volume_guid", "id_value": guid,
                        "ref_time": SEEN, "ref_time_scope": "entry", "user": user, "details": {}})


CREATED = datetime(2026, 10, 30, 21, 14, 3, 250000, tzinfo=timezone.utc)


def test_v1_guid_time_is_decoded():
    assert guid_v1_time(v1_guid(CREATED)) == CREATED
    assert guid_v1_time(v1_guid(CREATED).strip("{}").upper()) == CREATED


def test_other_guid_versions_have_no_time():
    assert guid_v1_time("{11111111-2222-3333-4444-555555555555}") is None   # version 3
    assert guid_v1_time(str(uuid.uuid4())) is None
    assert guid_v1_time("not a guid") is None and guid_v1_time(None) is None


def test_orphaned_volume_says_when_it_was_created():
    ev = host()
    orphan_volume(ev, v1_guid(CREATED))
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert f.severity == "low"
    assert "reads 2026-10-30T21:14:03.250000Z: the volume was first mounted here at or shortly after" in f.why
    assert "other orphaned volume" not in f.why
    assert f.evidence["volume_created"] == CREATED and f.evidence["volume_created_with"] == 0


def test_burst_of_volumes_created_in_one_second_is_called_out():
    ev = host()
    for i in range(5):
        orphan_volume(ev, v1_guid(CREATED + timedelta(microseconds=20 * i)))
    orphan_volume(ev, v1_guid(CREATED + timedelta(hours=11)))        # a separate plug-in
    findings = by_rule(find_tamper(ev))["orphaned_device_reference"]
    burst = [f for f in findings if f.evidence["volume_created_with"] == 4]
    alone = [f for f in findings if f.evidence["volume_created_with"] == 0]
    assert len(burst) == 5 and len(alone) == 1
    assert all("4 other orphaned volume ID(s) carry a time in the same second" in f.why for f in burst)
    assert "multi-slot card reader" in burst[0].why and "MountedDevices was cleaned" in burst[0].why
    assert all(f.severity == "low" for f in findings)


def test_non_time_based_volume_guid_keeps_the_old_text():
    ev = host()
    orphan_volume(ev, "{11111111-2222-3333-4444-555555555555}")
    f = by_rule(find_tamper(ev))["orphaned_device_reference"][0]
    assert "time-based" not in f.why and "volume_created" not in f.evidence
