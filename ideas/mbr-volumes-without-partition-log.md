# MBR volumes without the Partition log

**Why.** For MBR-partitioned sticks, `MountedDevices` stores a disk signature and partition offset instead of the
device path. USBHawk links those through Partition/Diagnostic event 1006, which carries the MBR. Windows 7 has no such
log, so the drive letter, the volume GUID and the MountPoints2 user of these sticks stay unlinked.

**Evidence (NIST CFReDS Data Leakage).** `\DosDevices\E:`, `Volume{662626a6-d181-11e4-9591-000c29ff2429}` and
`Volume{a2f2048e-d228-11e4-b630-000c29ff2429}` hold 12-byte MBR values. The two volume GUIDs are the ones in the
`informant` user's MountPoints2, and their GUIDs share time and node with the sticks' Partmgr `DiskId`s
(`{662626a4-...}`, `{a2f2048c-...}`).

**Approach (to research first).** Candidates: (1) the `DiskId` and volume GUID are version-1 UUIDs created moments
apart on the same node, so a volume GUID a few ticks after a device's `DiskId` points at that device; (2) the 12-byte
value's disk signature against the stick image's MBR when the image is available; (3) MountPoints2 and
VolumeInfoCache last-write times against connect times. Each link must state its basis and confidence, as the fleet
graph does.

**Tests.** Only after (1) is confirmed on more than one real Windows 7 image; synthetic tests for the chosen rule and
for refusing ambiguous matches.
