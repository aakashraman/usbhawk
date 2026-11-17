# Ideas

Future work for USBHawk: one file per idea, each saying why it matters, what evidence it rests on, a sketch of the
approach and how it would be tested. Nothing here is promised; an idea moves to `docs/ROADMAP.md` when work starts.

| Idea | Why | Found by | Size |
|---|---|---|---|
| [Windows 7: last connection from key timestamps](win7-last-connection.md) | Win7 has no `0066/0067` properties, so later connections are invisible | NIST CFReDS validation | S |
| [EMDMgmt entries without a device path](emdmgmt-volume-labels.md) | volume labels, VSNs and a reformat sit unused in EMDMgmt | NIST CFReDS validation | S |
| [MBR volumes without the Partition log](mbr-volumes-without-partition-log.md) | drive letters and MountPoints2 users of MBR sticks cannot be linked on Win7 | NIST CFReDS validation | M |
| [Execution evidence: Prefetch, Amcache, UserAssist](execution-evidence.md) | cleanup tools are seen only through BAM (Win10 1709+, about a week) | NIST CFReDS validation | M |
| [LNK and JumpList file attribution](lnk-jumplist-attribution.md) | which files were opened from the stick, natively instead of via CSV import | NIST answer key | M |
| [`.reg` export support](reg-export-support.md) | read registry exports, e.g. the Mendeley "Windows Registry Data Sets" | dataset survey | S |
| [Velociraptor artifact and KAPE module](velociraptor-kape.md) | collect exactly USBHawk's inputs, fleet-wide | roadmap | M |
| [Live SIEM tests for Elastic and Sentinel](live-siem-tests.md) | generated ES\|QL / KQL are structure-tested, not run in a live stack | roadmap | M |
| [File nodes in the fleet graph](graph-file-nodes.md) | follow a document, not just a stick, across hosts | module #1 design | M |
| [Multi-host test on M57-Patents](m57-multihost-test.md) | a public multi-host case for the fleet graph | dataset survey | S |
| [Signed release builds](signed-releases.md) | an unsigned `usbhawk.exe` trips SmartScreen and some EDR policies | packaging | S |

Size: S = a day or less, M = a few days. Real-data findings come from `docs/TESTING.md`; any idea that touches
parsing must add a regression test with fictional values (never the dataset's own data).
