# EMDMgmt entries without a device path

**Why.** EMDMgmt (ReadyBoost) keeps a volume label and volume serial number (VSN) for removable volumes. USBHawk links
entries whose key name contains the `USBSTOR#...#serial` device path. On the NIST Windows 7 image, the entries have no
device path, so labels, VSNs and a reformat go unused.

**Evidence (NIST CFReDS Data Leakage).** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` holds:

| Entry | Last write (UTC) | Meaning |
|---|---|---|
| `..._Authorized USB_1551191358` | 2015-03-23 18:31:12 | RM#1's label from the answer key; 3 s after RM#1's first install |
| `..._IAMAN $_@_2657770370` | 2015-03-24 13:58:34 | RM#2's label; 3 s after RM#2's first install |
| `..._IAMAN $_@_3034076057` | 2015-03-24 21:02:34 | same label, **new VSN**: the quick format the answer key lists as anti-forensics |

**Approach.** Parse label and VSN from every entry. Link an entry to a device only when its first last-write falls
within a few seconds of that device's install or connect and exactly one device is a candidate; otherwise keep it as an
unlinked volume (shown, never guessed). The same label with two VSNs is reformat evidence for the
`reformat_or_repartition` rule even without the Partition log.

**Tests.** Unique-candidate link, ambiguous candidates left unlinked, label with two VSNs raises the reformat reason,
existing `USBSTOR#` entries unchanged.
