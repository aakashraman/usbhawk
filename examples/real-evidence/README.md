# Real evidence: try USBHawk on public forensic datasets

The demos in the other folders run in seconds. To see USBHawk on a full, realistic case, fetch a public dataset.
`scripts/fetch_demo_datasets.py` downloads it into a folder of your choice (default `~\usbhawk-datasets`, outside the
repository), checks the published hashes and prepares a triage folder. **Nothing is bundled**; each dataset keeps its
own licence and terms.

| Dataset | Size | What it shows | Source |
|---|---|---|---|
| `evtx-attack` | 1.2 MB | Real Security 1102 and System 104 log-clearing records (detections, H7) | EVTX-ATTACK-SAMPLES by Samir Bousseaden (GPL-3.0) |
| `nist-leakage` | 5.1 GB download, 21 GB unpacked | A scripted insider data-leakage case on Windows 7, with two USB sticks and a written answer key (sessions, tamper, graph) | NIST CFReDS Data Leakage Case (2015) |

```
python scripts\fetch_demo_datasets.py --list
python scripts\fetch_demo_datasets.py evtx-attack
python scripts\fetch_demo_datasets.py nist-leakage
```

The NIST download needs 7-Zip (`7z` on the PATH or in `C:\Program Files\7-Zip`) to unpack the image and copy out the
registry hives and event logs. The script prints the exact USBHawk commands to run when it finishes.

## What USBHawk finds

**EVTX-ATTACK-SAMPLES:** 113 events; H7 fires twice, on the System 104 and the Security 1102 records, matching
Eric Zimmerman's EvtxECmd.

**NIST CFReDS Data Leakage case (Windows 7):** both USB sticks of the answer key are found with the right serials, the
right user (`informant`) and the right first-connection times; no false tamper findings; no false detection alerts
over 2,833 real events.

```
| 25 low | 2015-03-23 18:31:09 | SanDisk Cruzer Fit | 4C530012450531101593 | informant-PC\informant |
| 25 low | 2015-03-24 13:58:31 | SanDisk Cruzer Fit | 4C530012550531106501 | informant-PC\informant |
```

(14:31 and 09:58 EDT, as in NIST's answer key.) What Windows 7 does not record, and what USBHawk therefore misses on
it (later connections, volume labels, MBR drive letters, cleanup-tool runs), is in
[docs/TESTING.md](../../docs/TESTING.md), with a plan for each in [ideas/](../../ideas/README.md).

## Other public datasets

- Mendeley "Windows Registry Data Sets" (Kwon, CC BY 4.0, doi:10.17632/ghkms3cgbg.1): `.reg` text exports, which
  USBHawk does not read yet ([ideas/reg-export-support.md](../../ideas/reg-export-support.md)).
- Digital Corpora M57-Patents: several hosts in one scenario, a good fleet test for `usbhawk graph`
  ([ideas/m57-multihost-test.md](../../ideas/m57-multihost-test.md)).
