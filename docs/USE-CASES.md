# The four use cases on one page

**The idea behind USBHawk.** The classic USB forensic profile has 11 steps: which devices, their serials, first and
last connection, drive letter, volume name, user. That answers *"what was plugged in?"*. An investigation needs more:
*was data taken, was it hidden, where else did the stick go, and how do we catch it next time?* USBHawk starts from
the same artifacts and turns each of those questions into one command (methodology credits: the README's
[Credits and references](../README.md#credits-and-references)).

| # | The question | Command | What USBHawk adds to the device profile |
|---|---|---|---|
| 1 | Which USB sessions look like data theft, and why? | `usbhawk sessions` | Connect-to-remove **sessions**, users and files written, a **score with reasons** |
| 2 | Was the USB evidence wiped, or did Windows clean it up? | `usbhawk tamper` | Cross-checks the artifacts and **explains every gap**: cleanup tool, cleared log, or a Windows update |
| 3 | How do we catch it live next time? | `usbhawk detections` | The hunts as **live rules** for Sigma, Elastic and Sentinel, testable offline on real logs |
| 4 | Where else has this stick been, and who else used it? | `usbhawk graph` | Links one stick **across many hosts** and hunts the fleet |

Every example below is on the fictional demo data in [examples/](../examples/README.md), so you can run it yourself.

---

## 1. `sessions`: did someone copy data to a USB stick?

**Run it** on one host's collection (KAPE, Velociraptor, a mounted image; see [INTEGRATIONS.md](INTEGRATIONS.md)):

```powershell
usbhawk sessions --triage examples\tamper\wiped-host --tz America/New_York
```

**What you see:** one row per session, highest score first:

```
| Score  | Connected (UTC)     | Duration | Class | Device          | iSerialNumber | ... | Description
| 25 low | 2026-09-15 14:30:12 | ...      | uasp  | Samsung PSSD T7 | N7T00042CF19  | ... | first_seen_device
```

**What it means:** 13 rules each add points and a sentence (new device +25, outside work hours +15, files written
+20, bulk copy +20, archive +15, reformatted +25, leaver on a watchlist +30, approved device −50, ...). The score
(0-100: high ≥ 70, medium ≥ 40, low ≥ 15) is a **triage order, not a verdict**; the Description says why. Add
`--file-events` (an EDR export) to see what was written; without it, file rules cannot fire.

**Pivot:** the iSerialNumber and volume serial (to `graph` and other hosts), the drive letter and session window (to
EDR file events), the user (to `graph ... user`).

## 2. `tamper`: was the evidence wiped?

```powershell
usbhawk tamper --triage examples\tamper\wiped-host
```

```
| high   | orphaned_device_reference   | 2026-10-29 18:05:31 | USB serial 4C530001230601108811 still appears in registry:EMDMgmt but
|        |                             |                     | is missing from Enum ... USBOblivion was run by m.ortiz at 18:42:10Z, after it
| high   | cleanup_tool_execution      | 2026-10-29 18:42:10 | USBOblivion (USBOblivion64.exe) was run by m.ortiz (registry:BAM)
| medium | partition_log_gap           | -                   | Partition/Diagnostic log is empty, yet a USB disk arrived at 17:58
| low    | expected_artifact_missing   | -                   | setupapi.dev.log is missing although Windows\INF was collected
| info   | explained_by_feature_update | 2025-11-14 12:30:10 | missing from Enum, but a feature update came after: Windows cleanup
```

**What it means:** a stick that survives in one artifact but is gone from the device registry is an **orphan**. Its
severity rises when a cleanup tool ran or a log was cleared *after* it was last seen, and drops to `info` when a
Windows feature update explains the gap. The `Source Timestamp` is the time the surviving artifact recorded.

**Pivot:** the orphaned serials and volume names (`CASE-FILES`, `BACKUP`) are what to search for on other hosts with
`graph`; the tool run's user and time go to process and logon events.

## 3. `detections`: catch it live

```powershell
usbhawk detections run --events examples\detections\insider_timeline.jsonl
```

```
| Event Timestamp (UTC) | Hypothesis | Detection        | Level  | Description
| 2026-10-30 21:16:00   | H3         | bulk_copy_to_usb | high   | 60 matching events between 21:16:00Z and 21:19:56Z ...
| 2026-10-30 21:39:00   | H6         | usb_cleaner      | high   | process_name=USBOblivion64.exe; ...
Look at first (by level, then time):
  high    H3 bulk_copy_to_usb (at 2026-10-30 21:16:00); H6 usb_cleaner (at 2026-10-30 21:39:00); ...
```

**What it means:** eight hypotheses (H1-H8: device connected, off hours, bulk copy, archive, format, cleanup tool,
log cleared, USB registry history deleted), each a live rule generated for Sigma, Elastic and Sentinel by
`usbhawk detections build`. `detections run` replays logs offline through exactly the same logic, and says which
hypotheses could not fire for lack of telemetry. Each one is explained in
[hunt-detection-rules.md](hunt-detection-rules.md#each-hypothesis-explained).

**Pivot:** read the table as one story (device, copying, cleanup), then run `sessions` and `tamper` on a triage of the
host for the whole picture.

## 4. `graph`: where else has this stick been?

```powershell
usbhawk graph --runs examples\graph\fleet
usbhawk graph --runs examples\graph\fleet device 60A44C41
```

```
| high | wiped_here_seen_there | SanDisk Ultra (4C530001230601105525)                 | 1 | wiped on NW-OPS-WS019, NW-HR-WS007 still holds its history
| high | exfil_device_spread   | Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D) | 3 | score 85 on NW-FIN-WS042, also on NW-ENG-LT113, NW-HR-WS007
```

**What it means:** the outputs of `sessions` and `tamper` from many hosts, linked by the stick's serial (then volume
serial, then name and capacity). Six fleet hunts find the stick that carried data between hosts, the stick wiped on
one host but remembered by another, shared and new sticks. A pivot on a device or a user shows every host it touched.

**Pivot:** the hosts it names are the next ones to collect; `--out` exports the graph for Gephi and Neo4j.

---

**Putting it together on a case:** collect each host → `sessions` + `tamper` into one folder per host → `graph`
across them → `detections build` so the SOC catches the next one. Step by step: [GETTING-STARTED.md](GETTING-STARTED.md).
