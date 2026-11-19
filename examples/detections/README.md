# `usbhawk detections`: how do we catch it live next time?

Module #4. The hunts' hypotheses (H1-H8) written once as detection-as-code, then generated for **Sigma**,
**Elastic (ES|QL)** and **Microsoft Sentinel (KQL)**. Every rule carries its own must-match and must-not-match test
events, and `detections run` replays real logs (or JSONL events) through the rules offline, so you can see what would
have fired before you deploy anything.

| | |
|---|---|
| **Input** | Nothing (`list`, `test`, `build`); `.evtx` logs (`run --evtx`) or neutral events (`run --events`) |
| **Output** | Rule files for three platforms (`build`); an alert table and `alerts.jsonl` (`run --out`) |
| **In this folder** | `insider_timeline.jsonl`: 72 events of a Friday-evening insider (fictional), one JSON object per line |
| **Full guide** | [docs/hunt-detection-rules.md](../../docs/hunt-detection-rules.md) |

## 1. The rules

```powershell
usbhawk detections list
usbhawk detections test
```

`list` shows every hypothesis, its detections, ATT&CK techniques and the offline hunt it mirrors:

```
| Hypothesis | Rule                                     | Detections (level)                                                     | ATT&CK
| H1  | USB Storage Device Connected                    | usb_storage_connected (low), first_seen_usb_storage (medium)           | T1052.001, T1200
| H2  | USB Storage Connected Outside Work Hours        | usb_storage_off_hours (medium)                                         | T1052.001
| H3  | Bulk File Copy to Removable Media               | bulk_copy_to_usb (high)                                                | T1052.001
| H4  | Archive Written to Removable Media              | archive_to_usb (medium)                                                | T1560, T1052.001
| H5  | Disk Formatted or Repartitioned From the Command Line | format_command (medium)                                          | T1070, T1561
| H6  | USB History Cleanup Tool Executed               | usb_cleaner (high), general_cleaner (medium)                           | T1070, T1685.005
| H7  | Windows Event Log Cleared                       | security_log_cleared (high), log_cleared_104 (medium), clear_command (high) | T1685.005
| H8  | USB Device History Deleted From the Registry    | usb_registry_trace_deleted (high)                                      | T1070, T1112
```

`test` runs every rule against its own test events:

```
8 rules, 12 detections, 59 test events: all passed
```

## 2. Replay an insider timeline through the rules

The story: `j.doe` plugs in a Kingston stick at 21:14 UTC on a Friday, copies 64 board-pack documents, writes a 7z
archive, reformats the stick, then runs USBOblivion, which deletes the stick's registry keys and clears the Security
log.

```powershell
usbhawk detections run --events examples\detections\insider_timeline.jsonl
usbhawk detections run --events examples\detections\insider_timeline.jsonl --out out\detections
```

What you should see (every hypothesis fires, in order; the Description column trimmed):

```
1 event files (JSONL), 72 events: device_connect 1, event_log 2, file_event 65, process_creation 3, registry_event 1
| Event Timestamp (UTC) | Hypothesis | Detection           | Level  | Description
| 2026-10-30 21:14:00 | H1  | first_seen_usb_storage     | medium | USBSTOR\DISK&VEN_KINGSTON&PROD_DATATRAVELER_3.0&REV_PMAP\60A44C41... first seen at 2026-10-30T21:14:00Z
| 2026-10-30 21:14:00 | H1  | usb_storage_connected      | low    | device_id=USBSTOR\DISK&VEN_KINGSTON...; device_description=USB Mass Storage Device
| 2026-10-30 21:14:00 | H2  | usb_storage_off_hours      | medium | device_id=USBSTOR\DISK&VEN_KINGSTON...
| 2026-10-30 21:16:00 | H3  | bulk_copy_to_usb           | high   | 60 matching events between 21:16:00Z and 21:19:56Z (threshold 50 per 10 min); e.g. F:\Q3\board-pack-00.docx, ...
| 2026-10-30 21:22:00 | H4  | archive_to_usb             | medium | process_name=7zG.exe; file_path=F:\Q3\finance-share.7z; user=NW\j.doe
| 2026-10-30 21:34:00 | H5  | format_command             | medium | process_name=format.com; command_line=format.com F: /FS:exFAT /Q /Y; user=NW\j.doe
| 2026-10-30 21:39:00 | H6  | usb_cleaner                | high   | process_name=USBOblivion64.exe; command_line=USBOblivion64.exe -enable -auto; user=NW\j.doe
| 2026-10-30 21:39:30 | H8  | usb_registry_trace_deleted | high   | process_name=USBOblivion64.exe; registry_path=HKLM\System\CurrentControlSet\Enum\USBSTOR\...
| 2026-10-30 21:40:00 | H7  | clear_command              | high   | process_name=wevtutil.exe; command_line=wevtutil.exe cl Security; user=NW\j.doe
| 2026-10-30 21:40:01 | H7  | security_log_cleared       | high   | channel=Security; event_id=1102; provider=Microsoft-Windows-Eventlog; cleared_log=Security; user=NW\j.doe
Alerts per hypothesis: H1 2, H2 1, H3 1, H4 1, H5 1, H6 1, H7 2, H8 1
Look at first (by level, then time):
  high    H3 bulk_copy_to_usb (at 2026-10-30 21:16:00); H6 usb_cleaner (at 2026-10-30 21:39:00); H8 usb_registry_trace_deleted (at 2026-10-30 21:39:30); H7 clear_command (at 2026-10-30 21:40:00); H7 security_log_cleared (at 2026-10-30 21:40:01)
  medium  H1 first_seen_usb_storage (at 2026-10-30 21:14:00); H2 usb_storage_off_hours (at 2026-10-30 21:14:00); H4 archive_to_usb (at 2026-10-30 21:22:00); H5 format_command (at 2026-10-30 21:34:00)
  low     H1 usb_storage_connected (at 2026-10-30 21:14:00)
```

### Which alerts to look at first

The table is a **timeline**; the **Look at first** block under it is the **triage order**: high first, then
medium, then low, earliest first within each level. Then read the table top to bottom as one story:

1. **The device** (H1, H2): which stick, when, and whether it was new or out of hours. Its ID is the pivot for
   `usbhawk graph` and for `sessions` on a triage of the same host.
2. **The copying** (H3, H4): how many files, which archives, by which user and process.
3. **The cleanup** (H5 to H8): formatting, cleaner tools, cleared logs, deleted USB history. A copy followed by
   cleanup is far stronger than either alone.

A replay with no alerts ends with a **Telemetry gaps** note instead when the logs cannot show what a rule needs
(no Sysmon, no PnP or process auditing).

### The event format

`insider_timeline.jsonl` uses the neutral schema the rules are written in: one event per line, a `timestamp`, a
`_telemetry` type (`device_connect`, `event_log`, `file_event`, `process_creation`, `registry_event`) and the fields
that type needs. Two lines from it:

```json
{"timestamp": "2026-10-30T21:16:00Z", "_telemetry": "file_event", "_source": "Microsoft-Windows-Sysmon/Operational:11", "file_name": "board-pack-00.docx", "file_path": "F:\\Q3\\board-pack-00.docx", "host": "NW-FIN-WS042.corp.example", "image": "C:\\Windows\\explorer.exe", "process_name": "explorer.exe", "removable": true, "user": "NW\\j.doe"}
{"timestamp": "2026-10-30T21:39:30Z", "_telemetry": "registry_event", "_source": "Microsoft-Windows-Sysmon/Operational:12", "action": "delete", "host": "NW-FIN-WS042.corp.example", "image": "C:\\Users\\j.doe\\Downloads\\USBOblivion64.exe", "process_name": "USBOblivion64.exe", "registry_path": "HKLM\\System\\CurrentControlSet\\Enum\\USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\\60A44C413D5FF380E95A0B7D&0", "user": "NW\\j.doe"}
```

Convert any SIEM export to this format and you can test the rules against your own data without `.evtx` files.

## 3. Build deployable rules

```powershell
usbhawk detections build --out out\rules
```

```
wrote 37 files for sigma, elastic, sentinel to out\rules
```

| Folder | Contents |
|---|---|
| `sigma/` | SigmaHQ-style YAML (validated with pySigma and the SigmaHQ validators: 0 issues), including a correlation rule for H3. Where Sigma cannot express a rule (a 30-day first-seen, work hours), an `.unsupported.txt` says why instead of a weakened rule |
| `elastic/` | One ES\|QL query per detection over ECS fields, plus `usbhawk_rules.ndjson` to import into Kibana |
| `sentinel/` | One KQL query per detection for Microsoft Sentinel / Defender XDR |

For example, the start of `sentinel/H3_bulk_copy_to_usb__bulk_copy_to_usb.kql`:

```
// Bulk File Copy to Removable Media: bulk_copy_to_usb
// hypothesis H3 | level high | ATT&CK T1052.001 | offline hunt: usbhawk sessions.bulk_transfer
// generated by usbhawk from H3_bulk_copy_to_usb.yml - edit the YAML source, not this file
let UsbDrives = DeviceEvents
    | where ActionType == "UsbDriveMounted"
...
| where Events >= 50
```

## 4. On your own logs

```
usbhawk detections run --evtx C:\Windows\System32\winevt\Logs --removable-drives F:
```

Replays Sysmon, Security and System logs (run as administrator for a live system). Real public example: on
EVTX-ATTACK-SAMPLES the genuine Security 1102 and System 104 records fire H7 (see
[../real-evidence/](../real-evidence/README.md)).
