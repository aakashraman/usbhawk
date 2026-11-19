# USBHawk with KAPE, Velociraptor and Elastic

USBHawk sits between collection and the SIEM:

```
  collect                         analyse                                   store, search, alert
  KAPE  ──────────┐
                  ├──> triage folder ──> usbhawk sessions / tamper ──> per-host JSONL ──┐
  Velociraptor ───┘        (one host)        │                                          ├──> Elastic (or any SIEM)
                                             └──> usbhawk graph (many hosts) ──> findings ┘
  usbhawk detections build ──────────────────────────────────────> Sigma / ES|QL / KQL rules ──> live alerts
```

Every example below uses the fictional host from the demo kit (`NW-LEG-WS031`, wiped with USBOblivion by
`NW\m.ortiz`; see [examples/tamper](../examples/tamper/README.md)). The tool output is real; the names are invented.

What is verified and how:

| Integration | Verified | How |
|---|---|---|
| KAPE folder layout (`<tdest>\C\Windows\...`, RegBack copies) | ✅ | Automated tests (`tests/hunt_usb_tamper/test_tamper_triage_layouts.py`) and the example below |
| Velociraptor collection layout (`uploads\auto\C%3A\...`, `%25`-encoded names) | ✅ | Automated tests (same file) |
| Live collection on a running PC (`collect_local.ps1`) | ✅ | Release test cases 3.7 / 3.8 on a real Windows 11 PC, with and without Sysmon |
| Elastic detection rules (ES\|QL, Kibana import) | ✅ generated and checked against the reference evaluator | Not yet run in a live Elastic cluster: [ideas/live-siem-tests.md](../ideas/live-siem-tests.md) |
| Shipping results into Elastic (Filebeat, file upload) | ⚠️ standard Elastic features, not run here | The JSONL is ECS-shaped and one document per line |

---

## KAPE

### 1. Collect

KAPE (Kroll Artifact Parser and Extractor) copies the evidence files. USBHawk needs the registry hives, the event
logs and `setupapi.dev.log`. Use KAPE's built-in targets, from an elevated prompt on the host, or with `--tsource`
pointing at a mounted image:

```
kape.exe --tsource C: --tdest D:\kape\NW-LEG-WS031 --target RegistryHives,EventLogs,USBDevicesLogs
```

A compound target such as `KapeTriage` also includes them. Collect once per host, into a folder named after it.

### 2. Analyse

Point `--triage` at the `--tdest` folder. There is no KAPE flag: USBHawk finds the files by name. It also handles the
extra copies KAPE collects, such as the `config\RegBack` hives (empty since Windows 10 1803):

```
usbhawk tamper   --triage D:\kape\NW-LEG-WS031 --out runs\NW-LEG-WS031
usbhawk sessions --triage D:\kape\NW-LEG-WS031 --out runs\NW-LEG-WS031
```

```
  skipped D:\kape\NW-LEG-WS031\C\Windows\System32\config\RegBack\SYSTEM: empty file
  skipped D:\kape\NW-LEG-WS031\C\Windows\System32\config\RegBack\SOFTWARE: empty file
  parsed SYSTEM D:\kape\NW-LEG-WS031\C\Windows\System32\config\SYSTEM
  parsed SOFTWARE D:\kape\NW-LEG-WS031\C\Windows\System32\config\SOFTWARE
  parsed NTUSER m.ortiz
  parsed Partition/Diagnostic ...\Microsoft-Windows-Partition%4Diagnostic.evtx (0 records)
Host NW-LEG-WS031  feature updates/installs: 2024-02-12, 2026-03-02
| high   | orphaned_device_reference | 2026-10-29 18:05:31 | USB serial 4C530001230601108811 still appears in registry:EMDMgmt ...
| high   | cleanup_tool_execution    | 2026-10-29 18:42:10 | USBOblivion (USBOblivion64.exe) was run by m.ortiz ...
| medium | partition_log_gap         | -                   | Partition/Diagnostic log is empty, yet the registry shows 1 USB storage device(s) ...
```

### 3. Things to know

- **Dirty hives.** KAPE copies a running system's hives with their transaction logs (`SYSTEM.LOG1/.LOG2`) but does
  not apply them, and the newest USB activity is often only in those logs. Replay them with Eric Zimmerman's
  `rla.exe -d D:\kape\NW-LEG-WS031\C\Windows\System32\config --out D:\kape\NW-LEG-WS031-clean --ca`, then pass the
  clean hives with `--system` / `--software` (they override what `--triage` finds). rla names each output after its
  source path (`D_kape_NW-LEG-WS031_C_Windows_System32_config_SYSTEM`): list the folder and copy the names; a wrong
  name stops the run with a suggestion instead of running without the hive. USBHawk warns when a hive is dirty
  (`SYSTEM hive ... is dirty (sequence numbers 4317 and 4316)`), and every `orphaned_device_reference` on a dirty
  SYSTEM hive carries a caution: the drive connected just before collection can be missing from `Enum` without
  having been wiped.
- **KAPE VHDX/VHD output (`--vhdx`).** USBHawk reads files, not images: give it a `.vhdx` and it prints these steps.
  Mount it read-only (PowerShell as administrator), note the drive letter, then point USBHawk at that drive:

  ```
  Mount-DiskImage -ImagePath D:\kape\NW-LEG-WS031.vhdx -Access ReadOnly
  Get-DiskImage -ImagePath D:\kape\NW-LEG-WS031.vhdx | Get-Disk | Get-Partition | Get-Volume
  usbhawk tamper   --triage F:\ --out runs\NW-LEG-WS031
  usbhawk sessions --triage F:\ --out runs\NW-LEG-WS031
  usbhawk detections run --evtx F:\ --out runs\NW-LEG-WS031\detections
  Dismount-DiskImage -ImagePath D:\kape\NW-LEG-WS031.vhdx
  ```

  `detections run --evtx F:\` finds every `.evtx` on the drive and reads the host's time zone from the SYSTEM hive
  there, so H2 (off hours) is judged on the host's clock. Logs from `Windows.old` (the PC's previous installation)
  are labelled as such; their setup-time computer names (`WIN-...`) explain most `evidence_host_mismatch` findings.
- **Logs copied while open.** A chunk of a live-copied `.evtx` can be damaged. USBHawk reads around it and warns
  (`... 1 damaged chunk(s) or record(s) skipped, 20 records read from the rest of the file`); if the damaged log
  is the Partition/Diagnostic one, a record-ID jump is reported as low (possibly damage) rather than medium
  (deletion).
- **Volume shadow copies.** If KAPE collected shadow copies (`--vss`), each one is an older state of the same host.
  Run USBHawk once per copy, pointing `--triage` at that copy's folder, and compare: a stick present in an older copy
  but wiped from the current one is exactly what `tamper` and `graph` look for.
- **Disk images (E01, dd/raw, VMDK).** Mount the image read-only (Arsenal Image Mounter, FTK Imager), then run KAPE
  with `--tsource F:` (the mounted drive) and continue as above, or point `--triage F:\` at the drive directly.

---

## Velociraptor

### One host: an offline collector

1. In the Velociraptor GUI: **Server Artifacts → Build offline collector**, artifact **Windows.KapeFiles.Targets**,
   and tick the targets **RegistryHives**, **EventLogs** and **USBDevicesLogs** (Velociraptor ships the KAPE target
   definitions; if your version names them differently, pick the targets that collect the registry hives, the event
   logs and `Windows\INF\setupapi.dev*.log`). Build the Windows executable.
2. Run the collector on the host as administrator. It writes `Collection-<host>-<time>.zip`.
3. Extract the zip and point USBHawk at the extracted folder. Velociraptor's layout (`uploads\auto\C%3A\Windows\...`,
   `%` encoded as `%25` in file names) needs no flag:

```
usbhawk sessions --triage D:\velo\NW-LEG-WS031 --out runs\NW-LEG-WS031
usbhawk tamper   --triage D:\velo\NW-LEG-WS031 --out runs\NW-LEG-WS031
```

### Many hosts: a hunt

1. **Hunt Manager → New hunt**, artifact **Windows.KapeFiles.Targets** with the same three targets, scoped to the
   hosts (or the whole fleet). Launch it.
2. When the hunt completes, download its results and extract each host's collection into its own folder, for example
   `D:\hunt\collections\<host>`.
3. Run the host tools for every folder, then link the fleet:

```powershell
Get-ChildItem D:\hunt\collections -Directory | ForEach-Object {
    usbhawk sessions --triage $_.FullName --out "runs\$($_.Name)" -q
    usbhawk tamper   --triage $_.FullName --out "runs\$($_.Name)" -q
}
usbhawk graph --runs runs --out fleet
```

On the fictional demo fleet this gives (see [examples/graph](../examples/graph/README.md)):

```
Fleet 4 hosts, 6 USB devices (1 on more than one host), 4 users, 8 sessions
| high   | wiped_here_seen_there | SanDisk Ultra (4C530001230601105525)                 | 1 | wiped from the registry on NW-OPS-WS019, ...
| high   | exfil_device_spread   | Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D) | 3 | high-risk session (score 85) on NW-FIN-WS042 ...
```

The `wiped_here_seen_there` finding is the reason to hunt the whole fleet: the host that was wiped is not the host
that still remembers the stick.

---

## Elastic

Two separate things: **live rules** that run in Elastic Security, and **USBHawk's results** stored in Elastic so
you can search and pivot on them next to your other logs.

### 1. Live detection rules

```
usbhawk detections build --target elastic --out rules
```

This writes one ES|QL query per detection (`rules\elastic\*.esql`) and `rules\elastic\usbhawk_rules.ndjson`. In
Kibana: **Security → Rules → Detection rules (SIEM) → Import rules**, and choose the `.ndjson` file. The rules arrive
**disabled**, with ATT&CK mapping, severity, risk score and a triage guide (the `response` steps of each hypothesis).
Review them, then enable.

They query `logs-*, winlogbeat-*` with ECS field names, so the hosts need the telemetry each hypothesis reads:

| Hypotheses | Elastic data |
|---|---|
| H1, H2 | Windows Security logs with *Audit PNP Activity* enabled (event 6416) |
| H3, H4 | Sysmon file-create events (Elastic Agent **Windows** integration with the Sysmon channel, or Winlogbeat) |
| H5, H6, H7 (commands) | Sysmon process creation, or Security 4688 with command lines, or Elastic Defend |
| H7 | Security 1102 and System 104 |
| H8 | Sysmon registry events, with the USB registry rules from `scripts\lab\sysmon-usbhawk-lab.xml` |

Before enabling them, check them offline against your own logs: `usbhawk detections run --evtx <exported logs>` uses
the same logic and prints any **Telemetry gaps** (see [hunt-detection-rules.md](hunt-detection-rules.md)).

### 2. USBHawk results in Elastic

`sessions.jsonl`, `tamper.jsonl` and the graph's `findings.jsonl` are one ECS document per line: `@timestamp`,
`event.dataset` (`usbhawk.session`, `usbhawk.tamper`, `usbhawk.graph`), `event.risk_score`, `host.name`,
`user.name`, `usb.device.*` and a `usbhawk.*` group with every reason.

**Quick look:** Kibana's **Upload a file** (Integrations → Upload a file) imports a newline-delimited JSON file into an
index you name; choose `@timestamp` as the time field.

**Continuous (Filebeat):** for a case server or an IR workstation that produces results regularly:

```yaml
filebeat.inputs:
  - type: filestream
    id: usbhawk-results
    paths:
      - D:\usbhawk\runs\*\sessions.jsonl
      - D:\usbhawk\runs\*\tamper.jsonl
      - D:\usbhawk\fleet\findings.jsonl
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: true
output.elasticsearch:
  hosts: ["https://your-elastic:9200"]
```

Then search in Kibana (KQL), for example:

```
event.dataset : "usbhawk.session" and usbhawk.severity : "high"
event.dataset : "usbhawk.tamper" and usbhawk.rule : "cleanup_tool_execution"
usb.device.serial : "4C530001230601108811"
```

The last query is the pivot: one serial, every host and every finding that mentions it. `alerts.jsonl` from
`detections run` is plain JSON (its time field is `timestamp`), useful for a one-off upload rather than continuous
ingestion.

---

Related: [GETTING-STARTED.md](GETTING-STARTED.md) (install, collection, live response, telemetry),
[USE-CASES.md](USE-CASES.md) (the four use cases on one page), [ideas/velociraptor-kape.md](../ideas/velociraptor-kape.md)
(a ready-made Velociraptor artifact and KAPE module are planned).
