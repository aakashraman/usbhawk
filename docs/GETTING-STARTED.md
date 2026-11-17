# Getting started with USBHawk

From nothing to a first answer in a few minutes, then on to a real case. Every command here also has
`usbhawk <command> --help`, which shows the question it answers, its options, examples and the files it writes.

## 1. Get USBHawk

| You are... | Use | Needs |
|---|---|---|
| a responder on a Windows analysis box | **`usbhawk.exe`** from the release zip | nothing (Windows 10 / 11, x64) |
| an analyst with Python, on any OS | the **wheel**: `pip install usbhawk-1.0.0-py3-none-any.whl` | Python 3.11+ |
| changing USBHawk itself | the **source**: `pip install -e ".[dev]"` | Python 3.11+, git |

**Standalone exe.** Unzip `usbhawk-1.0.0-windows-x64.zip` anywhere, open PowerShell in that folder:

```powershell
.\usbhawk.exe                 # banner, the commands and examples
.\usbhawk.exe --version
```

Check the download against `SHA256SUMS.txt` first: `Get-FileHash .\usbhawk-1.0.0-windows-x64.zip`. The exe is not
code-signed yet, so SmartScreen may warn on first run (see [ideas/signed-releases.md](../ideas/signed-releases.md)).
It starts a little slower than the Python version because it unpacks itself on each run.

**Python package.** In a virtual environment:

```powershell
py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1          # Linux/macOS: python3 -m venv .venv && source .venv/bin/activate
pip install usbhawk-1.0.0-py3-none-any.whl
usbhawk --version             # or: python -m usbhawk --version
```

The commands are the same either way. Below, `usbhawk` means `.\usbhawk.exe` if you use the exe.

## 2. Try it on demo data (2 minutes)

The release zip and the repository include `examples/`, with fictional data for the fleet graph and the detection
rules. From the folder that contains `examples`:

```powershell
usbhawk detections run --events examples\detections\insider_timeline.jsonl
usbhawk graph --runs examples\fleet
usbhawk graph --runs examples\fleet device 60A44C41
```

The first replays a Friday-evening insider through the eight detection rules (all eight fire). The second links four
hosts' USB history and raises all six fleet hunts. The third shows everywhere one stick has been. What each line
means: [examples/README.md](../examples/README.md).

## 3. Investigate one host

**Collect.** USBHawk reads offline evidence: a KAPE or Velociraptor triage folder, a mounted image, or files copied
by hand. It needs:

| Artifact | Path on the host | Gives |
|---|---|---|
| SYSTEM, SOFTWARE | `C:\Windows\System32\config\` | every USB device, serials, letters, volumes, times |
| NTUSER.DAT (each user) | `C:\Users\<user>\` | which user mounted which volume |
| Partition/Diagnostic log | `...\winevt\Logs\Microsoft-Windows-Partition%4Diagnostic.evtx` | every connect and disconnect, reformat evidence (Windows 10+) |
| Security and System logs | `...\winevt\Logs\Security.evtx`, `System.evtx` | plug-ins, file access, log clearing |
| setupapi.dev.log | `C:\Windows\INF\` | first install |
| EDR file events (optional) | MDE / Sysmon / Falcon CSV export | files written to the stick |

A KAPE or Velociraptor triage that collects the registry hives and event logs has most of these; check that
`setupapi.dev.log` is in it too (USBHawk reports it as missing when the `INF` folder was collected without it). On a
lab machine of your own, `scripts\collect_local.ps1` (elevated) collects everything with `reg save` and
`wevtutil epl`. Point USBHawk at the folder; it finds everything inside.

**Run the hunts.**

```powershell
usbhawk sessions --triage D:\cases\WS042 --out out\WS042        # which sessions look like exfil, and why
usbhawk tamper   --triage D:\cases\WS042 --out out\WS042        # was the USB evidence wiped
usbhawk devices  --triage D:\cases\WS042                         # the 11-step profile of every device
```

Add EDR file events and HR context to `sessions` when you have them:

```powershell
usbhawk sessions --triage D:\cases\WS042 --file-events mde_files.csv --watchlist leavers.txt `
                 --allowlist approved_usb.txt --tz America/New_York --min-score 40 --out out\WS042
```

**Read the result.** Sessions are sorted by score; each line says why it scored (`first_seen_device`,
`off_hours`, `bulk_transfer`, `reformat_or_repartition`...), and `--out` writes the reasons in full to
`sessions.jsonl`. Tamper findings come with a severity and a sentence that says what was found and what explains it.
Warnings at the end (for example `evidence_host_mismatch`) are about the evidence itself: read them before trusting a
result. All times are UTC; only the off-hours judgement uses the host's local clock.

## 4. Many hosts

Run `sessions` and `tamper` with `--out out\<host>` for every host, then link them:

```powershell
usbhawk graph --runs out --out fleet           # findings + graph.json / graph.graphml / graph.cypher
usbhawk graph --runs out device 60A44C41       # where has this stick been (serial, VSN or name)
usbhawk graph --runs out user j.doe            # every stick one user touched
```

## 5. Catch it live next time

```powershell
usbhawk detections list                        # the 8 hypotheses and their 12 detections
usbhawk detections build --out rules           # Sigma, Elastic (ES|QL + Kibana import), Sentinel (KQL)
usbhawk detections run --evtx D:\cases\WS042\Logs --removable-drives F:   # replay collected logs through them
```

Thresholds, archive extensions and work hours come from a scoring file: copy `config\scoring.toml`, edit it, and pass
`--config my_scoring.toml` to `sessions` and `detections` so the offline hunt and the live rules agree.

## 6. Send results to a SIEM

Session, tamper and graph results are JSON Lines with ECS fields (`@timestamp`, `event.*`, `host.name`,
`user.name`) and a `usbhawk.*` group, ready for Splunk, Elastic or Sentinel ingestion; the others are plain JSON or CSV:

| File | From | Format |
|---|---|---|
| `sessions.jsonl` | `sessions` | ECS, `event.dataset: usbhawk.session` |
| `tamper.jsonl` | `tamper` | ECS, `event.dataset: usbhawk.tamper` |
| `findings.jsonl` | `graph` | ECS, `event.dataset: usbhawk.graph` |
| `sessions.csv` | `sessions` | one row per session with its reasons (Excel, timelines) |
| `devices.jsonl` | `sessions`, `devices` | one device profile per line (also the fleet graph's input) |
| `alerts.jsonl` | `detections run` | one alert per line: hypothesis, detection, level, why, evidence |

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `no artifacts found` | the folder has none of the files above; check the path, or pass files with `--system`, `--security-log`... |
| `config file not found` / `list file not found` | a typo in `--config`, `--watchlist` or `--allowlist`; USBHawk never falls back to defaults silently |
| `--runs path not found` | a typo in a `graph --runs` folder |
| only the first connection of each stick on a Windows 7 host | Windows 7 keeps no later-arrival times; see [REFERENCE.md](REFERENCE.md#known-limitations) |
| `evidence_host_mismatch` | the logs carry another computer name: logs from several machines were merged, or the PC was renamed or built from an image; the finding says which |
| hive errors on a live-collected hive | replay the hive's transaction logs first (KAPE does), or collect with `reg save` |
| no banner / want no banner | the banner shows in help and on an interactive terminal only; `-q` or `USBHAWK_NO_BANNER=1` turns it off |

Deeper: [REFERENCE.md](REFERENCE.md) (pipeline, scoring rules, artifacts, limits) and one guide per hunt:
[sessions](hunt-exfil-sessions.md), [tamper](hunt-usb-tamper.md), [detections](hunt-detection-rules.md),
[graph](hunt-fleet-device-graph.md).
