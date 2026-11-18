# Getting started with USBHawk

From nothing to a first answer in a few minutes, then on to a real case. Every command here also has
`usbhawk <command> --help`, which shows the question it answers, its options, examples and the files it writes.

## 1. Get USBHawk

| You are... | Use | Needs |
|---|---|---|
| a responder on a Windows analysis box | **`usbhawk.exe`** from the release zip | nothing (Windows 10 / 11, x64) |
| an analyst with Python, on any OS | the **wheel**: `pip install usbhawk-1.0.0-py3-none-any.whl` | Python 3.11+ |
| changing USBHawk itself | the **source**: `pip install -e ".[dev]"` | Python 3.11+, git |

Every step below is given for **PowerShell** and for **CMD** (Command Prompt) where the two differ. The downloads are
on the [Releases page](https://github.com/aakashraman/usbhawk/releases/latest); the examples assume you saved them
in `%USERPROFILE%\Downloads` and install into `C:\Tools`.

### Standalone exe (no Python)

1. **Check the download** against the zip's line in `SHA256SUMS.txt`:

   PowerShell:
   ```powershell
   Get-FileHash $env:USERPROFILE\Downloads\usbhawk-1.0.0-windows-x64.zip -Algorithm SHA256
   ```
   CMD:
   ```cmd
   certutil -hashfile %USERPROFILE%\Downloads\usbhawk-1.0.0-windows-x64.zip SHA256
   ```

2. **Unzip it** into `C:\Tools`:

   PowerShell:
   ```powershell
   Expand-Archive $env:USERPROFILE\Downloads\usbhawk-1.0.0-windows-x64.zip -DestinationPath C:\Tools
   ```
   CMD (`tar` is built into Windows 10 and 11):
   ```cmd
   mkdir C:\Tools
   tar -xf %USERPROFILE%\Downloads\usbhawk-1.0.0-windows-x64.zip -C C:\Tools
   ```

3. **Run it** from its folder. Write `.\usbhawk.exe`: PowerShell requires the `.\` for a program in the current
   folder, and CMD accepts it too (plain `usbhawk.exe` also works in CMD).

   PowerShell:
   ```powershell
   cd C:\Tools\usbhawk-1.0.0-windows-x64
   .\usbhawk.exe                 # banner, the commands and examples
   .\usbhawk.exe --version
   ```
   CMD (`/d` also switches drive, e.g. from `D:`):
   ```cmd
   cd /d C:\Tools\usbhawk-1.0.0-windows-x64
   .\usbhawk.exe
   .\usbhawk.exe --version
   ```

4. **Optional: run it from any folder.** Add the folder to your user `PATH`, then open a **new** terminal:

   PowerShell:
   ```powershell
   [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";C:\Tools\usbhawk-1.0.0-windows-x64", "User")
   ```
   CMD: open *Settings → System → About → Advanced system settings → Environment Variables*, edit `Path` under
   your user, and add `C:\Tools\usbhawk-1.0.0-windows-x64`. (Avoid `setx PATH`: it can cut a long PATH short.)

The exe is not code-signed yet, so SmartScreen may warn on the first run: *More info → Run anyway* (see
[ideas/signed-releases.md](../ideas/signed-releases.md)). It starts a little slower than the Python version because it
unpacks itself on each run.

### Python package (the wheel)

1. **Check Python** (3.11 or newer). Same in PowerShell and CMD:
   ```cmd
   py --version
   ```
   If `py` is not found, install Python from python.org (tick *Add python.exe to PATH*) or run
   `winget install Python.Python.3.13`, then open a new terminal.

2. **Create a virtual environment**, a private Python just for USBHawk. Same in PowerShell and CMD:
   ```cmd
   py -3 -m venv C:\Tools\usbhawk-venv
   ```

3. **Activate it.** The prompt then starts with `(usbhawk-venv)`. Do this in every new terminal:

   PowerShell:
   ```powershell
   C:\Tools\usbhawk-venv\Scripts\Activate.ps1
   ```
   CMD:
   ```cmd
   C:\Tools\usbhawk-venv\Scripts\activate.bat
   ```

   If PowerShell says *running scripts is disabled on this system*, skip activation and call the program by its full
   path, `C:\Tools\usbhawk-venv\Scripts\usbhawk.exe`, or use CMD.

4. **Install and check it.** Same in PowerShell and CMD:
   ```cmd
   pip install %USERPROFILE%\Downloads\usbhawk-1.0.0-py3-none-any.whl
   usbhawk --version
   ```
   In PowerShell write the path as `$env:USERPROFILE\Downloads\usbhawk-1.0.0-py3-none-any.whl`.
   `python -m usbhawk --version` works too. On Linux or macOS: `python3 -m venv ~/usbhawk-venv`,
   `source ~/usbhawk-venv/bin/activate`, then the same `pip install`.

The wheel installs the program only. The demo data (`examples\`) is in the release zip and the repository.

### From source

```cmd
git clone https://github.com/aakashraman/usbhawk
cd usbhawk
py -3 -m venv .venv
```

Activate (PowerShell `.\.venv\Scripts\Activate.ps1`, CMD `.venv\Scripts\activate.bat`), then:

```cmd
pip install -e ".[dev]"
python scripts\fetch_test_samples.py
pytest -q
```

`fetch_test_samples.py` downloads the public sample evidence (about 30 MB) that the `sessions` and `tamper` demos
and some tests use.

### PowerShell or CMD below

The rest of this guide is written for PowerShell. In CMD the `usbhawk` commands are the same, with two differences:

| | PowerShell | CMD |
|---|---|---|
| Continuing a long command on the next line | `` ` `` at the end of the line | `^` at the end of the line |
| Environment variables | `$env:USERPROFILE`, `$env:USBHAWK_NO_BANNER = "1"` | `%USERPROFILE%`, `set USBHAWK_NO_BANNER=1` |

Below, `usbhawk` means `.\usbhawk.exe` if you use the exe (in either shell).

## 2. Try it on demo data (2 minutes)

The release zip and the repository include `examples/`, with fictional demo evidence. From the folder that
contains `examples`:

```powershell
usbhawk detections run --events examples\detections\insider_timeline.jsonl
usbhawk tamper --triage examples\tamper\wiped-host
usbhawk graph --runs examples\graph\fleet
usbhawk graph --runs examples\graph\fleet device 60A44C41
```

The first replays a Friday-evening insider through the eight detection rules (all eight fire). The second examines a
PC wiped with USBOblivion (real registry hives and event log, fictional content) and finds the tool run, the sticks
it erased and the emptied log. The third links four hosts' USB history and raises all six fleet hunts. The fourth
shows everywhere one stick has been. What each line
means, and a demo for every tool (including `sessions` and `tamper` on public sample evidence):
[examples/](../examples/README.md), one folder per tool.

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

**Point USBHawk at it.** There is no format flag: `--triage <folder>` searches the folder and all its subfolders
and recognises the files above **by name**, wherever they are. So you point it at the top of whatever your
collection tool produced, one host per run:

| Evidence you have | What to pass |
|---|---|
| **KAPE** output (`--tdest D:\kape\WS042`, files under `...\C\Windows\...`) | `--triage D:\kape\WS042` |
| **Velociraptor** collection (`Windows.KapeFiles.Targets` or an offline collector): a zip | Extract the zip, then `--triage <extracted folder>`. Encoded paths such as `uploads\auto\C%3A\...` and `...Partition%254Diagnostic.evtx` are fine |
| A **disk image** (E01, dd/raw, VMDK, VHDX) | USBHawk does not open images itself. Mount it read-only (Arsenal Image Mounter, FTK Imager, or `Mount-DiskImage` for VHDX), then either run KAPE against the mounted drive (`kape.exe --tsource F: --tdest D:\kape\WS042 ...`) and use that folder, or point `--triage` at the mounted drive (`--triage F:\`, slower: it walks the whole volume) |
| A **live machine** you are responding on | Collect first with `scripts\collect_local.ps1`, then `--triage` its output: see [Live response](#live-response-on-a-running-machine) below |
| Files you copied by hand | Put them in one folder (any layout) and `--triage` it, or name each file: `--system`, `--software`, `--ntuser PATH=USER`, `--partition-log`, `--security-log`, `--system-log`, `--setupapi` |

Collection tools usually copy more than one file with the same name: the live hive in `Windows\System32\config`,
the `config\RegBack` copies (empty since Windows 10 1803, otherwise older backups) and a previous installation's
hives in `Windows.old`. USBHawk always uses the live hive and prints a `skipped ...` line for every other copy. Worked KAPE, Velociraptor
and Elastic examples: [INTEGRATIONS.md](INTEGRATIONS.md). The
user for each `NTUSER.DAT` is its folder name (`Users\j.doe\NTUSER.DAT` is `j.doe`).

What to collect with KAPE: the `RegistryHives`, `EventLogs` and `USBDevicesLogs` targets (or a compound target that
includes them); check that `setupapi.dev.log` is in the output, since USBHawk reports it as missing when the `INF`
folder was collected without it.

**Hives copied from a running system are "dirty".** Windows keeps its most recent registry changes in the
transaction logs next to each hive (`SYSTEM.LOG1`, `SYSTEM.LOG2`) until it writes them back, and the most recent
changes are often the USB activity you are looking for. USBHawk reads the hive file itself and does not replay those
logs. Replay them first with Eric Zimmerman's `rla.exe` into a separate folder, then give USBHawk the clean hives
(per-file flags override what `--triage` finds):

```powershell
rla.exe -d D:\kape\WS042 --out D:\kape\WS042-clean --ca
usbhawk sessions --triage D:\kape\WS042 --system <clean SYSTEM> --software <clean SOFTWARE> --out out\WS042
```

Hives saved with `reg save`, or from a machine that was shut down cleanly, are usually not dirty; an image of a
machine that lost power can be. When in doubt run `rla.exe` anyway: it only changes hives that need it.

### Live response on a running machine

USBHawk analyses collected evidence. The hives of a running Windows machine are locked, so collect first, from an
elevated PowerShell, writing to your IR drive rather than the evidence disk:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\collect_local.ps1 -Out E:\IR\WS042
usbhawk sessions --triage E:\IR\WS042 --out E:\IR\WS042-out
usbhawk tamper   --triage E:\IR\WS042 --out E:\IR\WS042-out
usbhawk detections run --evtx E:\IR\WS042 --out E:\IR\WS042-out
```

`collect_local.ps1` ships in the release zip (`scripts\`). It:

- saves `SYSTEM`, `SOFTWARE` and the current user's hive with `reg save` (clean copies: no transaction-log replay
  needed);
- exports the Partition/Diagnostic, Security, System and, when installed, Sysmon logs with `wevtutil epl`;
- copies `setupapi.dev.log`, and warns instead of stopping when a cleanup tool has deleted it.

It collects the hive of the user running it only; other profiles' `NTUSER.DAT` need KAPE. `detections run` on the
exported logs shows what the rules would have caught on this machine. You can also point `detections run --evtx` at
the live `C:\Windows\System32\winevt\Logs` folder from an elevated prompt; any log file Windows will not share is
listed and skipped, never fatal, and without administrator rights every file is refused, with a message saying so.

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

**Read the result.** Sessions are sorted by score; the Description column lists the rules that fired
(`first_seen_device`, `off_hours`, `bulk_transfer`, `reformat_or_repartition`...), and `--out` writes each rule's
points and full sentence to `sessions.jsonl`. The score is a **triage priority, not a verdict**: start with high
(≥ 70), read the rules rather than the number, and remember that without `--file-events` the file rules cannot fire.
How the 13 rules and the score work: [hunt-exfil-sessions.md, section 5](hunt-exfil-sessions.md#5-stage-4-score);
what to pivot on next: [the README's pivot table](../README.md#pivot-points). Tamper findings come with a severity and a sentence that says what was found and what explains it.
Warnings at the end (for example `evidence_host_mismatch`) are about the evidence itself: read them before trusting a
result. All times are UTC; only the off-hours judgement uses the host's local clock.

## 4. Many hosts

Collect the same files from every host (a Velociraptor hunt with `Windows.KapeFiles.Targets`, or KAPE), one folder
per host. Run `sessions` and `tamper` with `--out out\<host>` for every host, for example:

```powershell
Get-ChildItem D:\hunt\collections -Directory | ForEach-Object {
    usbhawk sessions --triage $_.FullName --out "out\$($_.Name)" -q
    usbhawk tamper   --triage $_.FullName --out "out\$($_.Name)" -q
}
```

then link them:

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

### Turn on the telemetry the rules need

The rules can only fire on events Windows actually records, and by default it records few of them. Every
`detections run` ends with a **Telemetry gaps** note naming the hypotheses that could not fire, so zero alerts is
never mistaken for "nothing happened":

| Hypotheses | Need | Default on Windows |
|---|---|---|
| H1, H2 (USB connected, off hours) | Security 6416 (*Audit PNP Activity*) or Defender `DeviceEvents` | off |
| H3, H4 (bulk copy, archive to USB) | Sysmon event 11 (file create) or Defender `DeviceFileEvents` | no Sysmon |
| H5, H6 (format, cleanup tool) | Sysmon event 1 or Security 4688 (*Audit Process Creation*, with command lines) | off |
| H7 (log cleared) | Security 1102, System 104 (or process creation) | **on** |
| H8 (USB history deleted from the registry) | Sysmon events 12/13 | no Sysmon |

To test the rules on a machine of your own (a lab VM is best), from an **elevated** PowerShell:

1. Download Sysmon from Microsoft Sysinternals (<https://learn.microsoft.com/sysinternals/downloads/sysmon>) and
   unzip it, e.g. to `C:\Tools\Sysmon`.
2. Install it with the lab config shipped in the release zip and repository (`scripts\lab\sysmon-usbhawk-lab.xml`).
   It logs every process start and every file created, plus registry changes under the USB keys. From the unzipped
   USBHawk folder (or the repository root):
   ```powershell
   C:\Tools\Sysmon\Sysmon64.exe -accepteula -i scripts\lab\sysmon-usbhawk-lab.xml
   ```
   `Error: Failed to open xml configuration` means the path is wrong for the folder you are in: give the full path
   to the `.xml` file instead.
3. Give its log room (that config is busy; 256 MB here):
   ```powershell
   wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456
   ```
4. Turn on USB plug-in auditing (Security 6416, for H1 and H2):
   ```powershell
   auditpol /set /subcategory:"Plug and Play Events" /success:enable
   ```
5. Check that both are recording:
   ```powershell
   Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 3
   auditpol /get /subcategory:"Plug and Play Events"
   ```
6. Exercise the rules with a **spare** stick (say it is `E:`): plug it in (H1; H2 too outside work hours), copy a
   folder of 50+ files to it (H3), and write an archive to it (H4), e.g.
   `Compress-Archive -Path $env:USERPROFILE\Documents\* -DestinationPath E:\test.zip`. Formatting the stick
   (H5) erases it; run cleaners (H6), clear logs (H7) or delete USB registry keys (H8) only on a throwaway VM.
7. Replay, elevated (or collect first with `collect_local.ps1`, which also exports the Sysmon log):
   ```powershell
   usbhawk detections run --evtx C:\Windows\System32\winevt\Logs --removable-drives E:
   ```
8. Afterwards, on a machine you use every day: `C:\Tools\Sysmon\Sysmon64.exe -u` removes Sysmon, and
   `auditpol /set /subcategory:"Plug and Play Events" /success:disable` turns the auditing back off. For production
   monitoring, start from a maintained Sysmon config (e.g. sysmon-modular) and add the USB registry rules from the
   lab config.

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
| `alerts.jsonl` | `detections run` | one alert per line: hypothesis, detection, level, description (`why`), evidence |

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `'usbhawk' is not recognized` (CMD) / `The term 'usbhawk' is not recognized` (PowerShell) | the virtual environment is not active in this terminal (activate it again), or you use the exe: run it as `.\usbhawk.exe` from its folder, or add the folder to `PATH` |
| PowerShell: *running scripts is disabled on this system* | `Activate.ps1` is blocked by the execution policy: call `...\Scripts\usbhawk.exe` by its full path, or activate in CMD with `activate.bat` |
| `'py' is not recognized` | Python is not installed or not on `PATH`: install Python 3.11+ and open a new terminal |
| SmartScreen blocks `usbhawk.exe` | the exe is not code-signed yet: *More info → Run anyway* |
| `detections run` shows zero alerts and a **Telemetry gaps** note | the logs hold none of the events those rules need (Windows records little by default): see [Turn on the telemetry the rules need](#turn-on-the-telemetry-the-rules-need) |
| `warning: ... N removal records with no connect before them were not counted as sessions` | expected for a card reader: an empty slot logs "no media" on every poll; only real connect-to-remove pairs become sessions |
| a session shows `(none) 5&1A2B3C4D&0&9` as its iSerialNumber | the device has no hardware serial; that is the instance ID Windows made up, which changes per USB port (rule `no_hardware_serial`) |
| `no artifacts found` | the folder has none of the files above; check the path, or pass files with `--system`, `--security-log`... |
| `config file not found` / `list file not found` | a typo in `--config`, `--watchlist` or `--allowlist`; USBHawk never falls back to defaults silently |
| `--runs path not found` | a typo in a `graph --runs` folder |
| only the first connection of each stick on a Windows 7 host | Windows 7 keeps no later-arrival times; see [REFERENCE.md](REFERENCE.md#known-limitations) |
| `evidence_host_mismatch` | the logs carry another computer name: logs from several machines were merged, or the PC was renamed or built from an image; the finding says which |
| hive errors, or recent USB activity missing, on hives copied from a running system | the hives are dirty: replay their transaction logs with `rla.exe` and pass the clean hives with `--system` / `--software` (see [3. Investigate one host](#3-investigate-one-host)), or collect with `reg save` |
| `skipped ...\RegBack\SYSTEM: empty file` (or `Windows.old`) | expected: the collection also copied backup hives; USBHawk uses the live one in `Windows\System32\config` |
| no banner / want no banner | the banner shows in help and on an interactive terminal only; `-q` or `USBHAWK_NO_BANNER=1` turns it off |

Deeper: [REFERENCE.md](REFERENCE.md) (pipeline, scoring rules, artifacts, limits) and one guide per hunt:
[sessions](hunt-exfil-sessions.md), [tamper](hunt-usb-tamper.md), [detections](hunt-detection-rules.md),
[graph](hunt-fleet-device-graph.md).
