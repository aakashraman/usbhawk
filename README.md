# USBHawk

```
   __  _______ ____  __  __               __
  / / / / ___// __ )/ / / /___ __      __/ /__
 / / / /\__ \/ __  / /_/ / __ `/ | /| / / //_/
/ /_/ /___/ / /_/ / __  / /_/ /| |/ |/ / ,<
\____//____/_____/_/ /_/\__,_/ |__/|__/_/|_|
   USB forensics for threat hunting & incident response
```

Windows USB forensics built for **threat hunting and incident response**, not just device inventory.

Most USB tools answer *"what devices were plugged in?"*. USBHawk answers the questions an investigation actually asks:

| Command | Question it answers |
|---|---|
| `usbhawk sessions` | Which USB sessions look like data exfiltration, and why? |
| `usbhawk tamper` | Did someone wipe the USB evidence, or did Windows clean it up? |
| `usbhawk detections` | How do we catch it live next time? (Sigma, Elastic, Sentinel rules) |
| `usbhawk graph` | Where else has this stick been, and who else used it? (many hosts) |
| `usbhawk devices` | What devices were connected? (the SANS FOR500 11-step profile) |

It turns the FOR500 device profile into connect → remove **sessions**, attaches users and file activity, scores every
session with explainable rules, and builds on that for tamper detection, live detection rules and a fleet graph.
*Formerly the "USB Threat Hunting Toolkit" (`usbthk`); `usbthk` still works as a command alias.*

```
Score      Start (UTC)          Dur   Class    Device            Letter  VSN                 Writes  Why
100 high   2026-10-30 21:14:52  26m   usbstor  Kingston DT 3.0   F:      8E2C41D7,11223344   61      first_seen_device; off_hours; file_writes;
                                                                                                     bulk_transfer; archive_written;
                                                                                                     reformat_or_repartition; watchlist_user
```

Every point of every score comes with a reason, e.g.
`off_hours +15: connected 2026-10-30 21:14Z = Fri 2026-10-30 17:14 America/New_York, outside work hours (tz from --tz)`.

## Get it

| | How | Needs |
|---|---|---|
| **Windows exe** | unzip `usbhawk-1.0.0-windows-x64.zip`, run `.\usbhawk.exe` | nothing |
| **Python package** | `pip install usbhawk-1.0.0-py3-none-any.whl`, then `usbhawk` or `python -m usbhawk` | Python 3.11+ (Windows, Linux, macOS) |
| **From source** | `pip install -e ".[dev]"` in a clone | Python 3.11+ |

Step by step, including checking the download: **[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)**.

## Try it in two minutes

```powershell
usbhawk detections run --events examples\detections\insider_timeline.jsonl   # an insider timeline: all 8 rules fire
usbhawk graph --runs examples\fleet                                          # four hosts: all 6 fleet hunts fire
usbhawk graph --runs examples\fleet device 60A44C41                          # everywhere one stick has been
```

Demo commands for every module, with the output to expect: **[examples/README.md](examples/README.md)**. Real public
evidence (the NIST CFReDS Data Leakage case, EVTX-ATTACK-SAMPLES) is one command away:
`python scripts\fetch_demo_datasets.py --list`.

## Use it on a case

```powershell
usbhawk sessions --triage D:\cases\WS042 --out out\WS042        # KAPE / Velociraptor folder or mounted image
usbhawk tamper   --triage D:\cases\WS042 --out out\WS042
usbhawk graph    --runs out --out fleet                         # after collecting several hosts
usbhawk detections build --out rules                            # deployable Sigma / ES|QL / KQL
```

Every command explains itself: `usbhawk <command> --help` shows the question it answers, options, examples, output
files and its guide.

## Modules

| # | Module | Question it answers | Verified on | Guide |
|---|---|---|---|---|
| 2 | `sessions`: exfil session scoring | Which USB sessions look like exfil, and why? | public samples, a real PC, NIST case | [hunt-exfil-sessions](docs/hunt-exfil-sessions.md) |
| 3 | `tamper`: USB tamper and cleanup detection | Wiped by someone, or cleaned up by Windows? | Win10 VM vs USBOblivion, NIST case | [hunt-usb-tamper](docs/hunt-usb-tamper.md) |
| 4 | `detections`: detection-as-code | Catch it live: Sigma, Elastic (ES\|QL), Sentinel (KQL) | Sysmon lab, EVTX-ATTACK-SAMPLES | [hunt-detection-rules](docs/hunt-detection-rules.md) |
| 1 | `graph`: fleet device graph | Where else has this stick been, who else used it? | two real hosts | [hunt-fleet-device-graph](docs/hunt-fleet-device-graph.md) |

On the NIST CFReDS Data Leakage case (Windows 7), USBHawk found both USB sticks of the answer key with the right
serials, user and first-connection times, and raised no false tamper or detection alerts. What it missed on Windows 7,
and why, is in [docs/TESTING.md](docs/TESTING.md) and [ideas/](ideas/README.md).

## Documentation

| Doc | Contents |
|---|---|
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | Install, demo, one host, many hosts, live rules, SIEM output, troubleshooting |
| [examples/README.md](examples/README.md) | Demo commands for every module and the output to expect; public datasets |
| [docs/REFERENCE.md](docs/REFERENCE.md) | How it works, scoring rules, time zones, every artifact parsed, known limitations |
| `docs/hunt-*.md` | One guide per module: logic, every finding, sample output, lab results, limits |
| [docs/TESTING.md](docs/TESTING.md) | Test layers, test inventory, lab procedures, real-data validation |
| [ideas/README.md](ideas/README.md) | Future work, one file per idea |
| [CHANGELOG.md](CHANGELOG.md) | Releases |
| [CLAUDE.md](CLAUDE.md) | Architecture rules and forensic gotchas for contributors |

## Testing

Every module is tested in three layers before it ships: automated tests (`pytest -q`, one folder per hunt plus the
demo kit), sample runs on public evidence, and lab tests on a throwaway VM cross-checked with Eric Zimmerman's RECmd
and EvtxECmd. Every documented sample output is backed by a test. Details: [docs/TESTING.md](docs/TESTING.md).

## Credits

Methodology: SANS FOR500. Research: Yogesh Khatri (device property timestamps), Nicole Ibrahim (MTP/PTP),
Kevin Ripa (USB serial numbers), David Cowen & Phill Moore (DeviceMigration). Prior art: USB Detective (Jason Hale),
parseusbs (Kathryn Hedley), Partition-4DiagnosticParser (theAtropos4n6). Parsers: regipy, evtx (pyevtx-rs).
Public test data: regipy test hives, Partition-4DiagnosticParser sample, NIST CFReDS, EVTX-ATTACK-SAMPLES
(fetched on demand, never bundled).

MIT License.
