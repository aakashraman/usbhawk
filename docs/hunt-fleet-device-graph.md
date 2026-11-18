# Hunt: fleet device graph (`usbhawk graph`, module #1)

> **The question:** *Where else has this USB stick been, and who else used it?*

Modules #2 to #4 look at **one computer at a time**. An insider case or a malware outbreak rarely stays on one: the
stick that left Finance with the board pack was plugged into three other machines that month. `usbhawk graph` reads the
per-host outputs of the other modules for any number of hosts and links them into one graph of devices, hosts, users
and volumes, then hunts across it.

```
 out\NW-FIN-WS042\  out\NW-HR-WS007\  out\NW-ENG-LT113\  ...     one folder per host: `usbhawk sessions --out`
        │  devices.jsonl  sessions.jsonl  (tamper.jsonl from `usbhawk tamper --out`, optional)
        ▼
 usbhawk graph --runs out
        │
   (Device)──CONNECTED_TO──>(Host)        first/last seen, sessions, files written, top risk score
   (User)────USED──────────>(Device)      on which hosts
   (Device)──HAS_VOLUME────>(Volume)      volume serial number (VSN)
        ▼
 findings (G1-G6) · pivots (device / user) · graph.json · GraphML · Neo4j Cypher
```

## Quick start

```powershell
# 1. Per host (or from a Velociraptor / KAPE collection per host)
usbhawk sessions --triage D:\cases\NW-FIN-WS042 --out out\NW-FIN-WS042
usbhawk tamper   --triage D:\cases\NW-FIN-WS042 --out out\NW-FIN-WS042     # optional: enables G4

# 2. The fleet
usbhawk graph --runs out --out fleet                    # findings + exports (folders, a parent folder, or out\*)
usbhawk graph --runs out device 60A44C41                # where has this stick been? (serial, key, VSN or name)
usbhawk graph --runs out user j.doe                     # every stick one user touched
usbhawk graph --runs out --min-hosts 2 --new-days 14    # tune thresholds
```

## Same stick, or just the same name? Identity across hosts

| Situation | Matched by | Confidence |
|---|---|---|
| Real hardware serial (`60A44C413D5FF380E95A0B7D`) | VID + PID + serial | **high** |
| Serial many sticks share (`0123456789ABCDEF`, one repeated character, very short, mostly zeros) | never alone: also needs a shared volume serial | medium |
| **Windows-generated serial** (`7&2A1B3C4D&0`, the device reported none; it exists on one host only) | shared **volume serial (VSN)** | medium |
| ... with no shared VSN | same **volume name + capacity + VID/PID** | low |

Two different real serials are **never** merged, even if a cloned image gave them the same VSN. Every finding states
how its stick was matched (`serial`, `vsn`, `name+capacity`) and with what confidence. Only storage devices are linked
by default (`--all-classes` adds hubs and HID devices), otherwise every virtual hub would be "on every host".

## Fleet hunts

| # | Finding | Fires when | Severity |
|---|---|---|---|
| G1 | `device_on_many_hosts` | one stick on `--min-hosts` (default 3) or more hosts | medium |
| G2 | `device_shared_by_users` | one stick used by `--min-users` (default 2) or more accounts | medium |
| G3 | `exfil_device_spread` | a stick with a **high-risk session** (module #2) on one host was also on other hosts | **high** |
| G4 | `wiped_here_seen_there` | a stick **wiped** on one host (module #3) is still recorded on another | **high** |
| G5 | `new_to_fleet` | first seen anywhere within `--new-days` (default 30), on one host only; needs at least that much fleet history | low |
| G6 | `serial_collision` | one serial on different VID/PIDs, or a weak serial shared by sticks with no volume in common | info |

Users are compared as accounts: `NW\J.Doe`, `j.doe` and `j.doe (MountPoints2)` are one user; machine accounts (`HOST$`)
and SYSTEM are ignored. A local profile and a Microsoft account of the same person are two accounts.

## Use cases and sample output

A fictional four-host fleet (Finance, HR, Engineering, Ops). Each block is real `usbhawk graph` output; the hosts, users,
serials and files are invented. The same fleet is a test (`test_fleet_sample_fleet.py`), so this section cannot go
stale.

**G4: a stick was wiped on one host, but another host still remembers it**
```
high    wiped_here_seen_there     SanDisk Ultra (4C530001230601105525) was wiped from the registry on NW-OPS-WS019
                                  (usbhawk tamper), but NW-HR-WS007 still holds its history. Collect that host: it
                                  shows what the wipe tried to hide.
```

**G3: the stick behind a high-risk session went elsewhere**
```
high    exfil_device_spread       Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D) had a high-risk session
                                  (score 85) on NW-FIN-WS042 and was also connected to NW-ENG-LT113, NW-HR-WS007;
                                  matched across hosts by serial (confidence high). Follow the stick: whatever was
                                  copied may be on those hosts too, or came from them.
```

**G1: one stick on many hosts**
```
medium  device_on_many_hosts      Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D) was connected to 3 hosts
                                  (NW-ENG-LT113, NW-FIN-WS042, NW-HR-WS007); matched across hosts by serial
                                  (confidence high).
```

**G2: one stick, several users**
```
medium  device_shared_by_users    Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D) was used by 3 different users
                                  (a.smith, j.doe, k.lee); matched across hosts by serial (confidence high).
```

**G5: a stick nobody in the fleet has seen before**
```
low     new_to_fleet              SanDisk Ultra (4C530001230601105525) was first seen anywhere in the fleet on
                                  2026-10-28T21:14:00Z, on NW-HR-WS007 only (new within 30 days; fleet history from
                                  2026-07-02T21:14:00Z).
```

**G6: a serial that cannot be trusted**
```
info    serial_collision          VID_FFFF&PID_5678\0123456789ABCDEF is a weak serial shared by 2 sticks that have no
                                  volume evidence in common (hosts NW-FIN-WS042, NW-OPS-WS019): not used to link them.
```

**Pivot: where has the Kingston been?** (`usbhawk graph --runs out device 60A44C41`)
```
Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D)  VID_0951&PID_1666\60A44C413D5FF380E95A0B7D | 3 host(s) | match: serial (high)
Host           First / Last Seen (UTC)  Sessions  Users    Top score  Writes  Volumes / VSN
NW-FIN-WS042   2026-10-30 21:14  1         j.doe    85 high    61      Q3-BOARD 8E2C41D7
NW-HR-WS007    2026-10-31 21:14  1         a.smith  0 info     0       8E2C41D7
NW-ENG-LT113   2026-11-02 21:14  1         k.lee    0 info     0       -
```

## Output

| File | Contents |
|---|---|
| `findings.jsonl` | One ECS-style document per finding (`event.dataset: usbhawk.graph`, severity, risk score, `usbhawk.why`, evidence with hosts, users, confidence and match basis) |
| `graph.json` | `nodes` (device, host, user, volume) and `edges` (CONNECTED_TO, USED, HAS_VOLUME) with their attributes |
| `graph.graphml` | The same graph for Gephi or yEd |
| `graph.cypher` | Neo4j import script (`MERGE`, safe to re-run) for BloodHound-style queries, e.g. `MATCH (d:Device)-[:CONNECTED_TO]->(h:Host) WITH d, count(h) AS n WHERE n > 2 RETURN d.label, n` |

## Lab validation (2026-11-17)

Two real machines: the analysis PC and the module #3/#4 lab VM. A 1 TB UASP USB disk had been used on both. Each was
collected with `scripts\collect_local.ps1` (read-only; the PC collection stayed outside the repository), processed with
`usbhawk sessions --out`, and linked with `usbhawk graph`.

| Check | Result |
|---|---|
| Same disk on two real hosts | linked by its **real serial, confidence high**; `device_on_many_hosts` at `--min-hosts 2` |
| Pivot | both hosts, the PC's history going back seven months, the VM's two days, the same volume name on both |
| Accounts | three accounts of one person (local profile, Microsoft account, VM account) reported as three users: correct at the account level |
| False positives found and fixed | users tagged `name (MountPoints2)` by module #2 were counted as extra users (6 false `device_shared_by_users`); now normalised, with a regression test |
| Collector bug found and fixed | on a host without Sysmon, `collect_local.ps1` stopped at the Sysmon check (PowerShell 5.1 turns `wevtutil`'s "log not found" into a terminating error) and skipped `setupapi.dev.log`; now probed with `Get-WinEvent -ListLog` |
| G4 | correctly quiet: the disk was never wiped (USBOblivion skips UASP disks) and the sticks it did wipe never touched the PC |
| Public samples as a 2-host fleet | no cross-host links (they share no stick): the negative control |

## Limits

* The graph is only as complete as the per-host collections; a stick used on an uncollected host is invisible.
* Windows-generated serials and fake serials depend on volume evidence; a reformatted stick with a new VSN and a new
  name cannot be linked.
* Users are accounts, not people: one person with several accounts counts several times.
* `new_to_fleet` needs at least `--new-days` of fleet history and is relative to the newest session in the data.
* Neo4j / GraphML exports are tested for structure and escaping; loading into a live Neo4j was not part of the lab.
