# `usbhawk graph`: where else has this stick been, and who else used it?

Module #1. One host tells you a stick was plugged in. A fleet tells you where it went next. `usbhawk graph` reads the
per-host output folders of `usbhawk sessions --out` and `usbhawk tamper --out` (never raw evidence), links the same
stick across hosts, and runs six fleet hunts on the result.

| | |
|---|---|
| **Input** | A folder with one sub-folder per host, each holding `devices.jsonl`, `sessions.jsonl` and optionally `tamper.jsonl` |
| **Output** | Findings table, device or user pivots; with `--out`: `findings.jsonl` (ECS), `graph.json`, `graph.graphml` (Gephi, yEd), `graph.cypher` (Neo4j) |
| **In this folder** | `fleet/`: four fictional hosts, written by the real module #2 and #3 writers |
| **Full guide** | [docs/hunt-fleet-device-graph.md](../../docs/hunt-fleet-device-graph.md) |

```
fleet/
  NW-FIN-WS042/    finance PC: j.doe copies 61 files to a Kingston stick (session score 85, high)
  NW-HR-WS007/     HR PC: a.smith uses the same Kingston the next day, and a SanDisk
  NW-ENG-LT113/    engineering laptop: k.lee has the Kingston, plus a brand-new stick
  NW-OPS-WS019/    ops PC: the SanDisk's registry traces were wiped here (tamper.jsonl)
```

## 1. Run the fleet hunts

```powershell
usbhawk graph --runs examples\graph\fleet
usbhawk graph --runs examples\graph\fleet --out out\fleet
```

What you should see (all six hunts fire; the Description column shortened):

```
Fleet 4 hosts, 6 USB devices (1 on more than one host), 4 users, 8 sessions
| Severity | Finding                | Device                                               | Hosts | Description
| high     | wiped_here_seen_there  | SanDisk Ultra (4C530001230601105525)                 | 1     | wiped from the registry on NW-OPS-WS019, but NW-HR-WS007 still holds its history
| high     | exfil_device_spread    | Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D) | 3     | high-risk session (score 85) on NW-FIN-WS042, also connected to NW-ENG-LT113, NW-HR-WS007
| medium   | device_on_many_hosts   | Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D) | 3     | connected to 3 hosts; matched across hosts by serial (confidence high)
| medium   | device_shared_by_users | Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D) | 3     | used by 3 different users (a.smith, j.doe, k.lee)
| low      | new_to_fleet           | SanDisk Ultra (4C530001230601105525)                 | 1     | first seen anywhere in the fleet on 2026-10-28, on NW-HR-WS007 only
| low      | new_to_fleet           | Generic USB Disk (weak serial 0123456789ABCDEF)      | 1     | first seen ... on NW-FIN-WS042 only
| low      | new_to_fleet           | Generic USB Disk (weak serial 0123456789ABCDEF)      | 1     | first seen ... on NW-OPS-WS019 only
| low      | new_to_fleet           | Kingston DataTraveler G4 (001CC0EC3477F9B0C7C41D3D)  | 1     | first seen ... on NW-ENG-LT113 only
| info     | serial_collision       | VID_FFFF&PID_5678\0123456789ABCDEF                   | 2     | weak serial shared by 2 sticks with no volume evidence in common: not used to link them
```

### How to read it

| Finding | The question it answers |
|---|---|
| `exfil_device_spread` | A stick with a high-risk session on one host also visited others. Follow it: what was copied may be there too, or came from there |
| `wiped_here_seen_there` | Someone wiped a stick's traces on one host, but another host still has its history. Collect that host: it shows what the wipe tried to hide |
| `device_on_many_hosts` | One stick moving between machines: how data walks out and how malware walks in |
| `device_shared_by_users` | Shared sticks break attribution; check whether the users work together |
| `new_to_fleet` | First time this stick has been seen anywhere in the fleet (in the last 30 days) |
| `serial_collision` | Two different cheap sticks report the same factory serial. USBHawk **refuses** to merge them: weak serials are never trusted alone |

How sticks are linked, strongest first: the **real serial** (high confidence), a shared **volume serial number**
(medium), then **volume name and capacity** (low). Two different real serials are never merged.

## 2. Pivot on a stick or a person

```powershell
usbhawk graph --runs examples\graph\fleet device 60A44C41
usbhawk graph --runs examples\graph\fleet user a.smith
```

`device` takes any part of a serial or device name, or a full volume serial number. The device pivot shows where the stick went, who used it,
and where it was written to:

```
Kingston DataTraveler 3.0 (60A44C413D5FF380E95A0B7D)  VID_0951&PID_1666\60A44C413D5FF380E95A0B7D | 3 host(s) | match: serial (high)
| Host         | First / Last Seen (UTC) | Sessions | Users   | Top score | Writes | Volumes / VSN     |
| NW-FIN-WS042 | 2026-10-30 21:14 | 1        | j.doe   | 85 high   | 61     | Q3-BOARD 8E2C41D7 |
| NW-HR-WS007  | 2026-10-31 21:14 | 1        | a.smith | 0 info    | 0      | 8E2C41D7          |
| NW-ENG-LT113 | 2026-11-02 21:14 | 1        | k.lee   | 0 info    | 0      | -                 |
```

The user pivot lists every stick `a.smith` touched: the Kingston from the finance PC, and the SanDisk. Under the
SanDisk's table it adds the host where the stick's traces were wiped, which has no row of its own because the wipe
removed them:

```
SanDisk Ultra (4C530001230601105525)  VID_0781&PID_5581\4C530001230601105525 | 1 host(s) | match: single record (single host)
| Host        | First / Last Seen (UTC) | Sessions | Users   | Top score | Writes | Volumes / VSN |
| NW-HR-WS007 | 2026-10-28 21:14        | 1        | a.smith | 0 info    | 0      | -             |
Also wiped from the registry on NW-OPS-WS019 (usbhawk tamper): the history above is what the wipe there tried to hide.
```

Two sticks that report the same weak serial (the `serial_collision` finding) stay separate everywhere: in the
exports their IDs carry the host, e.g. `VID_FFFF&PID_5678\0123456789ABCDEF@NW-FIN-WS042`.

## 3. Take the graph elsewhere

`--out out\fleet` writes:

| File | Open it with |
|---|---|
| `findings.jsonl` | Your SIEM (ECS fields, `event.dataset: usbhawk.graph`) |
| `graph.json` | Any script: nodes are hosts, devices, users and volumes; edges are `CONNECTED_TO` (with sessions, scores and writes), `USED` and `HAS_VOLUME` |
| `graph.graphml` | Gephi or yEd, for a picture of the fleet |
| `graph.cypher` | Neo4j: `cypher-shell < graph.cypher`, then query the fleet with Cypher |

## 4. On your own fleet

Run modules #2 and #3 into one folder per host, then graph the parent folder:

```
usbhawk sessions --triage D:\cases\WS042 --out runs\WS042
usbhawk tamper   --triage D:\cases\WS042 --out runs\WS042
usbhawk sessions --triage D:\cases\WS007 --out runs\WS007
usbhawk tamper   --triage D:\cases\WS007 --out runs\WS007
usbhawk graph --runs runs --out fleet
```
