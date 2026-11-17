"""Module #1: fleet device graph. "Where else has this stick been, and who else used it?"

Reads the per-host outputs of the other modules (devices.jsonl and sessions.jsonl from `usbhawk sessions --out`,
tamper.jsonl from `usbhawk tamper --out`) for many hosts and links them into one graph:

    (Device)-[CONNECTED_TO]->(Host)    (User)-[USED]->(Device)    (Device)-[HAS_VOLUME]->(Volume VSN)

Identity is the hard part, and every finding says how a stick was matched:
  * serial         a real hardware serial (VID/PID + iSerialNumber) is the same stick everywhere   -> high
  * vsn            Windows-generated serials (7&...&0) exist on one host only and cheap sticks share
                   fake serials (0123456789ABCDEF): those join only on a shared volume serial        -> medium
  * name+capacity  ... or on the same volume name, capacity and VID/PID                             -> low
Two different real serials are never merged, even if a cloned image gave them the same VSN.
"""

from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any
from xml.sax.saxutils import escape

from .util import iso, to_utc

STORAGE = {"usbstor", "uasp", "mtp"}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
RISK_SCORE = {"high": 75, "medium": 50, "low": 25, "info": 0}
CONFIDENCE = {"serial": "high", "vsn": "medium", "name+capacity": "low"}
NOT_A_USER = re.compile(r"^(system|local service|network service|anonymous logon|-|unknown|none)$|\$$", re.I)
_SEQUENCES = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", "1234567890ABCDEF")


# --------------------------------------------------------------------------- helpers
def norm_user(name) -> str | None:
    """'NW\\J.Doe' / 'j.doe (MountPoints2)' -> 'j.doe'; machine accounts and service identities -> None."""
    if not name:
        return None
    plain = re.sub(r"\s*\([^)]*\)\s*$", "", str(name).strip())    # module #2 tags e.g. " (MountPoints2)"
    short = plain.split("\\")[-1].split("@")[0].strip().lower()
    return None if not short or NOT_A_USER.search(short) else short


def norm_serial(serial) -> str:
    s = str(serial or "").upper()
    return re.sub(r"&\d+$", "", s)                       # USBSTOR instance LUN suffix


def is_weak_serial(serial) -> bool:
    """Serials that many different sticks share: too short, one repeated character, a counting sequence, mostly 0."""
    s = re.sub(r"[^0-9A-Z]", "", norm_serial(serial))
    if len(s) < 8 or len(set(s)) <= 2:
        return True
    if any(s in seq for seq in _SEQUENCES):
        return True
    return s.count("0") >= 0.6 * len(s)


def _read_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def find_runs(paths: list[str]) -> list[str]:
    """Host output folders (with devices.jsonl / sessions.jsonl): given directly, as wildcards, or one level down."""
    def is_run(d):
        return any(os.path.exists(os.path.join(d, f)) for f in ("devices.jsonl", "sessions.jsonl"))
    found = []
    for p in paths:
        for q in (glob.glob(p) if any(ch in p for ch in "*?[") else [p]):
            if not os.path.isdir(q):
                continue
            if is_run(q):
                found.append(os.path.abspath(q))
            else:
                found += [os.path.abspath(os.path.join(q, s)) for s in sorted(os.listdir(q))
                          if os.path.isdir(os.path.join(q, s)) and is_run(os.path.join(q, s))]
    return sorted(set(found))


# --------------------------------------------------------------------------- model
@dataclass
class Record:
    """One device as one host saw it."""
    host: str
    key: str
    vid: str
    pid: str
    serial: str
    generated: bool
    device_class: str = "other"
    vendor: str | None = None
    product: str | None = None
    capacity: int | None = None
    vsns: set[str] = field(default_factory=set)
    volume_names: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    sessions: list[dict] = field(default_factory=list)

    @property
    def weak(self) -> bool:
        return is_weak_serial(self.serial)

    @property
    def strong(self) -> bool:
        return not self.generated and not self.weak

    @property
    def storage(self) -> bool:
        return (self.device_class in STORAGE or bool(self.vsns or self.volume_names or self.sessions)
                or any(s.startswith("evtx:Partition") for s in self.sources))


@dataclass
class Cluster:
    """One physical stick across the fleet (as far as the evidence allows)."""
    records: list[Record]
    basis: set[str]
    confidence: str
    wiped_on: set[str] = field(default_factory=set)

    @property
    def hosts(self) -> set[str]:
        return {r.host for r in self.records}

    @property
    def id(self) -> str:
        keys = sorted({r.key for r in self.records}, key=lambda k: (not any(r.strong and r.key == k
                                                                            for r in self.records), k))
        return keys[0] if len(keys) == 1 else f"{keys[0]}+{len(keys) - 1}"

    @property
    def sessions(self) -> list[dict]:
        return sorted((s for r in self.records for s in r.sessions), key=lambda s: s["_start"] or s["_ts"] or 0)

    @property
    def users(self) -> set[str]:
        out = {u for r in self.records for u in r.users}
        out |= {u for s in self.sessions for u in s["_users"]}
        return {u for u in out if u}

    @property
    def vsns(self) -> set[str]:
        return {v for r in self.records for v in r.vsns}

    @property
    def first_seen(self):
        times = [s["_start"] for s in self.sessions if s["_start"]]
        return min(times) if times else None

    @property
    def last_seen(self):
        times = [s["_end"] or s["_start"] for s in self.sessions if s["_end"] or s["_start"]]
        return max(times) if times else None

    @property
    def label(self) -> str:
        r = next((x for x in self.records if x.strong), self.records[0])
        name = " ".join(x for x in (r.vendor, r.product) if x) or f"VID_{r.vid}&PID_{r.pid}"
        serial = r.serial if r.strong else ("weak serial " + r.serial if r.weak else "Windows-generated serial")
        return f"{name} ({serial})"

    def per_host(self) -> list[dict]:
        rows = []
        for host in self.hosts:
            ss = [s for s in self.sessions if s["_host"] == host]
            starts = [s["_start"] for s in ss if s["_start"]]
            ends = [s["_end"] or s["_start"] for s in ss if s["_end"] or s["_start"]]
            recs = [r for r in self.records if r.host == host]
            users = {u for s in ss for u in s["_users"]} | {u for r in recs for u in r.users}
            top = max(ss, key=lambda s: s["_score"], default=None)
            rows.append({"host": host, "first_seen": min(starts) if starts else None,
                         "last_seen": max(ends) if ends else None, "sessions": len(ss),
                         "users": sorted(u for u in users if u), "max_score": top["_score"] if top else 0,
                         "max_severity": top["_severity"] if top else None,
                         "writes": sum(s["_writes"] for s in ss),
                         "sample": [p for s in ss for p in s["_sample"]][:5],
                         "volume_names": sorted({v for r in recs for v in r.volume_names}),
                         "vsns": sorted({v for r in recs for v in r.vsns}),
                         "wiped_here": host in self.wiped_on})
        return sorted(rows, key=lambda r: (r["first_seen"] is None, r["first_seen"] or 0, r["host"]))


@dataclass
class GraphFinding:
    rule: str
    severity: str
    why: str
    evidence: dict[str, Any]
    ts: Any = None

    def to_dict(self) -> dict:
        def j(v):
            if isinstance(v, dict):
                return {k: j(x) for k, x in v.items()}
            if isinstance(v, (list, tuple, set)):
                return [j(x) for x in (sorted(v) if isinstance(v, set) else v)]
            return iso(v) if hasattr(v, "isoformat") else v
        return {"@timestamp": iso(self.ts),
                "event": {"kind": "alert" if self.severity in ("high", "medium") else "event",
                          "category": ["host"], "type": ["info"], "dataset": "usbhawk.graph",
                          "severity_label": self.severity, "risk_score": RISK_SCORE[self.severity]},
                "host": {"name": None, "names": self.evidence.get("hosts", [])},
                "usbhawk": {"rule": self.rule, "severity": self.severity, "why": self.why, "evidence": j(self.evidence)}}


# --------------------------------------------------------------------------- loading
def _session(doc: dict, host: str) -> dict:
    ev, ut = doc.get("event", {}), doc.get("usbhawk", {})
    fa = ut.get("file_activity", {})
    return {"_host": host, "_key": doc.get("usb", {}).get("device", {}).get("key"),
            "_start": to_utc(ev.get("start")), "_end": to_utc(ev.get("end")), "_ts": to_utc(doc.get("@timestamp")),
            "_users": {norm_user(u) for u in (doc.get("user", {}).get("names") or [])} - {None},
            "_score": int(ut.get("score") or 0), "_severity": ut.get("severity") or "info",
            "_writes": int(fa.get("writes") or 0), "_sample": list(fa.get("sample") or []),
            "session_id": ut.get("session_id")}


def _record_from(d: dict, host: str) -> Record:
    return Record(host=host, key=d["key"], vid=str(d.get("vid") or ""), pid=str(d.get("pid") or ""),
                  serial=str(d.get("serial") or ""), generated=bool(d.get("windows_generated_serial")),
                  device_class=d.get("device_class") or d.get("class") or "other", vendor=d.get("vendor"),
                  product=d.get("product") or d.get("friendly_name"), capacity=d.get("capacity_bytes"),
                  vsns={str(v).upper() for v in (d.get("vsns") or d.get("vsns_all_time") or [])},
                  volume_names={str(v) for v in d.get("volume_names") or []},
                  users={norm_user(u) for u in d.get("users") or []} - {None},
                  sources=set(d.get("sources") or []))


class _UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, i):
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i, j) -> bool:
        a, b = self.find(i), self.find(j)
        if a == b:
            return False
        self.parent[b] = a
        return True


class Fleet:
    def __init__(self, records: list[Record], tamper: list[dict], warnings: list[str]):
        self.records, self.warnings = records, warnings
        self.clusters = self._resolve(records)
        self._apply_tamper(tamper)

    # ---- summary
    @property
    def hosts(self) -> list[str]:
        return sorted({r.host for r in self.records})

    @property
    def session_count(self) -> int:
        return sum(len(r.sessions) for r in self.records)

    @property
    def users(self) -> set[str]:
        return {u for c in self.clusters for u in c.users}

    # ---- identity
    @staticmethod
    def _resolve(records: list[Record]) -> list[Cluster]:
        uf = _UnionFind(len(records))
        merged_by: dict[int, set[str]] = {}
        stage_of_join: list[tuple[int, int, str]] = []

        def join(i, j, basis):
            if uf.union(i, j):
                stage_of_join.append((i, j, basis))

        by_key: dict[str, list[int]] = {}
        for i, r in enumerate(records):
            if r.strong:
                by_key.setdefault(r.key.upper(), []).append(i)
        for ids in by_key.values():
            for j in ids[1:]:
                join(ids[0], j, "serial")
        by_vsn: dict[str, list[int]] = {}
        for i, r in enumerate(records):
            for v in r.vsns:
                by_vsn.setdefault(v, []).append(i)
        for ids in by_vsn.values():
            for a in range(len(ids)):
                for b in range(a + 1, len(ids)):
                    ra, rb = records[ids[a]], records[ids[b]]
                    if ra.strong and rb.strong and ra.key.upper() != rb.key.upper():
                        continue                 # two proven-different sticks (e.g. cloned image) stay apart
                    join(ids[a], ids[b], "vsn")
        by_name: dict[tuple, list[int]] = {}
        for i, r in enumerate(records):
            if not r.strong and r.capacity:
                for name in r.volume_names:
                    by_name.setdefault((r.vid.upper(), r.pid.upper(), name.lower(), r.capacity), []).append(i)
        for ids in by_name.values():
            for j in ids[1:]:
                join(ids[0], j, "name+capacity")

        groups: dict[int, list[int]] = {}
        for i in range(len(records)):
            groups.setdefault(uf.find(i), []).append(i)
        for i, j, basis in stage_of_join:
            merged_by.setdefault(uf.find(i), set()).add(basis)
        clusters = []
        for root, ids in groups.items():
            basis = merged_by.get(root, set())
            if len({records[i].host for i in ids}) < 2:
                conf = "single host"
            else:
                conf = min((CONFIDENCE[b] for b in basis), key=["low", "medium", "high"].index)
            clusters.append(Cluster([records[i] for i in ids], basis or {"single record"}, conf))
        return sorted(clusters, key=lambda c: c.id)

    def _apply_tamper(self, tamper: list[dict]) -> None:
        for t in tamper:
            u = t.get("usbhawk", {})
            ev = u.get("evidence", {})
            if u.get("rule") != "orphaned_device_reference" or ev.get("id_type") != "usb_serial":
                continue
            serial, key = norm_serial(ev.get("id_value")), str(ev.get("device_key") or "").upper()
            host = t.get("host", {}).get("name")
            for c in self.clusters:
                if any((r.strong and norm_serial(r.serial) == serial) or (key and r.key.upper() == key)
                       for r in c.records):
                    c.wiped_on.add(host)

    # ---- hunts
    def hunt(self, min_hosts: int = 3, min_users: int = 2, new_days: int = 30) -> list[GraphFinding]:
        out: list[GraphFinding] = []
        times = [s["_start"] for c in self.clusters for s in c.sessions if s["_start"]]
        now, oldest = (max(times), min(times)) if times else (None, None)
        for c in self.clusters:
            base = {"device": c.id, "label": c.label, "hosts": sorted(c.hosts), "users": sorted(c.users),
                    "confidence": c.confidence, "basis": sorted(c.basis), "first_seen": c.first_seen,
                    "last_seen": c.last_seen}
            how = (f"matched across hosts by {', '.join(sorted(c.basis))} (confidence {c.confidence})"
                   if len(c.hosts) > 1 else "seen on one host")
            high = sorted({s["_host"] for s in c.sessions if s["_severity"] == "high"})
            if high and c.hosts - set(high):
                top = max((s for s in c.sessions if s["_severity"] == "high"), key=lambda s: s["_score"])
                others = sorted(c.hosts - set(high))
                out.append(GraphFinding(
                    "exfil_device_spread", "high",
                    f"{c.label} had a high-risk session (score {top['_score']}) on {', '.join(high)} and was also "
                    f"connected to {', '.join(others)}; {how}. Follow the stick: whatever was copied may be on "
                    f"those hosts too, or came from them.",
                    {**base, "high_risk_on": high, "also_on": others, "top_score": top["_score"]},
                    top["_start"] or top["_ts"]))
            history = sorted(c.hosts - c.wiped_on)
            if c.wiped_on and history:
                holds = f"{history[0]} still holds" if len(history) == 1 else f"{', '.join(history)} still hold"
                matched = f" ({how})" if len(c.hosts) > 1 else ""
                out.append(GraphFinding(
                    "wiped_here_seen_there", "high",
                    f"{c.label} was wiped from the registry on {', '.join(sorted(c.wiped_on))} (usbhawk tamper), but "
                    f"{holds} its history{matched}. Collect {'that host' if len(history) == 1 else 'those hosts'}: "
                    f"{'it shows' if len(history) == 1 else 'they show'} what the wipe tried to hide.",
                    {**base, "wiped_on": sorted(c.wiped_on), "history_on": history}, c.last_seen))
            if len(c.hosts) >= min_hosts:
                out.append(GraphFinding(
                    "device_on_many_hosts", "medium",
                    f"{c.label} was connected to {len(c.hosts)} hosts ({', '.join(sorted(c.hosts))}); {how}. One "
                    f"stick moving between machines is how data walks out and how malware walks in.", base,
                    c.first_seen))
            if len(c.users) >= min_users:
                out.append(GraphFinding(
                    "device_shared_by_users", "medium",
                    f"{c.label} was used by {len(c.users)} different users ({', '.join(sorted(c.users))}); {how}. "
                    f"Shared sticks break attribution and policy; check whether the users work together.", base,
                    c.first_seen))
            if (now and c.first_seen and len(c.hosts) == 1 and oldest <= now - timedelta(days=new_days)
                    and c.first_seen >= now - timedelta(days=new_days)):
                out.append(GraphFinding(
                    "new_to_fleet", "low",
                    f"{c.label} was first seen anywhere in the fleet on {iso(c.first_seen)}, on "
                    f"{next(iter(c.hosts))} only (new within {new_days} days; fleet history from {iso(oldest)}).",
                    base, c.first_seen))
        out += self._collisions()
        return sorted(out, key=lambda f: (SEVERITY_ORDER[f.severity], f.ts.timestamp() if f.ts else float("inf"),
                                          f.rule))

    def _collisions(self) -> list[GraphFinding]:
        out = []
        by_serial: dict[str, set[tuple[str, str]]] = {}
        weak_clusters: dict[str, list[Cluster]] = {}
        for c in self.clusters:
            for r in c.records:
                if r.generated:
                    continue
                s = norm_serial(r.serial)
                if r.weak:
                    lst = weak_clusters.setdefault(f"VID_{r.vid}&PID_{r.pid}\\{s}", [])
                    if c not in lst:
                        lst.append(c)
                else:
                    by_serial.setdefault(s, set()).add((r.vid.upper(), r.pid.upper()))
        for s, vp in sorted(by_serial.items()):
            if len(vp) > 1:
                out.append(GraphFinding(
                    "serial_collision", "info",
                    f"Serial {s} appears with {len(vp)} different VID/PID pairs "
                    f"({', '.join(f'{v}:{p}' for v, p in sorted(vp))}): different products, so treated as different "
                    f"sticks.", {"serial": s, "vid_pid": sorted(f"{v}:{p}" for v, p in vp), "reason": "vid_pid",
                                 "confidence": "n/a"}))
        for key, cl in sorted(weak_clusters.items()):
            if len(cl) > 1:
                out.append(GraphFinding(
                    "serial_collision", "info",
                    f"{key} is a weak serial shared by {len(cl)} sticks that have no volume evidence in common "
                    f"(hosts {', '.join(sorted({h for c in cl for h in c.hosts}))}): not used to link them.",
                    {"device_key": key, "sticks": len(cl), "reason": "weak_serial",
                     "hosts": sorted({h for c in cl for h in c.hosts}), "confidence": "n/a"}))
        return out

    # ---- pivots
    def find_device(self, query: str) -> list[Cluster]:
        q = query.strip().lower()
        return [c for c in self.clusters
                if any(q in r.key.lower() or q in r.serial.lower() for r in c.records)
                or q.upper() in c.vsns or q in c.label.lower()]

    def find_user(self, name: str) -> list[Cluster]:
        u = norm_user(name)
        return [c for c in self.clusters if u and u in c.users]

    # ---- exports
    def graph(self) -> dict:
        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        for h in self.hosts:
            nodes[f"host:{h}"] = {"id": f"host:{h}", "type": "host", "label": h}
        for c in self.clusters:
            did = f"device:{c.id}"
            nodes[did] = {"id": did, "type": "device", "label": c.label, "confidence": c.confidence,
                          "basis": ",".join(sorted(c.basis)), "hosts": len(c.hosts),
                          "volumes": ",".join(sorted({v for r in c.records for v in r.volume_names})),
                          "wiped_on": ",".join(sorted(c.wiped_on))}
            for row in c.per_host():
                edges.append({"source": did, "target": f"host:{row['host']}", "type": "CONNECTED_TO",
                              "sessions": row["sessions"], "first_seen": iso(row["first_seen"]),
                              "last_seen": iso(row["last_seen"]), "max_score": row["max_score"],
                              "writes": row["writes"]})
            for u in sorted(c.users):
                nodes.setdefault(f"user:{u}", {"id": f"user:{u}", "type": "user", "label": u})
                on = sorted({s["_host"] for s in c.sessions if u in s["_users"]}
                            | {r.host for r in c.records if u in r.users})
                edges.append({"source": f"user:{u}", "target": did, "type": "USED", "hosts": ",".join(on)})
            for v in sorted(c.vsns):
                nodes.setdefault(f"volume:{v}", {"id": f"volume:{v}", "type": "volume", "label": v})
                edges.append({"source": did, "target": f"volume:{v}", "type": "HAS_VOLUME"})
        return {"nodes": list(nodes.values()), "edges": edges}

    def graphml(self) -> str:
        g = self.graph()
        nkeys = sorted({k for n in g["nodes"] for k in n if k != "id"})
        ekeys = sorted({k for e in g["edges"] for k in e if k not in ("source", "target")})
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">']
        lines += [f'  <key id="n_{k}" for="node" attr.name="{k}" attr.type="string"/>' for k in nkeys]
        lines += [f'  <key id="e_{k}" for="edge" attr.name="{k}" attr.type="string"/>' for k in ekeys]
        lines.append('  <graph id="usbhawk_fleet" edgedefault="directed">')
        for n in g["nodes"]:
            data = "".join(f'<data key="n_{k}">{escape(str(v))}</data>' for k, v in n.items()
                           if k != "id" and v not in (None, ""))
            lines.append(f'    <node id="{escape(n["id"], {chr(34): "&quot;"})}">{data}</node>')
        for i, e in enumerate(g["edges"]):
            data = "".join(f'<data key="e_{k}">{escape(str(v))}</data>' for k, v in e.items()
                           if k not in ("source", "target") and v not in (None, ""))
            lines.append(f'    <edge id="e{i}" source="{escape(e["source"], {chr(34): "&quot;"})}" '
                         f'target="{escape(e["target"], {chr(34): "&quot;"})}">{data}</edge>')
        lines += ["  </graph>", "</graphml>"]
        return "\n".join(lines) + "\n"

    def cypher(self) -> str:
        """Neo4j import script (MERGE, so it can be re-run): BloodHound-style queries on USB devices."""
        def q(v) -> str:
            return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"
        g = self.graph()
        label = {"device": "Device", "host": "Host", "user": "User", "volume": "Volume"}
        out = ["// usbhawk fleet graph - generated by usbhawk graph; load with cypher-shell or the Neo4j browser"]
        for n in g["nodes"]:
            props = ", ".join(f"n.{k} = {q(v)}" for k, v in n.items() if k not in ("id", "type") and v not in (None, ""))
            out.append(f"MERGE (n:{label[n['type']]} {{id: {q(n['id'])}}})" + (f" SET {props}" if props else "") + ";")
        for e in g["edges"]:
            props = ", ".join(f"r.{k} = {v if isinstance(v, int) else q(v)}" for k, v in e.items()
                              if k not in ("source", "target", "type") and v not in (None, ""))
            out.append(f"MATCH (a {{id: {q(e['source'])}}}), (b {{id: {q(e['target'])}}}) "
                       f"MERGE (a)-[r:{e['type']}]->(b)" + (f" SET {props}" if props else "") + ";")
        return "\n".join(out) + "\n"


def build_fleet(paths: list[str], all_classes: bool = False) -> Fleet:
    """Load every host output folder under `paths` and resolve devices across hosts."""
    records: list[Record] = []
    tamper: list[dict] = []
    warnings: list[str] = []
    for run in find_runs(paths):
        dev_path, ses_path, tam_path = (os.path.join(run, f) for f in ("devices.jsonl", "sessions.jsonl",
                                                                         "tamper.jsonl"))
        devices = _read_jsonl(dev_path) if os.path.exists(dev_path) else []
        sessions = _read_jsonl(ses_path) if os.path.exists(ses_path) else []
        if not os.path.exists(ses_path):
            warnings.append(f"{run}: no sessions.jsonl (devices only; run `usbhawk sessions --out` for timelines)")
        host = (next((d.get("host") for d in devices if d.get("host")), None)
                or next((s.get("host", {}).get("name") for s in sessions if s.get("host", {}).get("name")), None)
                or os.path.basename(run))
        by_key = {d["key"]: _record_from(d, host) for d in devices if d.get("key")}
        for s in sessions:
            key = s.get("usb", {}).get("device", {}).get("key")
            if not key:
                continue
            if key not in by_key:
                by_key[key] = _record_from(s.get("usb", {}).get("device", {}), host)
            by_key[key].sessions.append(_session(s, host))
        records += [r for r in by_key.values() if all_classes or r.storage]
        if os.path.exists(tam_path):
            tamper += _read_jsonl(tam_path)
    return Fleet(records, tamper, warnings)
