"""Replay real Windows event logs through the detection rules (`usbhawk detections run --evtx`).

Used to prove the rules on real telemetry in a lab: Sysmon (1 process, 11 file create, 12-14 registry),
Security (4688 process, 6416 device, 1102 cleared) and System (104 cleared) records are normalised to the
neutral schema the rules are written in, then every detection runs over the timeline:

  * single-event detections: every matching record is an alert;
  * thresholds: the same fixed buckets the generated ES|QL / KQL / Sigma correlations use;
  * first seen: replayed in time order - a value alerts at its first sighting in the logs, or when it comes
    back after more than the lookback. The logs' own span is the only history, and each alert says so.

Removable media: Sysmon file events carry no "removable" flag. By default drives D: to Z: count as removable (the
same heuristic as the Sigma / Elastic rules); pass the real USB letters with --removable-drives for a clean lab.
"""

from __future__ import annotations

import glob
import json
import os
from datetime import timedelta

from evtx import PyEvtxParser

from ..util import iso, to_utc
from .core import Rule, evaluate, evaluate_stream

SYSMON = "Microsoft-Windows-Sysmon/Operational"
REGISTRY_ACTIONS = {"deletekey": "delete", "deletevalue": "delete", "createkey": "create", "setvalue": "set",
                    "renamekey": "rename"}


# --------------------------------------------------------------------------- reading
def _text(v):
    if isinstance(v, dict):
        return v.get("#text")
    return v


def read_evtx(path: str):
    """Yield {channel, event_id, provider, computer, ts, data} for every record of one .evtx file."""
    for r in PyEvtxParser(path).records_json():
        try:
            evt = json.loads(r["data"])["Event"]
        except (ValueError, KeyError):
            continue
        system = evt.get("System", {})
        prov = system.get("Provider", {})
        tc = system.get("TimeCreated", {})
        data = evt.get("EventData") or evt.get("UserData") or {}
        if isinstance(data, dict) and len(data) == 1 and isinstance(next(iter(data.values())), dict):
            data = next(iter(data.values()))                 # UserData: {"LogFileCleared": {...}} -> inner
        try:
            eid = int(_text(system.get("EventID")))
        except (TypeError, ValueError):
            continue
        yield {"channel": system.get("Channel"), "event_id": eid,
               "provider": (prov.get("#attributes", {}) if isinstance(prov, dict) else {}).get("Name"),
               "computer": system.get("Computer"),
               "ts": to_utc((tc.get("#attributes", {}) if isinstance(tc, dict) else {}).get("SystemTime")
                            or r.get("timestamp")),
               "data": data if isinstance(data, dict) else {}}


def evtx_files(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            out += sorted(glob.glob(os.path.join(p, "**", "*.evtx"), recursive=True))
        else:
            out.append(p)
    return out


# --------------------------------------------------------------------------- normalising
def _base(path) -> str | None:
    s = str(path or "")
    return s.rsplit("\\", 1)[-1] or None


def _removable(path, removable_drives) -> bool:
    s = str(path or "")
    if len(s) < 3 or s[1] != ":":
        return False
    drive = s[:2].upper()
    if removable_drives is not None:
        return drive in {d.upper().rstrip("\\") for d in removable_drives}
    return drive[0] >= "D"                      # same heuristic as the generated Sigma / ES|QL rules


def _subject(d: dict) -> str | None:
    user, dom = d.get("SubjectUserName"), d.get("SubjectDomainName")
    return f"{dom}\\{user}" if user and dom else user or None


def normalize_record(rec: dict, removable_drives=None) -> list[dict]:
    """One EVTX record -> zero or more neutral events (each tagged with its _telemetry)."""
    ch, eid, d = rec.get("channel"), int(rec["event_id"]), rec.get("data") or {}
    common = {"timestamp": rec["ts"], "host": rec.get("computer"), "_source": f"{ch}:{eid}"}
    out = []
    if ch == SYSMON:
        if eid == 1:
            out.append({**common, "_telemetry": "process_creation", "image": d.get("Image"),
                        "process_name": _base(d.get("Image")), "command_line": d.get("CommandLine"),
                        "original_file_name": d.get("OriginalFileName"), "parent_image": d.get("ParentImage"),
                        "parent_name": _base(d.get("ParentImage")), "user": d.get("User")})
        elif eid == 11:
            path = d.get("TargetFilename")
            out.append({**common, "_telemetry": "file_event", "file_path": path, "file_name": _base(path),
                        "image": d.get("Image"), "process_name": _base(d.get("Image")), "user": d.get("User"),
                        "removable": _removable(path, removable_drives)})
        elif eid in (12, 13, 14):
            out.append({**common, "_telemetry": "registry_event", "registry_path": d.get("TargetObject"),
                        "image": d.get("Image"), "process_name": _base(d.get("Image")), "user": d.get("User"),
                        "action": REGISTRY_ACTIONS.get(str(d.get("EventType", "")).lower(), "other")})
        return out
    if ch in ("Security", "System"):
        out.append({**common, "_telemetry": "event_log", "channel": ch, "event_id": eid,
                    "provider": rec.get("provider"), "user": _subject(d),
                    "cleared_log": d.get("Channel") if eid == 104 else ("Security" if eid == 1102 else None)})
        if ch == "Security" and eid == 6416:
            out.append({**common, "_telemetry": "device_connect", "device_id": d.get("DeviceId"),
                        "device_class": d.get("ClassName"), "device_description": d.get("DeviceDescription"),
                        "user": _subject(d)})
        elif ch == "Security" and eid == 4688:
            image = d.get("NewProcessName")
            out.append({**common, "_telemetry": "process_creation", "image": image, "process_name": _base(image),
                        "command_line": d.get("CommandLine"), "parent_image": d.get("ParentProcessName"),
                        "parent_name": _base(d.get("ParentProcessName")), "user": _subject(d)})
    return out


def load_events_jsonl(paths: list[str]) -> list[dict]:
    """Neutral events, one JSON object per line: {"_telemetry": ..., "timestamp": ISO-8601, <neutral fields>}.

    The same schema the rules are written in, so demos and tests can replay a timeline without .evtx files.
    """
    from .core import TELEMETRY
    events = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                e = json.loads(line)
                if e.get("_telemetry") not in TELEMETRY:
                    raise ValueError(f"{path}:{n}: unknown _telemetry {e.get('_telemetry')!r} "
                                     f"(known: {', '.join(sorted(TELEMETRY))})")
                e["timestamp"] = to_utc(e.get("timestamp"))
                events.append(e)
    return sorted(events, key=lambda e: e["timestamp"])


def load_events(paths: list[str], removable_drives=None) -> list[dict]:
    events = []
    for f in evtx_files(paths):
        for rec in read_evtx(f):
            events += normalize_record(rec, removable_drives)
    return sorted(events, key=lambda e: e["timestamp"])


# --------------------------------------------------------------------------- replay
_SHOW = ("process_name", "command_line", "file_path", "registry_path", "device_id", "device_description",
         "channel", "event_id", "provider", "cleared_log", "user")


def _summary(e: dict) -> str:
    return "; ".join(f"{k}={e[k]}" for k in _SHOW if e.get(k) not in (None, ""))


def _alert(rule: Rule, det: dict, ts, why: str, e: dict | None = None, **evidence) -> dict:
    return {"timestamp": ts, "hypothesis": rule.hypothesis, "rule": rule.name, "detection": det["name"],
            "title": det.get("title") and f"{rule.title} ({det['title']})" or rule.title,
            "level": rule.level_of(det["name"]), "host": (e or {}).get("host"), "user": (e or {}).get("user"),
            "why": why, "evidence": evidence}


def run(rules: list[Rule], events: list[dict]) -> list[dict]:
    """Every alert the rules raise on this timeline, oldest first."""
    by_tel: dict[str, list[dict]] = {}
    for e in sorted(events, key=lambda e: e["timestamp"]):
        by_tel.setdefault(e.get("_telemetry"), []).append(e)
    alerts = []
    for rule in rules:
        for det in rule.detections:
            evs = by_tel.get(det["telemetry"], [])
            if det.get("threshold"):
                th = det["threshold"]
                for g in evaluate_stream(det, evs):
                    sample = sorted({x.get("file_path") or _summary(x) for x in g["events"]})[:5]
                    alerts.append(_alert(
                        rule, det, g["first"],
                        f"{g['count']} matching events between {iso(g['first'])} and {iso(g['last'])} "
                        f"(threshold {th['count']} per {th['window_minutes']} min); e.g. {', '.join(sample)}",
                        g["events"][0], count=g["count"], sample=sample))
            elif det.get("first_seen"):
                fs = det["first_seen"]
                lookback = timedelta(days=int(fs["lookback_days"]))
                start = evs[0]["timestamp"] if evs else None
                last: dict[str, object] = {}
                for e in evs:
                    if not evaluate(det, e):
                        continue
                    key = str(e.get(fs["by"], "")).lower()
                    prev = last.get(key)
                    if prev is None or e["timestamp"] - prev > lookback:
                        alerts.append(_alert(
                            rule, det, e["timestamp"],
                            f"{e.get(fs['by'])} first seen at {iso(e['timestamp'])}; the logs' history starts "
                            f"{iso(start)} (a live rule looks back {fs['lookback_days']} days)", e,
                            value=e.get(fs["by"]), history_start=start))
                    last[key] = e["timestamp"]
            else:
                for e in evs:
                    if evaluate(det, e):
                        alerts.append(_alert(rule, det, e["timestamp"], _summary(e), e, source=e.get("_source")))
    return sorted(alerts, key=lambda a: (a["timestamp"], a["hypothesis"], a["detection"]))
