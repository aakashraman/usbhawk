"""Rule sources for module #4: loading, shared variables, validation, and a reference evaluator.

A rule is one hypothesis (H1..H8). It holds one or more *detections*; each detection reads one kind of
telemetry and is written Sigma-style with neutral field names:

    detections:
      - name: usb_cleaner
        telemetry: process_creation
        selections:
          tool: {process_name|startswith: "${cleanup_tools.high}"}
        condition: tool

Detection-level options (beyond what one event can show):
    channel: Security|System                 event_log only
    removable_media: true                    file_event only: the file was written to removable media
    registry_action: delete                  registry_event only
    threshold: {count, window_minutes, by}   N matching events per group in a fixed time bucket
    first_seen: {by, lookback_days, window_minutes}   value not seen before within the lookback
    outside_work_hours: ${work_hours}        event time outside work hours on the configured local clock

`${...}` placeholders are filled from the same definitions the offline hunts use (scoring config defaults and
tamper.CLEANUP_TOOLS), so live rules and offline findings cannot drift apart. The evaluator here is the reference
semantics: generators must translate to exactly this behaviour, and the rules' own `tests:` run against it.
"""

from __future__ import annotations

import copy
import re
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml

from ..util import to_utc

RULES_DIR = Path(__file__).with_name("rules")
LEVELS = ("low", "medium", "high", "critical")
MODIFIERS = ("eq", "contains", "startswith", "endswith")
# Neutral fields per telemetry type. Generators map these to Sigma / ECS / Microsoft table columns.
TELEMETRY: dict[str, set[str]] = {
    "process_creation": {"process_name", "image", "command_line", "original_file_name", "parent_image",
                         "parent_name", "user", "host"},
    "event_log": {"event_id", "provider", "user", "host"},
    "device_connect": {"device_id", "device_class", "device_description", "user", "host"},
    "file_event": {"file_path", "file_name", "process_name", "image", "user", "host"},
    "registry_event": {"registry_path", "process_name", "image", "user", "host"},
}
CHANNELS = ("Security", "System")      # event_log channels the generators know how to target
DETECTION_KEYS = {"name", "title", "level", "telemetry", "channel", "selections", "condition", "removable_media",
                  "registry_action", "threshold", "first_seen", "outside_work_hours", "related"}
_VAR_RE = re.compile(r"^\$\{([A-Za-z0-9_.]+)\}$")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


# --------------------------------------------------------------------------- shared variables
def rule_vars(cfg: dict | None = None) -> dict[str, Any]:
    """Values rules may reference as ${name}; read live so tuning the hunts also tunes the detections."""
    from .. import tamper
    from ..scoring import load_config

    cfg = cfg or load_config()
    tools: dict[str, list[str]] = {"high": [], "medium": []}
    for prefix, (_label, severity, _what) in tamper.CLEANUP_TOOLS.items():
        tools.setdefault(severity, []).append(prefix)
    return {"cleanup_tools": tools, "archive_extensions": list(cfg["archive_extensions"]),
            "thresholds": dict(cfg["thresholds"]), "work_hours": dict(cfg["work_hours"])}


def _lookup(name: str, variables: dict):
    value: Any = variables
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            raise KeyError(f"unknown placeholder ${{{name}}}")
        value = value[part]
    return copy.deepcopy(value)


def resolve_vars(obj, variables: dict):
    """Replace "${a.b}" strings with variable values; a list placeholder inside a list is spliced in."""
    if isinstance(obj, dict):
        return {k: resolve_vars(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        out = []
        for item in obj:
            m = _VAR_RE.match(item) if isinstance(item, str) else None
            value = _lookup(m.group(1), variables) if m else resolve_vars(item, variables)
            out.extend(value) if (m and isinstance(value, list)) else out.append(value)
        return out
    if isinstance(obj, str):
        m = _VAR_RE.match(obj)
        return _lookup(m.group(1), variables) if m else obj
    return obj


# --------------------------------------------------------------------------- rule objects
@dataclass
class Rule:
    path: Path
    data: dict[str, Any]                   # placeholders already resolved
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    id = property(lambda self: self.data["id"])
    name = property(lambda self: self.data["name"])
    hypothesis = property(lambda self: self.data["hypothesis"])
    title = property(lambda self: self.data["title"])
    detections = property(lambda self: self.data["detections"])

    def detection(self, name: str) -> dict:
        return next(d for d in self.detections if d["name"] == name)

    def level_of(self, name: str) -> str:
        return self.detection(name).get("level", self.data["level"])

    def detection_id(self, name: str) -> str:
        """Stable per-detection UUID (Sigma id / Elastic rule_id): never changes across rebuilds.

        Derived deterministically (UUID5) but stamped as version 4, the form SigmaHQ's validators require.
        """
        return _v4(uuid.uuid5(uuid.UUID(self.id), name))

    def sub_id(self, name: str, part: str) -> str:
        """Stable UUID for a helper document of a detection (e.g. the base rule under a Sigma correlation)."""
        return _v4(uuid.uuid5(uuid.UUID(self.detection_id(name)), part))


def _v4(u: uuid.UUID) -> str:
    return str(uuid.UUID(bytes=u.bytes, version=4))


def load_rules(rules_dir: Path | str | None = None, cfg: dict | None = None) -> list[Rule]:
    variables = rule_vars(cfg)
    rules = []
    for path in sorted(Path(rules_dir or RULES_DIR).glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        rules.append(Rule(path=path, data=resolve_vars(raw, variables), raw=raw))
    return rules


def is_stateful(det: dict) -> bool:
    return bool(det.get("threshold") or det.get("first_seen"))


# --------------------------------------------------------------------------- conditions
_TOKEN_RE = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)")


def parse_condition(text: str):
    """'(a or b) and not c' -> nested tuples: ('and', x, y) / ('or', x, y) / ('not', x) / ('sel', name)."""
    tokens, pos = [], 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise ValueError(f"bad condition near {text[pos:]!r}")
        tokens.append(m.group(1))
        pos = m.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    i = 0

    def peek():
        return tokens[i].lower() if i < len(tokens) else None

    def take():
        nonlocal i
        i += 1
        return tokens[i - 1]

    def expr():
        node = term()
        while peek() == "or":
            take()
            node = ("or", node, term())
        return node

    def term():
        node = factor()
        while peek() == "and":
            take()
            node = ("and", node, factor())
        return node

    def factor():
        if peek() == "not":
            take()
            return ("not", factor())
        if peek() == "(":
            take()
            node = expr()
            if peek() != ")":
                raise ValueError(f"missing ')' in {text!r}")
            take()
            return node
        if peek() in (None, ")", "and", "or"):
            raise ValueError(f"bad condition {text!r}")
        return ("sel", take())

    tree = expr()
    if i != len(tokens):
        raise ValueError(f"unexpected {tokens[i]!r} in {text!r}")
    return tree


def selection_names(tree) -> set[str]:
    if tree[0] == "sel":
        return {tree[1]}
    return set().union(*(selection_names(t) for t in tree[1:]))


def parse_key(key: str) -> tuple[str, str, bool]:
    """'command_line|contains|all' -> ('command_line', 'contains', True): every value must match (Sigma |all)."""
    parts = key.split("|")
    every = len(parts) > 1 and parts[-1] == "all"
    if every:
        parts = parts[:-1]
    return parts[0], (parts[1] if len(parts) > 1 else "eq"), every


def split_key(key: str) -> tuple[str, str]:
    name, mod, _every = parse_key(key)
    return name, mod


# --------------------------------------------------------------------------- reference evaluator
def _norm(v) -> str:
    return str(v).strip().lower()


def _one(actual: str, mod: str, want: str) -> bool:
    return ((mod == "eq" and actual == want) or (mod == "contains" and want in actual)
            or (mod == "startswith" and actual.startswith(want)) or (mod == "endswith" and actual.endswith(want)))


def _field_matches(event: dict, key: str, values) -> bool:
    name, mod, every = parse_key(key)
    if event.get(name) is None:
        return False
    actual = _norm(event[name])
    wants = [_norm(v) for v in (values if isinstance(values, list) else [values])]
    test = all if every else any
    return test(_one(actual, mod, w) for w in wants)


def _eval(tree, results: dict[str, bool]) -> bool:
    op = tree[0]
    if op == "sel":
        return results[tree[1]]
    if op == "not":
        return not _eval(tree[1], results)
    left, right = _eval(tree[1], results), _eval(tree[2], results)
    return (left and right) if op == "and" else (left or right)


def outside_work_hours(ts, wh: dict) -> bool:
    """True when the UTC time `ts` falls outside work hours on the configured local clock."""
    local = to_utc(ts).astimezone(ZoneInfo(wh["timezone"]))
    return (local.weekday() not in wh["workdays"] or local.hour < wh["start_hour"]
            or local.hour >= wh["end_hour"])


def evaluate(detection: dict, event: dict) -> bool:
    """Does this single event (neutral field names) pass the detection's per-event logic?

    For threshold / first_seen detections this is only the filter; use evaluate_stream() for the alert.
    """
    if detection.get("telemetry") == "event_log" and _norm(event.get("channel", "")) != _norm(detection.get("channel", "")):
        return False
    if detection.get("removable_media") and not event.get("removable"):
        return False
    if detection.get("registry_action") and _norm(event.get("action", "")) != _norm(detection["registry_action"]):
        return False
    if detection.get("outside_work_hours"):
        if not event.get("timestamp") or not outside_work_hours(event["timestamp"], detection["outside_work_hours"]):
            return False
    sels = detection.get("selections") or {}
    if not detection.get("condition"):
        return True                      # base filters only (e.g. "any file written to removable media")
    results = {name: all(_field_matches(event, k, v) for k, v in sel.items()) for name, sel in sels.items()}
    return _eval(parse_condition(detection["condition"]), results)


def evaluate_stream(detection: dict, events: list[dict]) -> list[dict]:
    """Alerts for an ordered stream of events, including threshold and first_seen logic.

    threshold : events are grouped by `by` fields and fixed `window_minutes` buckets aligned to the epoch
                (like ES|QL BUCKET and KQL bin); a group with >= count events alerts.
    first_seen: "now" is the newest event; a value alerts when its earliest matching sighting within
                `lookback_days` lies inside the last `window_minutes` (what the scheduled queries compute).
    """
    hits = [e for e in events if evaluate(detection, e)]
    th, fs = detection.get("threshold"), detection.get("first_seen")
    if th:
        span = int(th["window_minutes"]) * 60
        groups: dict[tuple, list] = {}
        for e in hits:
            bucket = int(to_utc(e["timestamp"]).timestamp()) // span
            key = tuple(_norm(e.get(f, "")) for f in th.get("by", [])) + (bucket,)
            groups.setdefault(key, []).append(e)
        return [{"group": k, "count": len(v), "first": to_utc(v[0]["timestamp"]), "last": to_utc(v[-1]["timestamp"]),
                 "events": v} for k, v in groups.items() if len(v) >= int(th["count"])]
    if fs:
        if not hits:
            return []
        now = max(to_utc(e["timestamp"]) for e in events)
        oldest_allowed = now - timedelta(days=int(fs["lookback_days"]))
        window_start = now - timedelta(minutes=int(fs["window_minutes"]))
        first: dict[str, Any] = {}
        for e in hits:
            ts = to_utc(e["timestamp"])
            if ts >= oldest_allowed:
                key = _norm(e.get(fs["by"], ""))
                first[key] = min(first.get(key, ts), ts)
        return [{"value": k, "first_seen": t} for k, t in first.items() if t >= window_start]
    return [{"event": e} for e in hits]


def _expand(events: list[dict]) -> list[dict]:
    """Test helper: {..., repeat: 50, every_seconds: 5} -> 50 events 5 s apart."""
    out = []
    for e in events:
        n, step = int(e.get("repeat", 1)), int(e.get("every_seconds", 0))
        base = {k: v for k, v in e.items() if k not in ("repeat", "every_seconds")}
        for i in range(n):
            ev = dict(base)
            if "timestamp" in ev and i:
                ev["timestamp"] = to_utc(ev["timestamp"]) + timedelta(seconds=step * i)
            out.append(ev)
    return out


def run_rule_tests(rule: Rule) -> list[str]:
    """Run the rule's own test events; return a description of every failure."""
    failures = []
    for n, t in enumerate(rule.data.get("tests", [])):
        det = rule.detection(t["detection"])
        if "events" in t:
            got = bool(evaluate_stream(det, _expand(t["events"])))
            shown = f"{len(_expand(t['events']))} events"
        else:
            got = bool(evaluate_stream(det, [t["event"]])) if is_stateful(det) else evaluate(det, t["event"])
            shown = str(t["event"])
        if got is not bool(t["match"]):
            note = f" ({t['note']})" if t.get("note") else ""
            failures.append(f"{rule.hypothesis} test #{n} ({t['detection']}){note}: expected match={t['match']}, "
                            f"got {got} for {shown}")
    return failures


# --------------------------------------------------------------------------- validation
def _validate_detection(d: dict, errors: list[str]) -> None:
    dn = d.get("name", "?")
    for key in sorted(set(d) - DETECTION_KEYS):
        errors.append(f"{dn}: unknown detection key {key!r}")
    tel = d.get("telemetry")
    if tel not in TELEMETRY:
        errors.append(f"{dn}: unknown telemetry {tel!r} (known: {sorted(TELEMETRY)})")
        return
    fields = TELEMETRY[tel]
    if tel == "event_log" and d.get("channel") not in CHANNELS:
        errors.append(f"{dn}: event_log detections need channel one of {CHANNELS}")
    if d.get("removable_media") and tel != "file_event":
        errors.append(f"{dn}: removable_media only applies to file_event")
    if tel == "registry_event" and d.get("registry_action") != "delete":
        errors.append(f"{dn}: registry_event detections need registry_action: delete")
    if d.get("level") and d["level"] not in LEVELS:
        errors.append(f"{dn}: level {d['level']!r} not in {LEVELS}")
    if d.get("threshold") and d.get("first_seen"):
        errors.append(f"{dn}: use threshold or first_seen, not both")
    th = d.get("threshold")
    if th:
        if not (isinstance(th.get("count"), int) and th["count"] > 0 and isinstance(th.get("window_minutes"), int)):
            errors.append(f"{dn}: threshold needs integer count and window_minutes")
        for f in th.get("by", []):
            if f not in fields:
                errors.append(f"{dn}: threshold.by field {f!r} not available for {tel}")
    fs = d.get("first_seen")
    if fs:
        if fs.get("by") not in fields:
            errors.append(f"{dn}: first_seen.by field {fs.get('by')!r} not available for {tel}")
        if not (isinstance(fs.get("lookback_days"), int) and isinstance(fs.get("window_minutes"), int)):
            errors.append(f"{dn}: first_seen needs integer lookback_days and window_minutes")
    wh = d.get("outside_work_hours")
    if wh is not None and not (isinstance(wh, dict) and {"timezone", "start_hour", "end_hour", "workdays"} <= set(wh)):
        errors.append(f"{dn}: outside_work_hours must be the work_hours settings (use \"${{work_hours}}\")")
    for rel in d.get("related") or []:
        try:
            uuid.UUID(str(rel.get("id")))
        except (ValueError, AttributeError):
            errors.append(f"{dn}: related entries need a SigmaHQ rule id (UUID) and title")

    sels = d.get("selections") or {}
    for sname, sel in sels.items():
        for key in sel:
            fname, mod, every = parse_key(key)
            if every and mod == "eq":
                errors.append(f"{dn}.{sname}: |all needs contains/startswith/endswith")
            if fname not in fields:
                errors.append(f"{dn}.{sname}: field {fname!r} not available for {tel}")
            if mod not in MODIFIERS:
                errors.append(f"{dn}.{sname}: modifier {mod!r} not in {MODIFIERS}")
    if not d.get("condition"):
        if sels:
            errors.append(f"{dn}: selections without a condition")
        elif not (d.get("removable_media") or d.get("registry_action")):
            errors.append(f"{dn}: needs a condition (only removable_media / registry_action may stand alone)")
        return
    try:
        used = selection_names(parse_condition(str(d["condition"])))
        for missing in sorted(used - set(sels)):
            errors.append(f"{dn}: condition uses undefined selection {missing!r}")
    except ValueError as exc:
        errors.append(f"{dn}: {exc}")


def validate_rule(data: dict) -> list[str]:
    """Every problem in a (resolved) rule, as human-readable strings; [] means valid."""
    errors: list[str] = []
    for key in ("id", "hypothesis", "name", "title", "description", "level", "date", "attack", "detections", "tests"):
        if not data.get(key):
            errors.append(f"missing {key}")
    try:
        uuid.UUID(str(data.get("id")))
    except ValueError:
        errors.append(f"id {data.get('id')!r} is not a UUID")
    if not re.fullmatch(r"H\d+", str(data.get("hypothesis", ""))):
        errors.append(f"hypothesis {data.get('hypothesis')!r} must look like H6")
    if data.get("level") not in LEVELS:
        errors.append(f"level {data.get('level')!r} not in {LEVELS}")
    for t in data.get("attack") or []:
        if not _TECH_RE.match(str(t)):
            errors.append(f"attack technique {t!r} must look like T1070 or T1070.001")

    names = set()
    for d in data.get("detections") or []:
        names.add(d.get("name", "?"))
        _validate_detection(d, errors)

    tests = data.get("tests") or []
    for dn in sorted(names):
        kinds = {bool(t.get("match")) for t in tests if t.get("detection") == dn}
        if True not in kinds:
            errors.append(f"{dn}: needs at least one test event that must match")
        if False not in kinds:
            errors.append(f"{dn}: needs at least one no_match test event (where it must stay quiet)")
    for t in tests:
        if t.get("detection") not in names:
            errors.append(f"test refers to unknown detection {t.get('detection')!r}")
        if ("event" in t) == ("events" in t):
            errors.append(f"test for {t.get('detection')!r} needs exactly one of event / events")
    return errors
