"""Module #3: USB artifact tamper / cleanup detection.

Windows records a USB device in places that are easy to wipe (Enum\\USB, Enum\\USBSTOR, Enum\\SCSI) and in
places that usually survive (Partition/Diagnostic log, MountedDevices, Windows Portable Devices, EMDMgmt,
MountPoints2, DeviceMigration). When a device survives somewhere but is gone from Enum, one of two things
happened:

  * Windows removed it: a feature update purges Enum and archives devices under DeviceMigration.
    -> explained_by_feature_update (info)
  * Someone removed it: USBOblivion, a cleanup script, manual key deletion.
    -> orphaned_device_reference (medium; high if an event log was cleared within 24 h)

Event-log clearing (Security 1102, System 104) is reported on its own (log_cleared). Evidence from another
machine mixed into the triage folder is reported (evidence_host_mismatch) and excluded from the checks.

Scorers never parse: everything here reads the normalised Evidence model only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .model import CONNECT, LOG_CLEARED, UASP, USBSTOR, Evidence
from .util import iso, strip_lun

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
RISK_SCORE = {"high": 75, "medium": 50, "low": 25, "info": 0}
CORRELATION_WINDOW = timedelta(hours=24)
ENUM_PREFIX = "registry:Enum\\"
# Clearing one of these logs destroys USB evidence directly.
CRITICAL_CHANNELS = {
    "security", "system", "microsoft-windows-partition/diagnostic",
    "microsoft-windows-kernel-pnp/configuration", "microsoft-windows-driverframeworks-usermode/operational",
}
TAMPER_ID_TYPES = {"usb_serial", "volume_guid"}
STORAGE_CLASSES = {USBSTOR, UASP}
RAISE = {"info": "info", "low": "medium", "medium": "high", "high": "high"}
# Programs whose purpose is erasing USB/log traces (rule 5). Matched on the start of the executable name.
CLEANUP_TOOLS = {
    "usboblivion": ("USBOblivion", "high", "it exists to erase USB device history and, in our lab, also "
                                           "cleared the Security and System logs without saying so"),
    "drivecleanup": ("DriveCleanup", "medium", "it removes non-present USB storage devices from the registry"),
    "usbdeview": ("USBDeview", "medium", "it can uninstall USB devices and delete their registry records"),
    "privazer": ("PrivaZer", "medium", "this privacy cleaner wipes USB history among other traces"),
    "ccleaner": ("CCleaner", "medium", "this cleaner can clear event logs and recent-file traces"),
    "bleachbit": ("BleachBit", "medium", "this cleaner can wipe logs and usage traces"),
    "sdelete": ("SDelete", "medium", "it securely deletes files so they cannot be recovered"),
}


@dataclass
class Finding:
    rule: str
    severity: str                       # high | medium | low | info
    why: str                            # one human-readable sentence; a finding without it is a bug
    evidence: dict[str, Any] = field(default_factory=dict)
    ts: datetime | None = None          # when the underlying thing happened (UTC)
    host: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "@timestamp": iso(self.ts),
            "event": {"kind": "alert" if self.severity in ("high", "medium") else "event",
                      "category": ["host"], "type": ["info"], "dataset": "usbhawk.tamper",
                      "severity_label": self.severity, "risk_score": RISK_SCORE[self.severity]},
            "host": {"name": self.host},
            "usbhawk": {"rule": self.rule, "severity": self.severity, "why": self.why,
                       "evidence": _jsonable(self.evidence)},
        }


def _jsonable(value):
    if isinstance(value, datetime):
        return iso(value)
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        items = [_jsonable(v) for v in value]
        return sorted(items, key=str) if isinstance(value, set) else items
    return value


# --------------------------------------------------------------------------- entry point
def find_tamper(ev: Evidence) -> list[Finding]:
    host = ev.host.hostname
    findings = host_mismatch_findings(ev)
    foreign = foreign_computers(ev)
    clears = sorted((e for e in ev.events if e.kind == LOG_CLEARED), key=lambda e: e.ts)
    findings += [_log_cleared(e, host) for e in clears]
    findings += partition_log_gap_findings(ev, foreign)
    tools = cleanup_tool_runs(ev)
    findings += [_cleanup_tool(x, info, clears, host) for x, info in tools]
    findings += [_missing_artifact(name, host) for name in ev.collection_gaps]

    refs = list(_references(ev, foreign))
    if refs and "SYSTEM" not in ev.parsed:
        findings.append(Finding(
            "orphan_checks_skipped", "info",
            f"SYSTEM hive not parsed, so it is unknown whether {len(refs)} referenced device(s) are still "
            f"in Enum; orphan checks skipped. Add the SYSTEM hive to the triage.",
            {"references": len(refs)}, None, host))
    elif refs:
        findings += [_classify(r, ev, clears, tools) for r in refs]
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity],
                                           f.ts.timestamp() if f.ts else float("inf")))


# --------------------------------------------------------------------------- host consistency
def _short(name: str | None) -> str:
    return (name or "").split(".", 1)[0].strip().upper()


def foreign_computers(ev: Evidence) -> set[str]:
    """Computer names in the event logs that are not the host the registry hives came from."""
    me = _short(ev.host.hostname)
    if not me or me == "UNKNOWN-HOST":
        return set()
    return {c for counts in ev.log_computers.values() for c in counts if _short(c) != me}


def host_mismatch_findings(ev: Evidence) -> list[Finding]:
    foreign = foreign_computers(ev)
    out = []
    for log, counts in sorted(ev.log_computers.items()):
        bad = {c: n for c, n in counts.items() if c in foreign}
        if not bad:
            continue
        who = ", ".join(f"{c} ({n} records)" for c, n in sorted(bad.items()))
        out.append(Finding(
            "evidence_host_mismatch", "info",
            f"{log} log was written by {who}, but the registry hives are from {ev.host.hostname}: this log "
            f"comes from another machine. Devices seen only in it are excluded from tamper checks; check how "
            f"the triage folder was assembled.",
            {"log": log, "foreign_computers": bad, "registry_host": ev.host.hostname}, None, ev.host.hostname))
    return out


# --------------------------------------------------------------------------- log clearing
def _log_cleared(e, host) -> Finding:
    channel = e.details.get("channel") or "?"
    severity = "high" if channel.lower() in CRITICAL_CHANNELS else "medium"
    return Finding(
        "log_cleared", severity,
        f"{channel} event log cleared by {e.user or 'an unknown user'} at {iso(e.ts)} ({e.source}). "
        f"Clearing logs destroys evidence of device use and activity.",
        {"channel": channel, "user": e.user, "source": e.source, "computer": e.details.get("computer"),
         "backup_path": e.details.get("backup_path")}, e.ts, host)


# --------------------------------------------------------------------------- rule 3: Partition log gap
def partition_log_gap_findings(ev: Evidence, foreign: set[str]) -> list[Finding]:
    """The Partition/Diagnostic log lost records it must have had.

    * Record IDs jump: Windows never removes records from the middle of a log, so they were deleted.
    * The log is empty or starts at record 1 (a rolled-over log keeps IDs above 1), yet the registry shows
      USB disks arriving after the current Windows build was installed: their 1006 records were wiped.
    """
    st = ev.log_stats.get("Partition/Diagnostic")
    host = ev.host.hostname
    if not st or "SYSTEM" not in ev.parsed:
        return []
    comps = ev.log_computers.get("Partition/Diagnostic", {})
    if comps and all(c in foreign for c in comps):
        return []           # another machine's log: evidence_host_mismatch already says so
    out = []
    if st["id_gaps"]:
        lost = sum(b - a - 1 for a, b in st["id_gaps"])
        spans = ", ".join(f"{a} to {b}" for a, b in st["id_gaps"][:5])
        out.append(Finding(
            "partition_log_gap", "medium",
            f"Partition/Diagnostic log is missing {lost} record(s) inside its sequence (record IDs jump "
            f"{spans}). Windows never removes records from the middle of a log: they were deleted selectively.",
            {"log": "Partition/Diagnostic", "id_gaps": st["id_gaps"], "records": st["records"]}, None, host))

    fresh = st["records"] == 0 or st["first_id"] == 1
    updates = [u["ts"] for u in ev.host.feature_updates] + ([ev.host.install_time] if ev.host.install_time else [])
    build = max(updates) if updates else None
    if not fresh or build is None:
        return out
    start = st["oldest"]
    lost_devs = []
    for dev in ev.devices.values():
        if dev.device_class not in STORAGE_CLASSES or not any(s.startswith(ENUM_PREFIX) for s in dev.sources):
            continue
        arrivals = [e.ts for e in ev.events
                    if e.device_key == dev.key and e.kind == CONNECT and e.source.startswith("registry:")]
        last = max(arrivals, default=None)
        if last and last > build and (start is None or last < start):
            product = " ".join(x for x in (dev.vendor, dev.product) if x)
            lost_devs.append({"device": dev.key, "product": product or None, "last_arrival": last})
    if lost_devs:
        lost_devs.sort(key=lambda d: d["last_arrival"])
        state = "is empty" if start is None else f"starts fresh at record 1 ({iso(start)})"
        names = "; ".join(f"{d['device']} at {iso(d['last_arrival'])}" for d in lost_devs[:5])
        more = f" and {len(lost_devs) - 5} more" if len(lost_devs) > 5 else ""
        out.append(Finding(
            "partition_log_gap", "medium",
            f"Partition/Diagnostic log {state}, yet the registry shows {len(lost_devs)} USB storage device(s) "
            f"arriving after the current Windows build was installed ({iso(build)}): {names}{more}. Their 1006 "
            f"records are gone, and a log that rolls over keeps record IDs above 1, so the log was cleared or "
            f"reset after those arrivals.",
            {"log": "Partition/Diagnostic", "records": st["records"], "first_id": st["first_id"],
             "oldest_record": start, "current_build_installed": build, "devices": lost_devs}, start, host))
    return out


# --------------------------------------------------------------------------- rule 5: cleanup tools
def cleanup_tool_runs(ev: Evidence) -> list[tuple[dict, tuple]]:
    """Executions (BAM) of known USB/log cleanup tools, oldest first."""
    runs = []
    for x in ev.executions:
        name = (x.get("name") or "").lower()
        for prefix, info in CLEANUP_TOOLS.items():
            if name.startswith(prefix):
                runs.append((x, info))
                break
    return sorted(runs, key=lambda r: r[0]["ts"])


def _who(x: dict) -> str:
    return x.get("user") or x.get("sid") or "an unknown user"


def _cleanup_tool(x: dict, info: tuple, clears: list, host) -> Finding:
    label, severity, what = info
    after = [c for c in clears if timedelta(0) <= c.ts - x["ts"] <= CORRELATION_WINDOW]
    why = (f"{label} ({x['name']}) was run by {_who(x)}, last at {iso(x['ts'])} ({x.get('source')}: "
           f"{x['path']}). This is a cleanup tool: {what}.")
    if after:
        logs = ", ".join(sorted({c.details.get("channel") or "?" for c in after}))
        why += f" Event logs cleared within 24 h after it: {logs} (first at {iso(after[0].ts)})."
    return Finding("cleanup_tool_execution", severity, why,
                   {"tool": label, "name": x["name"], "path": x["path"], "user": x.get("user"),
                    "sid": x.get("sid"), "source": x.get("source"),
                    "log_clears_after": [c.ts for c in after]}, x["ts"], host)


def _missing_artifact(name: str, host) -> Finding:
    return Finding(
        "expected_artifact_missing", "low",
        f"{name} is missing from the triage although its folder (Windows\\INF) was collected. Windows always "
        f"keeps this log, and cleanup tools such as USBOblivion delete it; check that the collection did not "
        f"simply skip it.", {"artifact": name}, None, host)


# --------------------------------------------------------------------------- orphan references
def _migrated_serials(ev: Evidence) -> dict[str, dict]:
    out = {}
    for m in ev.migrated:
        serial = strip_lun(str(m.get("id", "")).rsplit("\\", 1)[-1]).upper()
        if serial:
            out[serial] = m
    return out


def _references(ev: Evidence, foreign: set[str]):
    """Everything that points at a device which Enum no longer lists."""
    by_dev: dict[str, list] = {}
    for e in ev.events:
        if e.device_key:
            by_dev.setdefault(e.device_key, []).append(e)

    for dev in ev.devices.values():
        if any(s.startswith(ENUM_PREFIX) for s in dev.sources):
            continue
        events = by_dev.get(dev.key, [])
        native = any(s.startswith("registry:") for s in dev.sources) or any(
            e.details.get("computer") not in foreign for e in events)
        if not native:
            continue  # only known from another machine's log
        product = " ".join(x for x in (dev.vendor, dev.product) if x)
        yield {"label": f"{product + ' ' if product else ''}{dev.key}", "id_type": "usb_serial",
               "id_value": dev.serial, "device_key": dev.key, "artifact": None,
               "ref_time": max((e.ts for e in events), default=None), "scope": "entry", "user": None,
               "surviving_sources": sorted(dev.sources),
               "device_migration": "registry:DeviceMigration" in dev.sources}

    migrated = _migrated_serials(ev)
    for u in ev.unlinked:
        if u.get("id_type") not in TAMPER_ID_TYPES:
            continue
        what = "USB serial" if u["id_type"] == "usb_serial" else "volume"
        yield {"label": f"{what} {u['id_value']}", "id_type": u["id_type"], "id_value": u["id_value"],
               "device_key": None, "artifact": u["artifact"], "ref_time": u.get("ref_time"),
               "scope": u.get("ref_time_scope"), "user": u.get("user"),
               "surviving_sources": [f"registry:{u['artifact']}"],
               "device_migration": u["id_type"] == "usb_serial" and str(u["id_value"]).upper() in migrated}


def _classify(ref: dict, ev: Evidence, clears: list, tools: list = ()) -> Finding:
    host = ev.host.hostname
    updates = sorted(ev.host.feature_updates, key=lambda f: f["ts"])
    t, scope = ref["ref_time"], ref["scope"]
    where = ", ".join(ref["surviving_sources"])
    base = {k: ref[k] for k in ("artifact", "id_type", "id_value", "device_key", "user", "surviving_sources")}
    base.update({"last_reference": t, "ref_time_scope": scope})

    if ref["device_migration"]:
        return Finding(
            "explained_by_feature_update", "info",
            f"{ref['label']} is missing from Enum but listed in DeviceMigration: Windows archived it during "
            f"a feature update. Benign.",
            {**base, "device_migration": True, "feature_update": None}, t, host)

    later = [u for u in updates if t and u["ts"] > t]
    if later:
        u = later[0]
        return Finding(
            "explained_by_feature_update", "info",
            f"{ref['label']} is missing from Enum, but a feature update/reinstall at {iso(u['ts'])} "
            f"({u['source']}) came after its last reference ({iso(t)}). Consistent with Windows cleanup.",
            {**base, "device_migration": False, "feature_update": u["ts"],
             "feature_update_source": u["source"]}, t, host)

    last_update = updates[-1] if updates else None
    after = (f"no feature update after it (latest on record: {iso(last_update['ts'])})" if last_update
             else "no feature update on record")
    who = f" (user {ref['user']})" if ref["user"] else ""
    if t is None:
        severity = "low" if updates else "medium"
        timing = (f"the reference has no timestamp, so it cannot be compared with the feature update(s) "
                  f"on record (latest: {iso(last_update['ts'])}); low confidence" if updates
                  else f"the reference has no timestamp and {after}")
    elif scope == "parent_key":
        severity = "low"
        timing = (f"last referenced at or before {iso(t)} (the key's last-write time is only an upper bound); "
                  f"{after}")
    else:
        severity = "medium"
        timing = f"last referenced {iso(t)}; {after}"
    if ref["id_type"] == "volume_guid":
        severity = "low"   # a volume GUID alone could be a VHD/ISO mount, not necessarily USB

    why = (f"{ref['label']}{who} still appears in {where} but is missing from Enum\\USB/USBSTOR/SCSI; "
           f"{timing}. The device keys were likely deleted (e.g. USBOblivion or manual cleanup).")
    evidence = {**base, "latest_feature_update": last_update["ts"] if last_update else None,
                "correlated_log_clear": None, "correlated_cleanup_tool": None}

    # Cleanup follows use: only a clear in the 24 h *after* the last reference correlates. (Lab: Explorer
    # recreated a MountPoints2 key minutes after USBOblivion had cleared the logs.)
    near = [c for c in clears if t and timedelta(0) <= c.ts - t <= CORRELATION_WINDOW]
    if near:
        c = near[0]
        severity = "high"
        why += (f" The {c.details.get('channel') or '?'} log was cleared at {iso(c.ts)} "
                f"by {c.user or 'an unknown user'}, within 24 h after it: consistent with deliberate cleanup.")
        evidence["correlated_log_clear"] = c.ts

    # A cleanup tool that ran after the last reference explains *how* the keys disappeared: one level up.
    ran = [(x, info) for x, info in tools if t and x["ts"] >= t]
    if ran:
        x, (label, _sev, _what) = ran[0]
        severity = RAISE[severity]
        why += (f" {label} was run by {_who(x)} at {iso(x['ts'])}, after this last reference: "
                f"the traces were likely wiped with it.")
        evidence["correlated_cleanup_tool"] = {"name": x["name"], "ts": x["ts"], "path": x["path"]}
    return Finding("orphaned_device_reference", severity, why, evidence, t, host)
