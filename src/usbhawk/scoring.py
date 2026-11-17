"""Explainable exfil-risk scoring for USB sessions.

Every rule returns points plus a human-readable reason, so a score of 85 always comes with
"why". Weights and thresholds live in config/scoring.toml and can be tuned per environment.
"""

from __future__ import annotations

import copy
import os
import tomllib
from zoneinfo import ZoneInfo, available_timezones

from .model import FILE_DELETE, FILE_WRITE, MTP, Session
from .tzmap import clean_windows_tz, windows_to_iana

DEFAULT_CONFIG: dict = {
    "work_hours": {"timezone": "UTC", "start_hour": 8, "end_hour": 18, "workdays": [0, 1, 2, 3, 4]},
    "thresholds": {
        "bulk_files": 50,
        "bulk_bytes": 500 * 1024 * 1024,
        "high_capacity_bytes": 256 * 10**9,
        "long_session_minutes": 30,
    },
    "weights": {
        "first_seen_device": 25,
        "off_hours": 15,
        "file_writes": 20,
        "bulk_transfer": 20,
        "archive_written": 15,
        "reformat_or_repartition": 25,
        "mass_delete_on_device": 10,
        "mtp_device": 10,
        "high_capacity": 5,
        "long_session": 5,
        "no_hardware_serial": 5,
        "watchlist_user": 30,
        "allowlisted_device": -50,
    },
    "severity": {"high": 70, "medium": 40, "low": 15},
    "archive_extensions": [".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".cab", ".iso", ".pst", ".kdbx"],
    "watchlist_users": [],
    "allowlist_serials": [],
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(path: str | None = None, **overrides) -> dict:
    """Load scoring config. work_hours.timezone_source records who chose the zone:
    "--tz" (override) > "config" (TOML) > "default" (UTC; may be replaced by apply_host_timezone)."""
    cfg = DEFAULT_CONFIG
    source = "default"
    if path and not os.path.isfile(path):
        raise ValueError(f"config file not found: {path}")     # never fall back to defaults on a typo
    if path:
        with open(path, "rb") as fh:
            file_cfg = tomllib.load(fh)
        cfg = _merge(cfg, file_cfg)
        if file_cfg.get("work_hours", {}).get("timezone"):
            source = "config"
    clean = {k: v for k, v in overrides.items() if v not in (None, [], "")}
    if "timezone" in clean:
        cfg = _merge(cfg, {"work_hours": {"timezone": clean.pop("timezone")}})
        source = "--tz"
    cfg = _merge(cfg, clean)
    cfg["work_hours"]["timezone_source"] = source
    _work_tz(cfg)  # fail now, not silently at scoring time
    return cfg


def apply_host_timezone(cfg: dict, windows_tz: str | None) -> tuple[dict, str | None]:
    """Use the host's registry time zone for work hours when neither --tz nor the config set one.

    Returns (new_cfg, warning). Timestamps stay UTC everywhere; this only changes the clock the
    off_hours rule judges against.
    """
    if cfg["work_hours"].get("timezone_source", "default") != "default":
        return cfg, None
    iana = windows_to_iana(windows_tz)
    if iana is None:
        return cfg, (f"work hours judged in UTC: host time zone {windows_tz!r} could not be mapped; "
                     f"pass --tz (e.g. --tz America/New_York) for accurate off_hours scoring")
    out = copy.deepcopy(cfg)
    out["work_hours"]["timezone"] = iana
    out["work_hours"]["timezone_source"] = f"host registry: {clean_windows_tz(windows_tz)}"
    return out, None


def _work_tz(cfg: dict) -> ZoneInfo:
    name = cfg["work_hours"]["timezone"]
    try:
        return ZoneInfo(name)
    except Exception as exc:
        if not available_timezones():
            raise ValueError(f"cannot resolve work-hours timezone {name!r}: no timezone database found "
                             f"(on Windows run: pip install tzdata)") from exc
        raise ValueError(f"unknown work-hours timezone {name!r}: use an IANA name such as "
                         f"'America/New_York', not a Windows name like 'Eastern Standard Time'") from exc


def _reason(rule: str, points: int, why: str) -> dict:
    return {"rule": rule, "points": points, "why": why}


def score_session(s: Session, cfg: dict) -> Session:
    w, t = cfg["weights"], cfg["thresholds"]
    layout_changes = [r for r in s.reasons if "_layout_change" in r]
    reasons: list[dict] = []

    def hit(rule, why):
        pts = int(w.get(rule, 0))
        if pts:
            reasons.append(_reason(rule, pts, why))

    dev = s.device
    if dev.serial.upper() in {x.upper() for x in cfg.get("allowlist_serials", [])}:
        hit("allowlisted_device", "device serial is on the allowlist")

    if s.first_seen:
        hit("first_seen_device", "first time this device was ever installed on this host")

    if s.start:
        wh = cfg["work_hours"]
        local = s.start.astimezone(_work_tz(cfg))
        if local.weekday() not in wh["workdays"] or not (wh["start_hour"] <= local.hour < wh["end_hour"]):
            hit("off_hours", f"connected {s.start:%Y-%m-%d %H:%M}Z = {local:%a %Y-%m-%d %H:%M} "
                             f"{wh['timezone']}, outside work hours "
                             f"(tz from {wh.get('timezone_source', 'default')})")

    writes = [e for e in s.file_events if e.kind == FILE_WRITE]
    deletes = [e for e in s.file_events if e.kind == FILE_DELETE]
    total_bytes = sum(e.details.get("size") or 0 for e in writes)
    if writes:
        hit("file_writes", f"{len(writes)} file write event(s) to the device during the session")
    if len(writes) >= t["bulk_files"] or total_bytes >= t["bulk_bytes"]:
        hit("bulk_transfer", f"{len(writes)} files / {total_bytes / 1048576:.1f} MB written")
    exts = tuple(cfg["archive_extensions"])
    archives = sorted({os.path.basename(str(e.details.get("path"))) for e in writes
                       if str(e.details.get("path", "")).lower().endswith(exts)})
    if archives:
        hit("archive_written", f"archive/container files written: {', '.join(archives[:5])}")
    if len(deletes) >= t["bulk_files"]:
        hit("mass_delete_on_device", f"{len(deletes)} delete events on the device")

    if layout_changes:
        hit("reformat_or_repartition",
            f"volume serial/partition layout changed {len(layout_changes)}x "
            f"(first at {layout_changes[0]['_layout_change']}) - device reformatted or repartitioned")
    elif len(s.vsns) > 1:
        hit("reformat_or_repartition", f"multiple volume serial numbers seen: {', '.join(s.vsns)}")

    if dev.device_class == MTP:
        hit("mtp_device", "MTP device (phone/tablet) - no drive letter, often missed by DLP")
    cap = s.capacity_bytes or dev.capacity_bytes or 0
    if cap >= t["high_capacity_bytes"]:
        hit("high_capacity", f"high-capacity device ({cap / 1e9:.0f} GB)")
    dur = s.duration_seconds
    if dur and dur >= t["long_session_minutes"] * 60:
        hit("long_session", f"connected for {dur / 60:.0f} minutes")
    if dev.windows_generated_serial:
        hit("no_hardware_serial", "device has no iSerialNumber (Windows-generated id); hard to track fleet-wide")

    watch = {u.lower() for u in cfg.get("watchlist_users", [])}
    if watch:
        names = {u.lower().split(" (")[0] for u in s.users} | {str(e.user).lower() for e in s.file_events if e.user}
        flagged = sorted(n for n in names if n in watch or n.split("\\")[-1] in watch)
        if flagged:
            hit("watchlist_user", f"watchlisted user(s) active: {', '.join(flagged)}")

    s.reasons = reasons
    s.score = max(0, min(100, sum(r["points"] for r in reasons)))
    sev = cfg["severity"]
    s.severity = ("high" if s.score >= sev["high"] else "medium" if s.score >= sev["medium"]
                  else "low" if s.score >= sev["low"] else "info")
    return s


def score_sessions(sessions: list[Session], cfg: dict) -> list[Session]:
    for s in sessions:
        score_session(s, cfg)
    return sorted(sessions, key=lambda s: (-s.score, s.start or s.end))
