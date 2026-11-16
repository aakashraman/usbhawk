"""Writers: ECS-flavoured JSONL (SIEM-ready), flat CSV, and a console table."""

from __future__ import annotations

import csv
import json
import os

from .model import FILE_DELETE, FILE_READ, FILE_WRITE, Evidence, Session
from .util import iso

SEV_STYLE = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}


def session_to_ecs(s: Session) -> dict:
    d = s.device
    writes = [e for e in s.file_events if e.kind == FILE_WRITE]
    dur = s.duration_seconds
    return {
        "@timestamp": iso(s.start or s.end),
        "event": {"kind": "event", "category": ["host"], "type": ["connection"],
                  "dataset": "usbthk.session", "start": iso(s.start), "end": iso(s.end),
                  "duration": int(dur * 1e9) if dur is not None else None,
                  "risk_score": s.score, "severity_label": s.severity},
        "host": {"name": s.host},
        "user": {"name": s.users[0] if s.users else None, "names": s.users},
        "usb": {"device": {
            "key": d.key, "vid": d.vid, "pid": d.pid, "serial": d.serial, "class": d.device_class,
            "vendor": d.vendor, "product": d.product, "friendly_name": d.friendly_name,
            "device_id": d.device_id, "capacity_bytes": s.capacity_bytes or d.capacity_bytes,
            "windows_generated_serial": d.windows_generated_serial,
            "volume_names": sorted(d.volume_names), "drive_letters": sorted(d.drive_letters),
            "volume_guids": sorted(d.volume_guids), "disk_ids": sorted(d.disk_ids),
            "vsns_all_time": sorted(d.vsns)}},
        "usbthk": {
            "session_id": s.session_id, "score": s.score, "severity": s.severity,
            "reasons": s.reasons, "first_seen": s.first_seen, "vsns": s.vsns,
            "filesystems": s.filesystems, "connect_events": s.connect_events,
            "evidence": {"start": s.start_sources, "end": s.end_sources},
            "file_activity": {
                "writes": len(writes),
                "reads": sum(e.kind == FILE_READ for e in s.file_events),
                "deletes": sum(e.kind == FILE_DELETE for e in s.file_events),
                "bytes_written": sum(e.details.get("size") or 0 for e in writes),
                "sample": [e.details.get("path") for e in writes[:25]],
            },
        },
    }


def write_jsonl(sessions: list[Session], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for s in sessions:
            fh.write(json.dumps(session_to_ecs(s), default=str) + "\n")


def write_csv(sessions: list[Session], path: str) -> None:
    cols = ["score", "severity", "host", "start_utc", "end_utc", "duration_min", "device_class",
            "vendor", "product", "serial", "volume_names", "drive_letters", "vsns", "users",
            "file_writes", "first_seen", "reasons", "session_id"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for s in sessions:
            d = s.device
            dur = s.duration_seconds
            w.writerow([s.score, s.severity, s.host, iso(s.start), iso(s.end),
                        f"{dur / 60:.1f}" if dur is not None else "", d.device_class, d.vendor,
                        d.product or d.friendly_name, d.serial, ";".join(sorted(d.volume_names)),
                        ";".join(sorted(d.drive_letters)), ";".join(s.vsns), ";".join(s.users),
                        sum(e.kind == FILE_WRITE for e in s.file_events), s.first_seen,
                        " | ".join(f"{r['rule']}(+{r['points']})" for r in s.reasons), s.session_id])


def write_devices(ev: Evidence, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for d in ev.devices.values():
            fh.write(json.dumps({"host": ev.host.hostname, **d.to_dict()}, default=str) + "\n")


def print_sessions(sessions: list[Session], ev: Evidence, limit: int = 50) -> None:
    from rich.console import Console
    from rich.table import Table

    con = Console()
    h = ev.host
    con.print(f"[bold]Host[/bold] {h.hostname}  [dim]{h.os_product or ''} {h.os_build or ''} "
              f"tz={h.timezone_key} last install/feature update={iso(h.install_time)}[/dim]")
    t = Table(show_lines=False, header_style="bold")
    for c in ("Score", "Start (UTC)", "Dur", "Class", "Device", "Serial", "Vol / Letter", "VSN",
              "Users", "Writes", "Why"):
        t.add_column(c, overflow="fold")
    for s in sessions[:limit]:
        d = s.device
        dur = s.duration_seconds
        t.add_row(
            f"[{SEV_STYLE[s.severity]}]{s.score} {s.severity}[/]",
            (iso(s.start) or "?")[:19].replace("T", " "),
            f"{dur / 60:.0f}m" if dur is not None else "no-end",
            d.device_class,
            f"{d.vendor or ''} {d.product or d.friendly_name or ''}".strip(),
            d.serial[:24],
            f"{','.join(sorted(d.volume_names)) or '-'} {','.join(sorted(d.drive_letters))}",
            ",".join(s.vsns[:3]) + ("…" if len(s.vsns) > 3 else ""),
            ", ".join(s.users[:2]) or "-",
            str(sum(e.kind == FILE_WRITE for e in s.file_events)),
            "; ".join(r["rule"] for r in s.reasons) or "-",
        )
    con.print(t)
    if len(sessions) > limit:
        con.print(f"[dim]… {len(sessions) - limit} more sessions in the output files[/dim]")
    for w in ev.warnings[:10]:
        con.print(f"[dim yellow]warning:[/] {w}")


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path
