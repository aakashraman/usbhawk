"""usbthk command line.

  usbthk sessions --triage C:\\Cases\\WS042\\kape_out --tz America/New_York --out out\\
  usbthk devices  --triage /cases/ws042
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from . import __version__
from .collect import ArtifactSet, discover, load
from .output import (ensure_dir, print_findings, print_sessions, write_csv, write_devices, write_findings,
                     write_jsonl)
from .scoring import apply_host_timezone, load_config, score_sessions
from .sessions import build_sessions
from .tamper import find_tamper, host_mismatch_findings


def _artifacts(args) -> ArtifactSet:
    arts = discover(args.triage) if args.triage else ArtifactSet()
    if args.system:
        arts.system = args.system
    if args.software:
        arts.software = args.software
    for item in args.ntuser or []:
        path, _, user = item.partition("=")
        arts.ntuser.append((path, user or os.path.basename(os.path.dirname(path)) or "unknown"))
    arts.partition_diag += args.partition_log or []
    arts.security += args.security_log or []
    arts.system_log += args.system_log or []
    arts.setupapi += args.setupapi or []
    arts.file_events += args.file_events or []
    return arts


def _read_list(path):
    if not path:
        return []
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]


def _common(p: argparse.ArgumentParser):
    g = p.add_argument_group("evidence (use --triage to auto-discover, or point at files)")
    g.add_argument("--triage", help="folder containing KAPE/Velociraptor output or a mounted image")
    g.add_argument("--system", help="SYSTEM hive")
    g.add_argument("--software", help="SOFTWARE hive")
    g.add_argument("--ntuser", action="append", metavar="PATH[=USER]", help="NTUSER.DAT (repeatable)")
    g.add_argument("--partition-log", action="append", help="Microsoft-Windows-Partition%%4Diagnostic.evtx")
    g.add_argument("--security-log", action="append", help="Security.evtx")
    g.add_argument("--system-log", action="append", help="System.evtx")
    g.add_argument("--setupapi", action="append", help="setupapi.dev.log")
    g.add_argument("--file-events", action="append",
                   help="CSV of file activity (MDE DeviceFileEvents, Sysmon 11, Falcon, LECmd)")
    p.add_argument("--out", help="output folder for JSONL/CSV")
    p.add_argument("-q", "--quiet", action="store_true")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="usbthk", description="USB Threat Hunting Toolkit")
    ap.add_argument("--version", action="version", version=f"usbthk {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("sessions", help="build and score USB connect sessions (exfil triage)")
    _common(sp)
    sp.add_argument("--config", help="scoring TOML (see config/scoring.toml)")
    sp.add_argument("--tz", help="IANA timezone for work hours, e.g. America/New_York "
                                 "(default: config file, else the host's registry time zone, else UTC)")
    sp.add_argument("--watchlist", help="text file of usernames (e.g. leavers list)")
    sp.add_argument("--allowlist", help="text file of approved device serials")
    sp.add_argument("--min-score", type=int, default=0)
    sp.add_argument("--all-classes", action="store_true", help="include HID/hubs/etc., not just storage")
    sp.add_argument("--limit", type=int, default=50, help="rows to print")

    dp = sub.add_parser("devices", help="device inventory (11-step profile per device)")
    _common(dp)

    tp = sub.add_parser("tamper", help="detect wiped USB traces and cleared logs (cleanup vs feature update)")
    _common(tp)

    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("regipy").setLevel(logging.CRITICAL)  # noisy about undecodable REG_SZ
    say = (lambda *_: None) if args.quiet else (lambda m: print(m, file=sys.stderr))

    arts = _artifacts(args)
    if not any(arts.summary().values()):
        ap.error("no artifacts found - pass --triage or individual artifact paths")
    say(f"usbthk {__version__}: loading artifacts")
    ev = load(arts, verbose=say)

    if args.cmd == "tamper":
        findings = find_tamper(ev)
        print_findings(findings, ev)
        if args.out:
            path = os.path.join(ensure_dir(args.out), "tamper.jsonl")
            write_findings(findings, path)
            say(f"wrote {len(findings)} findings to {path}")
        return 0

    # Mixed-host evidence also matters for sessions/devices: surface it as a warning there.
    ev.warnings.extend(f.why for f in host_mismatch_findings(ev))

    if args.cmd == "devices":
        import json
        if args.out:
            write_devices(ev, os.path.join(ensure_dir(args.out), "devices.jsonl"))
        for d in ev.devices.values():
            print(json.dumps({"host": ev.host.hostname, **d.to_dict()}, default=str))
        return 0

    try:
        cfg = load_config(args.config, timezone=args.tz,
                          watchlist_users=_read_list(args.watchlist),
                          allowlist_serials=_read_list(args.allowlist))
    except ValueError as exc:
        print(f"usbthk: error: {exc}", file=sys.stderr)
        return 2
    cfg, tz_warning = apply_host_timezone(cfg, ev.host.timezone_key)
    if tz_warning:
        ev.warnings.append(tz_warning)
    wh = cfg["work_hours"]
    say(f"work hours {wh['start_hour']:02d}:00-{wh['end_hour']:02d}:00 {wh['timezone']} "
        f"(tz from {wh['timezone_source']}); all timestamps are UTC")
    sessions = build_sessions(ev, include_all_classes=args.all_classes)
    sessions = [s for s in score_sessions(sessions, cfg) if s.score >= args.min_score]
    print_sessions(sessions, ev, limit=args.limit)
    if args.out:
        out = ensure_dir(args.out)
        write_jsonl(sessions, os.path.join(out, "sessions.jsonl"))
        write_csv(sessions, os.path.join(out, "sessions.csv"))
        write_devices(ev, os.path.join(out, "devices.jsonl"))
        say(f"wrote {len(sessions)} sessions to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
