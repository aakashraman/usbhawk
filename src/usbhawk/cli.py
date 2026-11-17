"""USBHawk command line: one tool, five commands (sessions, devices, tamper, detections, graph).

  usbhawk --help                       banner, the hunts, examples
  usbhawk <command> --help             what the command answers, options, examples, outputs, guide
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


def _detections(args) -> int:
    from .detections import TARGETS, build, load_rules, run_rule_tests, validate_rule

    try:
        rules = load_rules(cfg=load_config(args.config) if args.config else None)
    except ValueError as exc:
        print(f"usbhawk: error: {exc}", file=sys.stderr)
        return 2
    if args.action == "list":
        from rich.console import Console
        from rich.table import Table
        t = Table(header_style="bold")
        for c in ("Hyp", "Rule", "Detections (level)", "ATT&CK", "Offline hunt"):
            t.add_column(c, overflow="fold")
        for r in rules:
            dets = ", ".join(f"{d['name']} ({r.level_of(d['name'])})" for d in r.detections)
            t.add_row(r.hypothesis, r.title, dets, ", ".join(r.data["attack"]), f"usbhawk {r.data.get('usbhawk', '-')}")
        Console().print(t)
        return 0
    if args.action == "test":
        problems = []
        for r in rules:
            problems += [f"{r.path.name}: {e}" for e in validate_rule(r.data)] + run_rule_tests(r)
        n_tests = sum(len(r.data.get("tests", [])) for r in rules)
        for p in problems:
            print(f"FAIL {p}")
        print(f"{len(rules)} rules, {sum(len(r.detections) for r in rules)} detections, {n_tests} test events: "
              f"{'all passed' if not problems else f'{len(problems)} problem(s)'}")
        return 1 if problems else 0
    if args.action == "run":
        return _detections_run(args, rules)
    targets = TARGETS if args.target == "all" else (args.target,)
    written = 0
    for target in targets:
        for rel, text in build(rules, target).items():
            path = os.path.join(args.out, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            written += 1
    print(f"wrote {written} files for {', '.join(targets)} to {args.out}")
    return 0


def _detections_run(args, rules) -> int:
    import json
    from collections import Counter

    from rich.console import Console
    from rich.table import Table

    from .detections.replay import evtx_files, load_events, run
    from .util import iso

    files = evtx_files(args.evtx)
    if not files:
        print("usbhawk: error: no .evtx files found", file=sys.stderr)
        return 2
    drives = [d.strip() for d in args.removable_drives.split(",")] if args.removable_drives else None
    events = load_events(files, drives)
    alerts = run(rules, events)
    con = Console()
    kinds = Counter(e["_telemetry"] for e in events)
    con.print(f"[bold]{len(files)} log files[/bold], {len(events)} events: "
              + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items()))
              + f"  [dim]removable drives: {', '.join(drives) if drives else 'D:-Z: (heuristic)'}[/dim]")
    if alerts:
        t = Table(show_lines=True, header_style="bold")
        for c in ("Time (UTC)", "Hyp", "Detection", "Level", "Why"):
            t.add_column(c, overflow="fold")
        style = {"high": "bold red", "medium": "yellow", "low": "cyan", "critical": "bold red"}
        for a in alerts:
            t.add_row(iso(a["timestamp"])[:19].replace("T", " "), a["hypothesis"], a["detection"],
                      f"[{style.get(a['level'], '')}]{a['level']}[/]", a["why"][:300])
        con.print(t)
    per = Counter(a["hypothesis"] for a in alerts)
    con.print("Alerts per hypothesis: " + ", ".join(f"{r.hypothesis} {per.get(r.hypothesis, 0)}" for r in rules))
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, "alerts.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for a in alerts:
                fh.write(json.dumps({**a, "timestamp": iso(a["timestamp"])}, default=str) + "\n")
        con.print(f"wrote {len(alerts)} alerts to {path}")
    return 0


def _graph(args) -> int:
    import json

    from rich.console import Console
    from rich.table import Table

    from .graph import build_fleet, find_runs
    from .util import iso

    say = (lambda *_: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    runs = find_runs(args.runs)
    if not runs:
        print(f"usbhawk: error: no host outputs (devices.jsonl / sessions.jsonl) found under {' '.join(args.runs)}",
              file=sys.stderr)
        return 2
    say(f"usbhawk graph: {len(runs)} host output folders")
    fleet = build_fleet(runs, all_classes=args.all_classes)
    con = Console()
    style = {"high": "bold red", "medium": "yellow", "low": "cyan", "info": "dim"}

    if args.pivot:
        kind, query = args.pivot[0].lower(), " ".join(args.pivot[1:])
        if kind not in ("device", "user") or not query:
            print("usbhawk: error: pivot must be `device QUERY` or `user NAME`", file=sys.stderr)
            return 2
        hits = fleet.find_device(query) if kind == "device" else fleet.find_user(query)
        if not hits:
            con.print(f"No {kind} matching {query!r} in {len(fleet.hosts)} hosts.")
            return 1
        for c in hits:
            con.print(f"[bold]{c.label}[/bold]  [dim]{c.id} | {len(c.hosts)} host(s) | match: "
                      f"{', '.join(sorted(c.basis))} ({c.confidence})[/dim]")
            t = Table(header_style="bold")
            t.add_column("Host", no_wrap=True)                  # host names must never be split
            t.add_column("Seen (UTC)", no_wrap=True)
            for col in ("Sessions", "Users", "Top score", "Writes", "Volumes / VSN"):
                t.add_column(col, overflow="fold")
            for row in c.per_host():
                sev = row["max_severity"] or "info"
                first = (iso(row["first_seen"]) or "-")[:16].replace("T", " ")
                last = (iso(row["last_seen"]) or "-")[:16].replace("T", " ")
                note = " [red](wiped here)[/]" if row["wiped_here"] else ""
                t.add_row(row["host"] + note, first if first == last else f"{first}\n{last}", str(row["sessions"]),
                          ", ".join(row["users"]) or "-", f"[{style.get(sev, '')}]{row['max_score']} {sev}[/]",
                          str(row["writes"]), " ".join(row["volume_names"] + row["vsns"]) or "-")
            con.print(t)
        return 0

    findings = fleet.hunt(min_hosts=args.min_hosts, min_users=args.min_users, new_days=args.new_days)
    multi = sum(1 for c in fleet.clusters if len(c.hosts) > 1)
    con.print(f"[bold]Fleet[/bold] {len(fleet.hosts)} hosts, {len(fleet.clusters)} USB devices ({multi} on more "
              f"than one host), {len(fleet.users)} users, {fleet.session_count} sessions")
    if findings:
        t = Table(show_lines=True, header_style="bold")
        for col in ("Severity", "Finding", "Device", "Hosts", "Why"):
            t.add_column(col, overflow="fold")
        for f in findings:
            ev = f.evidence
            t.add_row(f"[{style[f.severity]}]{f.severity}[/]", f.rule, ev.get("label") or ev.get("device_key")
                      or ev.get("serial", "-"), str(len(ev.get("hosts", [])) or "-"), f.why)
        con.print(t)
    else:
        con.print("[green]No fleet findings.[/green]")
    for w in fleet.warnings[:10]:
        con.print(f"[dim yellow]warning:[/] {w}")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        with open(os.path.join(args.out, "findings.jsonl"), "w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(json.dumps(f.to_dict(), default=str) + "\n")
        with open(os.path.join(args.out, "graph.json"), "w", encoding="utf-8") as fh:
            json.dump(fleet.graph(), fh, indent=1, default=str)
        for name, text in (("graph.graphml", fleet.graphml()), ("graph.cypher", fleet.cypher())):
            with open(os.path.join(args.out, name), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
        say(f"wrote {len(findings)} findings and the graph (json, graphml, cypher) to {args.out}")
    return 0


HUNTS = "Hunts over offline Windows evidence: KAPE / Velociraptor triage folders or mounted images.\n"

TOP_EXAMPLES = """\
Examples:
  usbhawk sessions --triage D:\\cases\\WS042 --out out\\WS042
  usbhawk tamper   --triage D:\\cases\\WS042 --out out\\WS042
  usbhawk detections build --config config\\scoring.toml --out build
  usbhawk graph --runs out device 60A44C41

Run `usbhawk <command> --help` for its options and more examples. All timestamps are UTC.
Guides: docs/hunt-*.md. Also installed as `usbthk`, the former name.
"""

HELP = {   # command -> (description, examples / outputs / guide)
    "sessions": (
        "Which USB sessions look like data exfiltration, and why?\n\n"
        "Builds connect -> remove sessions from the registry, event logs and setupapi.dev.log, attaches users and\n"
        "file activity, and scores every session with explainable rules: each point comes with a reason.",
        "Examples:\n"
        "  usbhawk sessions --triage D:\\cases\\WS042 --out out\\WS042\n"
        "  usbhawk sessions --triage D:\\cases\\WS042 --tz America/New_York --watchlist leavers.txt --min-score 40\n"
        "  usbhawk sessions --triage D:\\cases\\WS042 --file-events mde_DeviceFileEvents.csv --out out\\WS042\n\n"
        "Output (--out): sessions.jsonl (ECS, SIEM-ready), sessions.csv, devices.jsonl\n"
        "Guide: docs/hunt-exfil-sessions.md"),
    "devices": (
        "Device inventory: the SANS FOR500 11-step profile of every USB device, one JSON line per device on\n"
        "stdout (vendor, product, serial, first/last connect, drive letter, volume name, VSN, users).",
        "Examples:\n"
        "  usbhawk devices --triage D:\\cases\\WS042\n"
        "  usbhawk devices --system SYSTEM --software SOFTWARE --ntuser NTUSER.DAT=j.doe --out out\\WS042\n\n"
        "Output (--out): devices.jsonl"),
    "tamper": (
        "Did someone wipe the USB evidence, or did Windows clean it up?\n\n"
        "Finds devices that survive in some artifacts but are gone from Enum, cleared event logs, a reset\n"
        "Partition/Diagnostic log and cleanup tools such as USBOblivion, and separates them from feature updates.",
        "Examples:\n"
        "  usbhawk tamper --triage D:\\cases\\WS042 --out out\\WS042\n"
        "  usbhawk tamper --system SYSTEM --software SOFTWARE --partition-log Partition.evtx --security-log Security.evtx\n\n"
        "Output (--out): tamper.jsonl (ECS)\n"
        "Guide: docs/hunt-usb-tamper.md"),
    "detections": (
        "Catch it live: the hunts' hypotheses H1-H8 as Sigma, Elastic (ES|QL) and Microsoft Sentinel (KQL)\n"
        "rules, generated from one YAML source per hypothesis. Thresholds and lists come from the same config\n"
        "the offline hunts use.",
        "Examples:\n"
        "  usbhawk detections list\n"
        "  usbhawk detections test\n"
        "  usbhawk detections --config config\\scoring.toml build --out build\n"
        "  usbhawk detections run --evtx D:\\cases\\WS042\\C\\Windows\\System32\\winevt\\Logs --removable-drives F:\n\n"
        "Guide: docs/hunt-detection-rules.md"),
    "graph": (
        "Where else has this stick been, and who else used it?\n\n"
        "Links the per-host outputs of `usbhawk sessions/tamper --out` from many hosts into one graph of devices,\n"
        "hosts, users and volumes, then hunts across it. Each finding says how the stick was matched: real\n"
        "serial (high), shared volume serial (medium) or volume name + capacity (low).",
        "Examples:\n"
        "  usbhawk graph --runs out --out fleet\n"
        "  usbhawk graph --runs out device 60A44C41\n"
        "  usbhawk graph --runs out user j.doe\n"
        "  usbhawk graph --runs out\\NW-* --min-hosts 2 --new-days 14\n\n"
        "Output (--out): findings.jsonl (ECS), graph.json, graph.graphml (Gephi / yEd), graph.cypher (Neo4j)\n"
        "Guide: docs/hunt-fleet-device-graph.md"),
}


def _command(sub, name: str, short: str):
    description, epilog = HELP[name]
    return sub.add_parser(name, help=short, description=description, epilog=epilog,
                          formatter_class=argparse.RawDescriptionHelpFormatter)


def main(argv=None) -> int:
    from .banner import banner, show_banner

    ap = argparse.ArgumentParser(prog="usbhawk", description=banner() + "\n" + HUNTS, epilog=TOP_EXAMPLES,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"usbhawk {__version__}")
    sub = ap.add_subparsers(dest="cmd", metavar="<command>", title="commands")

    sp = _command(sub, "sessions", "Which USB sessions look like data exfiltration, and why?")
    _common(sp)
    sp.add_argument("--config", help="scoring TOML (see config/scoring.toml)")
    sp.add_argument("--tz", help="IANA timezone for work hours, e.g. America/New_York "
                                 "(default: config file, else the host's registry time zone, else UTC)")
    sp.add_argument("--watchlist", help="text file of usernames (e.g. leavers list)")
    sp.add_argument("--allowlist", help="text file of approved device serials")
    sp.add_argument("--min-score", type=int, default=0)
    sp.add_argument("--all-classes", action="store_true", help="include HID/hubs/etc., not just storage")
    sp.add_argument("--limit", type=int, default=50, help="rows to print")

    tp = _command(sub, "tamper", "Did someone wipe the USB evidence, or did Windows clean it up?")
    _common(tp)

    dp2 = _command(sub, "detections", "Catch it live: the same hypotheses as Sigma, Elastic, Sentinel rules")
    dp2.add_argument("--config", help="scoring TOML: thresholds, archive extensions and work hours for the rules "
                                      "(same file as `usbhawk sessions --config`)")
    dsub = dp2.add_subparsers(dest="action", required=True, metavar="<action>")
    raw = argparse.RawDescriptionHelpFormatter
    dsub.add_parser("list", help="show the rules and their detections", formatter_class=raw,
                    epilog="Examples:\n  usbhawk detections list")
    dsub.add_parser("test", help="validate every rule and run its built-in test events", formatter_class=raw,
                    epilog="Examples:\n  usbhawk detections test\n  usbhawk detections --config my_scoring.toml test")
    db = dsub.add_parser("build", help="generate deployable rules", formatter_class=raw,
                         description="Generate rules for Sigma, Elastic (ES|QL + Kibana import file) and Sentinel (KQL).",
                         epilog="Examples:\n"
                                "  usbhawk detections build --out build\n"
                                "  usbhawk detections build --target elastic --out build\n"
                                "  usbhawk detections --config config\\scoring.toml build --target sentinel\n\n"
                                "Output: build/sigma/*.yml, build/elastic/*.esql + usbhawk_rules.ndjson "
                                "(Kibana > Security > Rules > Import), build/sentinel/*.kql")
    db.add_argument("--target", default="all", choices=["all", "sigma", "elastic", "sentinel"])
    db.add_argument("--out", default="build", help="output folder (default: build)")
    dr = dsub.add_parser("run", help="replay real event logs (Sysmon, Security, System .evtx) through the rules",
                         formatter_class=raw,
                         description="Replay collected .evtx files through every rule: proves the rules on real "
                                     "telemetry, or hunts a triage with them.",
                         epilog="Examples:\n"
                                "  usbhawk detections run --evtx D:\\triage\\C\\Windows\\System32\\winevt\\Logs\n"
                                "  usbhawk detections run --evtx Sysmon.evtx Security.evtx --removable-drives F: "
                                "--out alerts\n\n"
                                "Output (--out): alerts.jsonl")
    dr.add_argument("--evtx", nargs="+", required=True, metavar="PATH", help=".evtx files or folders (recursive)")
    dr.add_argument("--removable-drives", metavar="F:,H:",
                    help="drive letters that are USB media (default: D: to Z:, the rules' heuristic)")
    dr.add_argument("--out", help="folder for alerts.jsonl")

    gp = _command(sub, "graph", "Where else has this stick been, and who else used it? (many hosts)")
    gp.add_argument("--runs", nargs="+", required=True, metavar="PATH",
                    help="host output folders, a parent folder of them, or a wildcard (out\\*)")
    gp.add_argument("--out", help="folder for findings.jsonl, graph.json, graph.graphml, graph.cypher")
    gp.add_argument("--min-hosts", type=int, default=3, help="device_on_many_hosts threshold (default 3)")
    gp.add_argument("--min-users", type=int, default=2, help="device_shared_by_users threshold (default 2)")
    gp.add_argument("--new-days", type=int, default=30, help="new_to_fleet window in days (default 30)")
    gp.add_argument("--all-classes", action="store_true", help="include non-storage devices (hubs, HID...)")
    gp.add_argument("-q", "--quiet", action="store_true")
    gp.add_argument("pivot", nargs="*", metavar="device QUERY | user NAME",
                    help="show one stick across the fleet (serial, key, VSN, name) or everything one user touched")

    dp = _command(sub, "devices", "Device inventory: the FOR500 11-step profile of every USB device")
    _common(dp)

    args = ap.parse_args(argv)
    if args.cmd is None:                     # bare `usbhawk`: show the banner and what it can do
        ap.print_help()
        return 0
    show_banner(quiet=getattr(args, "quiet", False))
    if args.cmd == "detections":
        return _detections(args)
    if args.cmd == "graph":
        return _graph(args)
    logging.basicConfig(level=logging.WARNING)
    logging.getLogger("regipy").setLevel(logging.CRITICAL)  # noisy about undecodable REG_SZ
    say = (lambda *_: None) if args.quiet else (lambda m: print(m, file=sys.stderr))

    arts = _artifacts(args)
    if not any(arts.summary().values()):
        ap.error("no artifacts found - pass --triage or individual artifact paths")
    say(f"usbhawk {__version__}: loading artifacts")
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
        print(f"usbhawk: error: {exc}", file=sys.stderr)
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
