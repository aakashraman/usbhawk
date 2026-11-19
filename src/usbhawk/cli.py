"""USBHawk command line: one tool, five commands (sessions, devices, tamper, detections, graph).

  usbhawk --help                       banner, the hunts, examples
  usbhawk <command> --help             what the command answers, options, examples, outputs, guide
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys

from . import __version__
from .collect import ArtifactSet, discover, load
from .output import (ensure_dir, print_findings, print_sessions, write_csv, write_devices, write_findings,
                     write_jsonl)
from .scoring import apply_host_timezone, load_config, score_sessions
from .sessions import build_sessions
from .tamper import find_tamper, host_mismatch_findings


DISK_IMAGE_EXTS = (".vhdx", ".vhd", ".e01", ".ex01", ".dd", ".raw", ".img", ".001", ".vmdk", ".aff4")


def _disk_image_hint(path: str) -> str:
    """What to say when a file, not a folder, is passed where a collection folder belongs."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in DISK_IMAGE_EXTS:
        return (f"usbhawk: error: {path} is a file; --triage needs the collection FOLDER (a KAPE --tdest, an "
                f"extracted Velociraptor collection, or a mounted drive such as F:\\)")
    if ext in (".vhdx", ".vhd"):
        steps = ("  Mount it read-only first (PowerShell as administrator):\n"
                 f"    Mount-DiskImage -ImagePath \"{os.path.abspath(path)}\" -Access ReadOnly\n"
                 "    Get-DiskImage -ImagePath \"<same path>\" | Get-Disk | Get-Partition | Get-Volume   # drive letter\n"
                 "  then run:  usbhawk sessions --triage F:\\   (use the letter Windows gave it)\n"
                 "  and when done:  Dismount-DiskImage -ImagePath \"<same path>\"")
    else:
        steps = ("  Mount it read-only first with a forensic mounter (Arsenal Image Mounter, FTK Imager\n"
                 "  'Mount Image', or on Linux ewfmount / mount -o ro,loop), or export the triage files with\n"
                 "  KAPE (--msource <mounted drive>), then run:  usbhawk sessions --triage F:\\")
    return (f"usbhawk: error: {path} is a disk image ({ext}); USBHawk reads files, not images.\n{steps}")


_EVIDENCE_FLAGS = (("system", "--system"), ("software", "--software"), ("ntuser", "--ntuser"),
                   ("partition_log", "--partition-log"), ("security_log", "--security-log"),
                   ("system_log", "--system-log"), ("setupapi", "--setupapi"), ("file_events", "--file-events"))


def _missing_evidence_paths(args) -> str | None:
    """A file named on the command line must exist: running on without it gives a confident but wrong answer.
    Real case: `--system clean-hives\\SYSTEM` after rla.exe, which names its output
    `F_C_Windows_System32_config_SYSTEM`; the run went on without SYSTEM as "unknown-host" and skipped every orphan
    check. The error suggests files in that folder whose name ends with the one asked for (rla's naming)."""
    lines: list[str] = []
    rla_named = False
    for attr, flag in _EVIDENCE_FLAGS:
        value = getattr(args, attr, None)
        for item in ([value] if isinstance(value, str) else value or []):
            path = item.partition("=")[0] if attr == "ntuser" else item
            if os.path.isfile(path):
                continue
            lines.append(f"usbhawk: error: {flag} file not found: {path}")
            folder, name = os.path.split(os.path.abspath(path))
            try:
                near = sorted(f for f in os.listdir(folder)
                              if f.upper().endswith(name.upper()) and os.path.isfile(os.path.join(folder, f)))
            except OSError:
                near = []
            for f in near[:5]:
                lines.append(f"  did you mean: {flag} \"{os.path.join(folder, f)}\"")
            rla_named = rla_named or any("_" in f for f in near)
    if rla_named:
        lines.append("  (rla.exe names a replayed hive after its source path, e.g. F_C_Windows_System32_config_SYSTEM)")
    return "\n".join(lines) or None


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
    if not os.path.isfile(path):
        raise ValueError(f"list file not found: {path}")
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
        cfg = load_config(args.config, timezone=getattr(args, "tz", None))
        if args.action == "run" and getattr(args, "evtx", None):
            cfg = _host_work_hours(cfg, args.evtx)
        rules = load_rules(cfg=cfg)
    except ValueError as exc:
        print(f"usbhawk: error: {exc}", file=sys.stderr)
        return 2
    args.work_hours = cfg["work_hours"]
    if args.action == "list":
        from rich.console import Console
        from rich.table import Table
        t = Table(header_style="bold")
        for c in ("Hypothesis", "Rule", "Detections (level)", "ATT&CK", "Offline hunt (usbhawk)"):
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


_DEVICE_PATH = re.compile(r"(?:USBSTOR|USB|SCSI)\\[^\\\s;]+\\([^\\\s;]+)", re.I)


PAIR_WINDOW_S = 30   # USB node and disk 6416 of one plug-in: same second for a stick, 5 s for a spinning disk


def _pair_plug_ins(alerts: list[dict]) -> list[tuple[dict, int]]:
    r"""[(alert, how many alerts it stands for)]: one row per plug-in. Windows writes Security 6416 for the USB
    device (USB\VID_..\SERIAL) and again for its disk (USBSTOR\Disk..\SERIAL&0), so H1 and H2 fire twice per
    plug-in (real case: 58 H1 alerts for 29 plug-ins). The two are usually in the same second, but an external
    hard disk can take a few seconds to spin up (real case: an external USB 3.0 disk, 5 s), so the same rule on the
    same serial pairs within PAIR_WINDOW_S, and a row never holds two USB nodes or two disks (two plug-ins).
    The disk's alert, which names vendor and product, is kept; alerts.jsonl is not touched."""
    from .util import strip_lun, to_utc
    groups: list[dict] = []
    open_by_key: dict = {}
    for a in alerts:
        why = a.get("why") or ""
        m = _DEVICE_PATH.search(why)
        ts = to_utc(a.get("timestamp"))
        if not m or ts is None:
            groups.append({"kept": a, "n": 1})
            continue
        part = "disk" if m.group(0).upper().startswith(("USBSTOR", "SCSI")) else "node"
        key = (a["hypothesis"], a["detection"], strip_lun(m.group(1)).upper())
        g = open_by_key.get(key)
        if g and part not in g["parts"] and abs((ts - g["ts"]).total_seconds()) <= PAIR_WINDOW_S:
            g["parts"].add(part)
            g["n"] += 1
            if part == "disk":
                g["kept"] = a
            continue
        g = {"kept": a, "n": 1, "ts": ts, "parts": {part}}
        open_by_key[key] = g
        groups.append(g)
    return [(g["kept"], g["n"]) for g in groups]


def _host_work_hours(cfg: dict, paths: list[str]) -> dict:
    """H2 (off hours) is judged on the host's clock, as `sessions` does: without --tz or a config time zone, use the
    time zone in the SYSTEM hive found next to the logs (a KAPE / Velociraptor triage or a mounted image).
    Real case: replaying a triage judged H2 in UTC and missed a 07:02 New York connection that `sessions` flagged."""
    from .parsers.registry import read_timezone_key
    from .scoring import apply_host_timezone
    if cfg["work_hours"].get("timezone_source", "default") != "default":
        return cfg
    for p in paths:
        if os.path.isdir(p):
            arts = discover(p)
            key = read_timezone_key(arts.system) if arts.system else None
            if key:
                out, _warning = apply_host_timezone(cfg, key)
                return out
    return cfg


def _detections_run(args, rules) -> int:
    import json
    from collections import Counter

    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    from .detections.replay import TELEMETRY_SOURCES, coverage_gaps, evtx_files, load_events, load_events_jsonl, run
    from .util import iso

    drives = [d.strip() for d in args.removable_drives.split(",")] if args.removable_drives else None
    if args.events:
        files = list(args.events)
        try:
            events = load_events_jsonl(files)
        except (OSError, ValueError) as exc:
            print(f"usbhawk: error: {exc}", file=sys.stderr)
            return 2
        source = "event files (JSONL)"
    else:
        for p in args.evtx:
            if os.path.isfile(p) and os.path.splitext(p)[1].lower() in DISK_IMAGE_EXTS:
                print(_disk_image_hint(p).replace("usbhawk sessions --triage", "usbhawk detections run --evtx"),
                      file=sys.stderr)
                return 2
        files = evtx_files(args.evtx)
        if not files:
            print("usbhawk: error: no .evtx files found", file=sys.stderr)
            return 2
        errors: list = []
        damaged: list = []
        events = load_events(files, drives, errors, damaged)
        source = "log files"
        for f, skipped, read, first in damaged[:5]:
            print(f"  damaged {f}: {skipped} chunk(s)/record(s) skipped, {read} records read around them "
                  f"({first[:120]})", file=sys.stderr)
        if len(damaged) > 5:
            print(f"  ... and {len(damaged) - 5} more damaged files (read around the damage)", file=sys.stderr)
        if errors:
            denied = any("PermissionError" in m or "Access is denied" in m for _f, m in errors)
            for f, msg in errors[:5]:
                print(f"  skipped {f}: {msg}", file=sys.stderr)
            if len(errors) > 5:
                print(f"  ... and {len(errors) - 5} more", file=sys.stderr)
            hint = (" Live logs need an elevated (Administrator) prompt, or export them first: "
                    "wevtutil epl Security Security.evtx (see scripts\\collect_local.ps1)." if denied else "")
            if len(errors) == len(files):
                print(f"usbhawk: error: none of the {len(files)} log files could be read.{hint}", file=sys.stderr)
                return 2
            print(f"warning: {len(errors)} of {len(files)} log files could not be read and were skipped.{hint}",
                  file=sys.stderr)
            source = f"log files ({len(errors)} unreadable, skipped)"
    alerts = run(rules, events)
    con = Console()
    kinds = Counter(e["_telemetry"] for e in events)
    wh = args.work_hours
    zone = wh.get("timezone", "UTC")
    origin = {"default": "default: no --tz, config or host hive found", "--tz": "from --tz",
              "config": "from --config"}.get(wh.get("timezone_source", "default"), f"from {wh.get('timezone_source')}")
    con.print(f"[dim]H2 work hours {wh['start_hour']:02d}:00-{wh['end_hour']:02d}:00 {zone} ({origin}); "
              f"all timestamps are UTC[/dim]")
    if wh.get("timezone_source", "default") == "default":
        con.print("[yellow]warning:[/yellow] off hours (H2) are judged in UTC; pass --tz with the user's time zone "
                  "(e.g. --tz America/New_York)" + ("" if args.events else
                  ", or point --evtx at a triage folder that contains the SYSTEM hive"))
    con.print(f"[bold]{len(files)} {source}[/bold], {len(events)} events: "
              + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items()))
              + ("" if args.events else
                 f"  [dim]removable drives: {', '.join(drives) if drives else 'D:-Z: (heuristic)'}[/dim]"))
    style = {"high": "bold red", "medium": "yellow", "low": "cyan", "critical": "bold red"}
    rows = _pair_plug_ins(alerts)
    if alerts:
        t = Table(show_lines=True, header_style="bold")
        for c in ("Event Timestamp (UTC)", "Hypothesis", "Detection", "Level", "Description"):
            t.add_column(c, overflow="fold")
        for a, n in rows:
            why = escape(a["why"][:300] + (" [the same plug-in is logged again for its USB device node]"
                                           if n > 1 else ""))      # rich would read [..] as markup and drop it
            t.add_row(iso(a["timestamp"])[:19].replace("T", " "), a["hypothesis"], a["detection"],
                      f"[{style.get(a['level'], '')}]{a['level']}[/]", why)
        con.print(t)
    per = Counter(a["hypothesis"] for a in alerts)
    con.print("Alerts per hypothesis: " + ", ".join(f"{r.hypothesis} {per.get(r.hypothesis, 0)}" for r in rules))
    if len(rows) < len(alerts):
        con.print(f"[dim]Shown as {len(rows)} rows: Windows logs each USB plug-in twice (Security 6416 for the USB "
                  f"device and for its disk), and each pair is one row here; alerts.jsonl keeps both, as a live "
                  f"rule would.[/dim]")
    if alerts:
        # Triage order: the table is a timeline; this says where to start reading it.
        con.print("[bold]Look at first[/bold] (by level, then time):")
        for level in ("critical", "high", "medium", "low", "informational"):
            group: dict[tuple, list] = {}
            for a, _n in rows:
                if a["level"] == level:
                    group.setdefault((a["hypothesis"], a["detection"]), []).append(a["timestamp"])
            if group:
                def when(ts):   # full date: alerts of one detection can span weeks
                    first, last = (iso(min(ts))[:19].replace("T", " "), iso(max(ts))[:19].replace("T", " "))
                    return f"at {first}" if first == last else f"{first} to {last}"
                items = [f"{h} {d}" + (f" x{len(ts)}" if len(ts) > 1 else "") + f" ({when(ts)})"
                         for (h, d), ts in sorted(group.items(), key=lambda kv: min(kv[1]))]
                con.print(f"  [{style.get(level, '')}]{level:<7}[/] " + "; ".join(items))
        con.print("  Then read the table top to bottom as one story: the device (H1, H2), the copying (H3, H4), the "
                  "cleanup (H5-H8). `usbhawk detections list` explains every hypothesis.")
    gaps = coverage_gaps(rules, events)
    if gaps:
        con.print("[yellow]Telemetry gaps:[/yellow] these hypotheses could not fire, because the logs hold no events "
                  "of the kind they need (zero alerts here means no telemetry, not no activity):")
        for tel, hyps in gaps:
            con.print(f"  {', '.join(hyps)}: no {tel} events (from {TELEMETRY_SOURCES.get(tel, tel)})")
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, "alerts.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for a in alerts:
                fh.write(json.dumps({**a, "timestamp": iso(a["timestamp"])}, default=str) + "\n")
        con.print(f"wrote {len(alerts)} alerts to {path}")
    return 0


def _split_pivot(args) -> None:
    """`--runs out device 60A44C41`: --runs takes several paths, so argparse hands it the pivot words too.

    The first `device` / `user` that is not an existing path starts the pivot (a folder really named `device`
    still works as a run path).
    """
    if args.pivot:
        return
    for i, p in enumerate(args.runs[1:], 1):
        if p.lower() in ("device", "user") and not os.path.exists(p):
            args.runs, args.pivot = args.runs[:i], args.runs[i:]
            return


def _graph(args) -> int:
    import json

    from rich.console import Console
    from rich.markup import escape
    from rich.table import Table

    from .graph import build_fleet, find_runs
    from .util import iso

    say = (lambda *_: None) if args.quiet else (lambda m: print(m, file=sys.stderr))
    _split_pivot(args)
    missing = [p for p in args.runs if not any(ch in p for ch in "*?[") and not os.path.exists(p)]
    if missing:
        print(f"usbhawk: error: --runs path not found: {', '.join(missing)}", file=sys.stderr)
        return 2
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
            t.add_column("First / Last Seen (UTC)", no_wrap=True)
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
            gone = sorted(c.wiped_on - c.hosts)        # a wiped host has no records left, so it has no row above
            if gone:
                con.print(f"[red]Also wiped from the registry on {', '.join(gone)}[/red] (usbhawk tamper): the "
                          f"history above is what the wipe there tried to hide.")
        return 0

    findings = fleet.hunt(min_hosts=args.min_hosts, min_users=args.min_users, new_days=args.new_days)
    multi = sum(1 for c in fleet.clusters if len(c.hosts) > 1)
    con.print(f"[bold]Fleet[/bold] {len(fleet.hosts)} hosts, {len(fleet.clusters)} USB devices ({multi} on more "
              f"than one host), {len(fleet.users)} users, {fleet.session_count} sessions")
    if findings:
        t = Table(show_lines=True, header_style="bold")
        for col in ("Severity", "Finding", "Device", "Hosts", "Description"):
            t.add_column(col, overflow="fold")
        for f in findings:
            ev = f.evidence
            t.add_row(f"[{style[f.severity]}]{f.severity}[/]", f.rule, escape(ev.get("label") or ev.get("device_key")
                      or ev.get("serial", "-")), str(len(ev.get("hosts", [])) or "-"), escape(f.why))
        con.print(t)
    else:
        con.print("[green]No fleet findings.[/green]")
    for w in fleet.warnings[:10]:
        con.print(f"[dim yellow]warning:[/] {escape(w)}")
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
Guides: docs/hunt-*.md.
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
        "Device inventory: the classic 11-step profile of every USB device, one JSON line per device on\n"
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
                                "  usbhawk detections run --evtx F:\\   (a mounted KAPE VHDX: H2 uses the host's "
                                "time zone)\n"
                                "  usbhawk detections run --evtx Sysmon.evtx Security.evtx --removable-drives F: "
                                "--out alerts\n\n"
                                "Output (--out): alerts.jsonl")
    src = dr.add_mutually_exclusive_group(required=True)
    src.add_argument("--evtx", nargs="+", metavar="PATH", help=".evtx files or folders (recursive)")
    src.add_argument("--events", nargs="+", metavar="JSONL",
                     help="neutral events, one JSON object per line (see examples/detections/)")
    dr.add_argument("--removable-drives", metavar="F:,H:",
                    help="drive letters that are USB media (default: D: to Z:, the rules' heuristic)")
    dr.add_argument("--out", help="folder for alerts.jsonl")
    dr.add_argument("--tz", help="IANA time zone for the off-hours rule (H2), e.g. America/New_York (default: the "
                                 "config, else the SYSTEM hive found under --evtx, else UTC)")

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

    dp = _command(sub, "devices", "Device inventory: the classic 11-step profile of every USB device")
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

    if args.triage and os.path.isfile(args.triage):
        print(_disk_image_hint(args.triage), file=sys.stderr)
        return 2
    if args.triage and not os.path.isdir(args.triage):
        print(f"usbhawk: error: --triage folder not found: {args.triage} (point it at the collection folder: a KAPE "
              f"--tdest, an extracted Velociraptor collection, or a mounted drive such as F:\\)", file=sys.stderr)
        return 2
    missing = _missing_evidence_paths(args)
    if missing:
        print(missing, file=sys.stderr)
        return 2
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
