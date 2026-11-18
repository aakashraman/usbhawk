"""Smoke-test a built USBHawk (the standalone exe or a wheel install) as a user would run it.

    python scripts/smoke_test.py --usbhawk dist\\usbhawk-1.0.0-windows-x64\\usbhawk.exe --examples examples
    python scripts/smoke_test.py --usbhawk .venv-wheel\\Scripts\\usbhawk.exe --examples examples --triage tests\\data

Runs every demo command from a scratch folder outside the repository (so nothing is imported from the source tree)
and checks exit codes and the documented results. Exit code 0 only if every check passes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FLEET_RULES = {"wiped_here_seen_there", "exfil_device_spread", "device_on_many_hosts", "device_shared_by_users",
               "new_to_fleet", "serial_collision"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--usbhawk", required=True, help="the usbhawk executable to test")
    ap.add_argument("--examples", required=True, help="the examples folder")
    ap.add_argument("--triage", help="optional triage folder (e.g. tests/data) for sessions / devices / tamper")
    ap.add_argument("--version", help="expected version (default: any)")
    args = ap.parse_args(argv)

    exe = str(Path(args.usbhawk).resolve())
    ex = Path(args.examples).resolve()
    failures: list[str] = []
    work = Path(tempfile.mkdtemp(prefix="usbhawk-smoke-"))

    def run(name, argv, expect=(), banner=False, code=0):
        env = {**os.environ, "COLUMNS": "160", "PYTHONIOENCODING": "utf-8"}
        env.pop("USBHAWK_NO_BANNER", None)
        if not banner:
            env["USBHAWK_NO_BANNER"] = "1"
        p = subprocess.run([exe, *argv], cwd=work, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=env, timeout=600)
        text = p.stdout + p.stderr
        missing = [e for e in expect if e not in text]
        ok = p.returncode == code and not missing
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            failures.append(name)
            print(f"       exit {p.returncode} (want {code}); missing {missing}\n       {text[-1500:]}")
        return p

    print(f"smoke test: {exe}\n  scratch folder: {work}")
    v = run("--version", ["--version"], [f"usbhawk {args.version}" if args.version else "usbhawk "])
    run("help with banner", [], ["USB forensics for threat hunting", "sessions", "graph"], banner=True)
    run("detections list", ["detections", "list"], ["H1", "H8"])
    run("detections test", ["detections", "test"], ["8 rules, 12 detections", "all passed"])
    run("detections build", ["detections", "build", "--out", "rules"], ["sigma, elastic, sentinel"])
    built = [p for p in (work / "rules").rglob("*") if p.is_file()]
    if len(built) < 30:
        failures.append(f"detections build wrote only {len(built)} files")
    run("detections run --events", ["detections", "run", "--events", str(ex / "detections" / "insider_timeline.jsonl"),
                                    "--out", "alerts"],
        ["Alerts per hypothesis: H1 2, H2 1, H3 1, H4 1, H5 1, H6 1, H7 2, H8 1"])
    run("graph", ["graph", "--runs", str(ex / "graph" / "fleet"), "--out", "fleet"], ["Fleet 4 hosts, 6 USB devices"])
    findings = work / "fleet" / "findings.jsonl"
    rules = {json.loads(x)["usbhawk"]["rule"] for x in findings.read_text(encoding="utf-8").splitlines()} \
        if findings.exists() else set()
    if rules != FLEET_RULES:
        failures.append(f"graph findings {sorted(rules)}")
    run("graph device pivot", ["graph", "--runs", str(ex / "graph" / "fleet"), "device", "60A44C41"],
        ["match: serial (high)", "NW-ENG-LT113"])
    run("graph user pivot", ["graph", "--runs", str(ex / "graph" / "fleet"), "user", "a.smith"], ["SanDisk Ultra"])
    run("graph missing path", ["graph", "--runs", "no-such-folder"], ["--runs path not found"], code=2)
    run("missing config", ["detections", "--config", "typo.toml", "test"], ["config file not found"], code=2)
    if args.triage and Path(args.triage).is_dir():
        t = str(Path(args.triage).resolve())
        run("sessions", ["sessions", "--triage", t, "--tz", "America/New_York", "--out", "host"], ["Host "])
        run("devices", ["devices", "--triage", t], ['"key": "VID_'])
        run("tamper", ["tamper", "--triage", t, "--out", "host"], ["Host "])
    elif args.triage:
        print(f"  skip sessions / devices / tamper: {args.triage} not found")

    print(f"{'PASSED' if not failures else 'FAILED'}: {len(failures)} failure(s)" + (f": {failures}" if failures else ""))
    if not failures:
        shutil.rmtree(work, ignore_errors=True)         # keep the scratch folder only to debug a failure
    return 0 if not failures and v.returncode == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
