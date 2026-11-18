"""Regenerate the fictional demo data in examples/ (committed; every file is backed by a test).

    python scripts/make_examples.py

  examples/graph/fleet/<HOST>/ devices.jsonl, sessions.jsonl, tamper.jsonl for four fictional hosts, written by the
                               REAL module #2/#3 writers (the same fleet docs/hunt-fleet-device-graph.md documents)
  examples/detections/         insider_timeline.jsonl: the Friday-evening insider timeline from
                               docs/hunt-detection-rules.md, as neutral events (`detections run --events`)
  examples/tamper/wiped-host/  a triage folder of a host wiped with USBOblivion, as REAL artifacts: registry hives
                               (regf) and an emptied Partition/Diagnostic log (evtx), written by
                               tests/hunt_usb_tamper/wiped_host_builder.py (byte-for-byte deterministic)

The builders live with their tests (tests/hunt_*/), so the demo data, the documentation and the tests can never
drift apart: tests/examples_demo/test_examples_demo.py fails if a committed file differs from what this writes.
All values are fictional (hosts NW-*, users NW\\j.doe, NW\\a.smith, NW\\k.lee, NW\\m.ortiz, invented serials).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
sys.path[:0] = [str(ROOT / "tests" / "hunt_fleet_device_graph"), str(ROOT / "tests" / "hunt_detection_rules"),
                str(ROOT / "tests" / "hunt_usb_tamper")]


def _event_line(e: dict) -> str:
    row = {k: v for k, v in e.items() if v is not None}
    row["timestamp"] = e["timestamp"].isoformat().replace("+00:00", "Z")
    order = ["timestamp", "_telemetry"] + sorted(k for k in row if k not in ("timestamp", "_telemetry"))
    return json.dumps({k: row[k] for k in order}, ensure_ascii=False)


def _clear(dest: Path) -> None:
    """Delete the generated files under dest. Folders are kept: OneDrive or an open Explorer window can hold a
    folder open on Windows, and builders recreate what they need with mkdir(exist_ok=True)."""
    if dest.exists():
        for f in dest.rglob("*"):
            if f.is_file():
                f.unlink()
        for d in sorted((d for d in dest.rglob("*") if d.is_dir()), key=lambda d: -len(d.parts)):
            try:
                d.rmdir()                      # empty folders left by an older layout; fine if it is held open
            except OSError:
                pass
    dest.mkdir(parents=True, exist_ok=True)


def write_fleet(dest: Path) -> list[str]:
    from test_fleet_sample_fleet import documented_fleet
    _clear(dest)
    documented_fleet(dest)
    return sorted(p.name for p in dest.iterdir())


def write_timeline(dest: Path) -> int:
    from test_detection_sample_timeline import timeline
    dest.parent.mkdir(parents=True, exist_ok=True)
    events = timeline()
    with open(dest, "w", encoding="utf-8", newline="\n") as fh:
        for e in events:
            fh.write(_event_line(e) + "\n")
    return len(events)


def write_wiped_host(dest: Path) -> list[str]:
    from wiped_host_builder import build_wiped_host
    _clear(dest)
    return build_wiped_host(dest)


def generate(root: Path = EXAMPLES) -> None:
    hosts = write_fleet(root / "graph" / "fleet")
    n = write_timeline(root / "detections" / "insider_timeline.jsonl")
    print(f"fleet:      {len(hosts)} hosts -> {os.path.relpath(root / 'graph' / 'fleet', ROOT)} ({', '.join(hosts)})")
    print(f"detections: {n} events -> {os.path.relpath(root / 'detections' / 'insider_timeline.jsonl', ROOT)}")
    wiped = write_wiped_host(root / "tamper" / "wiped-host")
    print(f"tamper:     {len(wiped)} files -> {os.path.relpath(root / 'tamper' / 'wiped-host', ROOT)}")


if __name__ == "__main__":
    generate()
