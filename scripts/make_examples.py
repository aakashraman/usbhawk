"""Regenerate the fictional demo data in examples/ (committed; every file is backed by a test).

    python scripts/make_examples.py

  examples/fleet/<HOST>/       devices.jsonl, sessions.jsonl, tamper.jsonl for four fictional hosts, written by the
                               REAL module #2/#3 writers (the same fleet docs/hunt-fleet-device-graph.md documents)
  examples/detections/         insider_timeline.jsonl: the Friday-evening insider timeline from
                               docs/hunt-detection-rules.md, as neutral events (`detections run --events`)

The builders live with their tests (tests/hunt_*/), so the demo data, the documentation and the tests can never
drift apart: tests/examples_demo/test_examples_demo.py fails if a committed file differs from what this writes.
All values are fictional (hosts NW-*, users NW\\j.doe, NW\\a.smith, NW\\k.lee, NW\\m.ortiz, invented serials).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
sys.path[:0] = [str(ROOT / "tests" / "hunt_fleet_device_graph"), str(ROOT / "tests" / "hunt_detection_rules")]


def _event_line(e: dict) -> str:
    row = {k: v for k, v in e.items() if v is not None}
    row["timestamp"] = e["timestamp"].isoformat().replace("+00:00", "Z")
    order = ["timestamp", "_telemetry"] + sorted(k for k in row if k not in ("timestamp", "_telemetry"))
    return json.dumps({k: row[k] for k in order}, ensure_ascii=False)


def write_fleet(dest: Path) -> list[str]:
    from test_fleet_sample_fleet import documented_fleet
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
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


def generate(root: Path = EXAMPLES) -> None:
    hosts = write_fleet(root / "fleet")
    n = write_timeline(root / "detections" / "insider_timeline.jsonl")
    print(f"fleet:      {len(hosts)} hosts -> {os.path.relpath(root / 'fleet', ROOT)} ({', '.join(hosts)})")
    print(f"detections: {n} events -> {os.path.relpath(root / 'detections' / 'insider_timeline.jsonl', ROOT)}")


if __name__ == "__main__":
    generate()
