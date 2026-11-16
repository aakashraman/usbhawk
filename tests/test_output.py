"""Output contract: the fields Splunk/Elastic searches and dashboards will depend on.

If one of these tests breaks, a downstream SIEM query probably breaks too - change both together.
"""

import csv
import json

from usbthk.output import session_to_ecs, write_csv, write_jsonl
from usbthk.parsers.file_events import load_file_events
from usbthk.scoring import load_config, score_sessions
from usbthk.sessions import build_sessions

from test_sessions_scoring import scenario, write_mde_csv

CSV_COLUMNS = ["score", "severity", "host", "start_utc", "end_utc", "duration_min", "device_class",
               "vendor", "product", "serial", "volume_names", "drive_letters", "vsns", "users",
               "file_writes", "first_seen", "reasons", "session_id"]


def scored(tmp_path):
    ev, _ = scenario()
    load_file_events(write_mde_csv(tmp_path), ev)
    cfg = load_config(timezone="America/New_York", watchlist_users=["j.doe"], work_hours={"end_hour": 17})
    return score_sessions(build_sessions(ev), cfg)


def test_ecs_document_has_siem_fields(tmp_path):
    doc = session_to_ecs(scored(tmp_path)[0])
    assert doc["@timestamp"] == "2026-10-30T21:14:52Z"
    e = doc["event"]
    assert e["dataset"] == "usbthk.session" and e["kind"] == "event"
    assert e["start"] == "2026-10-30T21:14:52Z" and e["end"] == "2026-10-30T21:41:07Z"
    assert e["duration"] == (26 * 60 + 15) * 10**9          # ECS duration is nanoseconds
    assert e["risk_score"] == 100 and e["severity_label"] == "high"
    assert doc["host"]["name"] == "NW-FIN-WS042"
    assert doc["user"]["name"] == "NW\\j.doe"
    dev = doc["usb"]["device"]
    assert dev["serial"] == "60A44C413D5FF380E95A0B7D" and dev["vid"] == "0951" and dev["pid"] == "1666"
    u = doc["usbthk"]
    assert len(u["session_id"]) == 16
    assert {r["rule"] for r in u["reasons"]} >= {"first_seen_device", "bulk_transfer", "archive_written"}
    assert u["file_activity"]["writes"] == 61
    assert u["file_activity"]["bytes_written"] == 60 * 12_000_000 + 900_000_000
    assert u["vsns"] == ["8E2C41D7", "11223344"]


def test_all_timestamps_are_utc_z(tmp_path):
    doc = session_to_ecs(scored(tmp_path)[0])
    for ts in (doc["@timestamp"], doc["event"]["start"], doc["event"]["end"]):
        assert ts.endswith("Z")


def test_jsonl_one_valid_document_per_session(tmp_path):
    sessions = scored(tmp_path)
    path = tmp_path / "sessions.jsonl"
    write_jsonl(sessions, str(path))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == len(sessions)
    assert all(json.loads(line)["event"]["dataset"] == "usbthk.session" for line in lines)


def test_csv_columns_and_reason_format(tmp_path):
    sessions = scored(tmp_path)
    path = tmp_path / "sessions.csv"
    write_csv(sessions, str(path))
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == CSV_COLUMNS
    row = dict(zip(rows[0], rows[1]))
    assert row["score"] == "100" and row["severity"] == "high"
    assert row["duration_min"] == "26.2"
    assert "first_seen_device(+25)" in row["reasons"]
    assert row["vsns"] == "8E2C41D7;11223344"


def test_session_id_is_stable_across_runs(tmp_path):
    """Same evidence -> same id, so re-running a case does not create duplicate SIEM records."""
    a = scored(tmp_path)[0].session_id
    b = scored(tmp_path)[0].session_id
    assert a == b
