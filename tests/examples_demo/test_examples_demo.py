"""The demo kit in examples/: every command in examples/README.md must run and show what the README says.

  * the fictional data in examples/ is exactly what scripts/make_examples.py writes (no drift);
  * module #1 (graph) and module #4 (detections) demos run on that fictional data;
  * modules #2 / #3 demos need real hives and logs: they run on the public samples in tests/data
    (scripts/fetch_test_samples.py) and skip when those are missing.
"""

import importlib.util
import json
import os
import pathlib
import re
import shlex

import pytest

from usbhawk.cli import main

from conftest import sample

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples"
FLEET_RULES = {"wiped_here_seen_there", "exfil_device_spread", "device_on_many_hosts", "device_shared_by_users",
               "new_to_fleet", "serial_collision"}


@pytest.fixture(autouse=True)
def _no_banner(monkeypatch):
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    monkeypatch.setenv("COLUMNS", "160")


def run(argv, capsys):
    try:
        code = main(argv)
    except SystemExit as exc:
        code = exc.code
    out, err = capsys.readouterr()
    return code or 0, out, err


def jsonl(path):
    return [json.loads(x) for x in pathlib.Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]


# --------------------------------------------------------------------------- the data
def _load_generator():
    spec = importlib.util.spec_from_file_location("make_examples", ROOT / "scripts" / "make_examples.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_examples_match_the_generator(tmp_path, capsys):
    _load_generator().generate(tmp_path)
    fresh = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*") if p.is_file())
    shipped = sorted(p.relative_to(EXAMPLES) for p in EXAMPLES.rglob("*.jsonl"))
    assert fresh == shipped, "examples/ is stale: run python scripts/make_examples.py"
    for rel in fresh:
        a = (tmp_path / rel).read_text(encoding="utf-8").replace("\r\n", "\n")
        b = (EXAMPLES / rel).read_text(encoding="utf-8").replace("\r\n", "\n")
        assert a == b, f"examples/{rel} is stale: run python scripts/make_examples.py"


def test_examples_are_fictional_only():
    """Only the documented fictional hosts and users; nothing from a lab VM, a real case or this PC."""
    text = "".join(p.read_text(encoding="utf-8") for p in EXAMPLES.rglob("*") if p.is_file())
    hosts = set(re.findall(r'"(?:host|name)": "([^"]+)"', text)) - {None}
    assert {h.split(".")[0] for h in hosts if h.startswith("NW-")} == {
        "NW-FIN-WS042", "NW-HR-WS007", "NW-ENG-LT113", "NW-OPS-WS019"}
    users = {u.lower() for u in re.findall(r"NW\\\\([a-z.]+)", text)}
    assert users <= {"j.doe", "a.smith", "k.lee", "m.ortiz"}
    assert not re.search(r"S-1-5-21-\d", text)                      # no SIDs
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)       # no IPs


# --------------------------------------------------------------------------- module #1 graph
def test_demo_graph_finds_all_six_hunts(tmp_path, capsys):
    code, out, _ = run(["graph", "--runs", str(EXAMPLES / "fleet"), "--out", str(tmp_path)], capsys)
    assert code == 0 and "Fleet 4 hosts, 6 USB devices" in out
    assert {f["usbhawk"]["rule"] for f in jsonl(tmp_path / "findings.jsonl")} == FLEET_RULES
    for name in ("graph.json", "graph.graphml", "graph.cypher"):
        assert (tmp_path / name).stat().st_size > 0


def test_demo_graph_device_pivot(capsys):
    code, out, _ = run(["graph", "--runs", str(EXAMPLES / "fleet"), "device", "60A44C41"], capsys)
    assert code == 0 and "match: serial (high)" in out and "Severity" not in out
    rows = [ln for ln in out.splitlines() if re.match(r"^[|│] NW-", ln)]
    assert [re.split(r"[|│]", r)[1].strip() for r in rows] == ["NW-FIN-WS042", "NW-HR-WS007", "NW-ENG-LT113"]
    assert "85 high" in rows[0] and "Q3-BOARD 8E2C41D7" in rows[0]


def test_demo_graph_user_pivot(capsys):
    code, out, _ = run(["graph", "--runs", str(EXAMPLES / "fleet"), "user", "a.smith"], capsys)
    assert code == 0 and "host(s) | match:" in out and "Severity" not in out
    assert "Kingston DataTraveler 3.0" in out and "SanDisk Ultra" in out


# --------------------------------------------------------------------------- module #4 detections
def test_demo_detections_replay_fires_h1_to_h8(tmp_path, capsys):
    events = str(EXAMPLES / "detections" / "insider_timeline.jsonl")
    code, out, _ = run(["detections", "run", "--events", events, "--out", str(tmp_path)], capsys)
    assert code == 0
    assert "Alerts per hypothesis: H1 2, H2 1, H3 1, H4 1, H5 1, H6 1, H7 2, H8 1" in out
    assert {a["hypothesis"] for a in jsonl(tmp_path / "alerts.jsonl")} == {f"H{i}" for i in range(1, 9)}


def test_demo_detections_test_and_build(tmp_path, capsys):
    assert run(["detections", "test"], capsys)[0] == 0
    code, _out, _ = run(["detections", "build", "--target", "all", "--out", str(tmp_path)], capsys)
    assert code == 0
    built = {p.parent.name for p in tmp_path.rglob("*") if p.is_file()}
    assert {"sigma", "elastic", "sentinel"} <= built


# --------------------------------------------------------------------------- modules #2 / #3 on public samples
def test_demo_sessions_devices_tamper_on_public_samples(tmp_path, capsys):
    sample("SYSTEM")
    triage = str(ROOT / "tests" / "data")
    code, out, _ = run(["sessions", "--triage", triage, "--tz", "America/New_York", "--out", str(tmp_path)], capsys)
    assert code == 0 and "WKS-WIN732BITA" in out
    assert any(s["event"]["risk_score"] > 0 for s in jsonl(tmp_path / "sessions.jsonl"))
    code, out, _ = run(["devices", "--triage", triage], capsys)
    assert code == 0 and "SECRETPLANS" in out
    code, out, _ = run(["tamper", "--triage", triage], capsys)
    assert code == 0 and "evidence_host_mismatch" in out


# --------------------------------------------------------------------------- the README itself
def _readme_commands():
    text = (EXAMPLES / "README.md").read_text(encoding="utf-8")
    cmds = []
    for block in re.findall(r"```(?:powershell|bash)\n(.*?)```", text, re.S):
        cmds += [ln.strip() for ln in block.splitlines() if ln.strip().startswith("usbhawk ")]
    return cmds


def test_readme_lists_a_demo_for_every_module():
    cmds = " ".join(_readme_commands())
    for sub in ("graph", "detections run", "detections test", "detections build", "sessions", "devices", "tamper"):
        assert f"usbhawk {sub}" in cmds


@pytest.mark.parametrize("line", [c for c in _readme_commands() if "examples" in c] if
                         (EXAMPLES / "README.md").exists() else [])
def test_every_readme_demo_on_fictional_data_runs(line, tmp_path, monkeypatch, capsys):
    """Commands are run from a scratch folder so their --out folders never land in the repo."""
    monkeypatch.chdir(tmp_path)
    argv = []
    for a in shlex.split(line.replace("\\", "/"))[1:]:
        argv.append(str(ROOT / a) if a.startswith("examples") else a)
    code, out, err = run(argv, capsys)
    assert code == 0, f"{line}\n{out}\n{err}"
    assert out.strip()
