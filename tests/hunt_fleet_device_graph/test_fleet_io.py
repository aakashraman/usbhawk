"""Module #1: reading per-host outputs, pivots, exports (JSON, GraphML, Neo4j Cypher) and the CLI."""

import json
import xml.etree.ElementTree as ET
from datetime import timedelta

import pytest

from usbthk.cli import main
from usbthk.graph import build_fleet, find_runs

from fleet_builder import T0, HostRun, write_fleet

WS042, WS007, LT113 = "NW-FIN-WS042", "NW-HR-WS007", "NW-ENG-LT113"


def small_fleet(tmp_path):
    a, b, c = HostRun(WS042), HostRun(WS007), HostRun(LT113)
    a.session(a.stick(vsns={"8E2C41D7"}, volume_names={"Q3-BOARD"}), score=85, severity="high", writes=12,
              users=["NW\\j.doe"])
    b.session(b.stick(vsns={"8E2C41D7"}), start=T0 + timedelta(days=1), users=["NW\\a.smith"])
    c.session(c.stick(), start=T0 + timedelta(days=3), users=["NW\\k.lee"])
    c.session(c.stick(serial="AA951D0000007252", product="v100w"), users=["NW\\k.lee"])
    return write_fleet(tmp_path, a, b, c)


# --------------------------------------------------------------------------- reading
def test_find_runs_accepts_folders_parents_and_wildcards(tmp_path):
    small_fleet(tmp_path)
    assert len(find_runs([str(tmp_path)])) == 3                         # parent folder of host runs
    assert len(find_runs([str(tmp_path / "NW-*")])) == 3                # wildcard (PowerShell passes it literally)
    assert len(find_runs([str(tmp_path / WS042)])) == 1                 # one host
    assert find_runs([str(tmp_path / "nothing-here")]) == []


def test_fleet_summary(tmp_path):
    f = build_fleet(small_fleet(tmp_path))
    assert f.hosts == sorted([LT113, WS007, WS042])
    assert len(f.clusters) == 2 and f.session_count == 4
    assert {"j.doe", "a.smith", "k.lee"} == f.users


def test_host_without_sessions_file_still_loads(tmp_path):
    a = HostRun(WS042)
    a.stick()
    root = a.write(tmp_path)
    (tmp_path / WS042 / "sessions.jsonl").unlink()
    f = build_fleet([root])
    assert len(f.clusters) == 1 and f.warnings


# --------------------------------------------------------------------------- pivots
def test_device_pivot_by_serial_fragment_or_vsn(tmp_path):
    f = build_fleet(small_fleet(tmp_path))
    [c] = f.find_device("60a44c41")
    assert c.hosts == {WS042, WS007, LT113}
    view = c.per_host()
    assert [h["host"] for h in view] == [WS042, WS007, LT113]              # in time order
    assert view[0]["max_score"] == 85 and view[0]["writes"] == 12 and view[0]["users"] == ["j.doe"]
    assert f.find_device("8E2C41D7") == [c]


def test_user_pivot(tmp_path):
    f = build_fleet(small_fleet(tmp_path))
    devs = f.find_user("NW\\K.LEE")
    assert len(devs) == 2
    assert f.find_user("nobody") == []


# --------------------------------------------------------------------------- exports
def test_graph_json_nodes_and_edges(tmp_path):
    g = build_fleet(small_fleet(tmp_path)).graph()
    types = {}
    for n in g["nodes"]:
        types[n["type"]] = types.get(n["type"], 0) + 1
    assert types == {"device": 2, "host": 3, "user": 3, "volume": 1}
    rels = {e["type"] for e in g["edges"]}
    assert rels == {"CONNECTED_TO", "USED", "HAS_VOLUME"}
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    conn = [e for e in g["edges"] if e["type"] == "CONNECTED_TO" and e["target"] == f"host:{WS042}"
            and "60A44C41" in e["source"]][0]
    assert conn["sessions"] == 1 and conn["max_score"] == 85 and conn["first_seen"].endswith("Z")


def test_graphml_is_valid_xml_for_gephi(tmp_path):
    xml = build_fleet(small_fleet(tmp_path)).graphml()
    root = ET.fromstring(xml)
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    assert len(root.findall(".//g:node", ns)) == 9 and len(root.findall(".//g:edge", ns)) > 0
    assert {k.get("attr.name") for k in root.findall("g:key", ns)} >= {"type", "label"}


def test_cypher_merges_and_escapes(tmp_path):
    a = HostRun(WS042)
    a.session(a.stick(volume_names={"O'BRIEN \\ FILES"}), users=["NW\\j.doe"])
    cy = build_fleet(write_fleet(tmp_path, a)).cypher()
    assert "MERGE (n:Device {id: " in cy and "MERGE (n:Host {id: 'host:NW-FIN-WS042'})" in cy
    assert ":CONNECTED_TO" in cy and ":USED" in cy
    assert "O\\'BRIEN \\\\ FILES" in cy


# --------------------------------------------------------------------------- CLI
def test_cli_writes_findings_and_exports(tmp_path, capsys):
    small_fleet(tmp_path / "runs")
    out = tmp_path / "fleet"
    assert main(["graph", "--runs", str(tmp_path / "runs"), "--out", str(out), "-q"]) == 0
    for name in ("findings.jsonl", "graph.json", "graph.graphml", "graph.cypher"):
        assert (out / name).exists(), name
    rules = {json.loads(l)["usbthk"]["rule"] for l in (out / "findings.jsonl").read_text().splitlines()}
    assert {"exfil_device_spread", "device_on_many_hosts", "device_shared_by_users"} <= rules
    doc = json.loads((out / "findings.jsonl").read_text().splitlines()[0])
    assert doc["event"]["dataset"] == "usbthk.graph" and doc["@timestamp"].endswith("Z")


def test_cli_device_and_user_pivots(tmp_path, capsys):
    small_fleet(tmp_path / "runs")
    assert main(["graph", "--runs", str(tmp_path / "runs"), "-q", "device", "60A44C41"]) == 0
    text = capsys.readouterr().out
    assert WS042 in text and WS007 in text and LT113 in text
    assert main(["graph", "--runs", str(tmp_path / "runs"), "-q", "user", "k.lee"]) == 0
    assert "v100w" in capsys.readouterr().out


def test_cli_without_runs_fails_clearly(tmp_path, capsys):
    assert main(["graph", "--runs", str(tmp_path / "empty")]) == 2
    assert "no host outputs" in capsys.readouterr().err
