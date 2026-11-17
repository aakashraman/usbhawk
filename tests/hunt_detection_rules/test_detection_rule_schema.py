"""Module #4: the YAML rule sources are valid, unique, and share their lists/thresholds with modules #2 and #3.

The rules are the single source of truth: Sigma, Elastic and Sentinel queries are generated from them. Lists like
the cleanup-tool names come from the same Python definitions the offline hunts use (`${...}` placeholders), so a
live detection and an offline finding can never disagree about what counts as a cleanup tool.
"""

import copy
import uuid

import pytest

import usbhawk.tamper as tamper
from usbhawk.detections import load_rules, rule_vars, resolve_vars, validate_rule

VALID = {
    "id": "0b8b0f3e-6a43-4f1c-9a63-9d1f3f6c2a10",
    "hypothesis": "H9",
    "name": "example_rule",
    "title": "Example rule",
    "description": "Fires on an example process.",
    "level": "medium",
    "date": "2026-11-17",
    "attack": ["T1070"],
    "usbhawk": "tamper.cleanup_tool_execution",
    "false_positives": ["Administrators testing"],
    "detections": [{
        "name": "process",
        "telemetry": "process_creation",
        "selections": {"tool": {"process_name": "example.exe"}},
        "condition": "tool",
    }],
    "tests": [
        {"detection": "process", "match": True, "event": {"process_name": "Example.EXE"}},
        {"detection": "process", "match": False, "event": {"process_name": "notepad.exe"}},
    ],
}


def broken(**changes):
    rule = copy.deepcopy(VALID)
    for path, value in changes.items():
        target = rule
        keys = path.split("__")
        for k in keys[:-1]:
            target = target[int(k)] if isinstance(target, list) else target[k]
        target[keys[-1]] = value
    return rule


# --------------------------------------------------------------------------- shipped rules
def test_every_shipped_rule_is_valid():
    rules = load_rules()
    assert rules, "no rules shipped"
    for r in rules:
        assert validate_rule(r.data) == [], r.path


def test_rule_ids_and_hypotheses_are_unique():
    rules = load_rules()
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))
    assert all(uuid.UUID(i) for i in ids)
    hyps = [r.hypothesis for r in rules]
    assert len(hyps) == len(set(hyps))


def test_file_name_starts_with_the_hypothesis():
    for r in load_rules():
        assert r.path.name.startswith(f"{r.hypothesis}_"), r.path


# --------------------------------------------------------------------------- shared definitions
def test_cleanup_tool_lists_come_from_the_tamper_module():
    v = rule_vars()
    high = [k for k, (_label, sev, _what) in tamper.CLEANUP_TOOLS.items() if sev == "high"]
    medium = [k for k, (_label, sev, _what) in tamper.CLEANUP_TOOLS.items() if sev == "medium"]
    assert v["cleanup_tools"]["high"] == high and "usboblivion" in high
    assert v["cleanup_tools"]["medium"] == medium and "ccleaner" in medium


def test_a_new_cleanup_tool_reaches_the_live_rules(monkeypatch):
    monkeypatch.setitem(tamper.CLEANUP_TOOLS, "wipeusbnow", ("WipeUSBNow", "high", "fictional test tool"))
    h6 = next(r for r in load_rules() if r.hypothesis == "H6")
    values = h6.detection("usb_cleaner")["selections"]["tool"]["process_name|startswith"]
    assert "wipeusbnow" in values


def test_thresholds_and_extensions_come_from_scoring_config():
    v = rule_vars()
    assert v["thresholds"]["bulk_files"] == 50
    assert ".zip" in v["archive_extensions"] and ".kdbx" in v["archive_extensions"]


def test_placeholders_expand_inside_lists_and_scalars():
    v = {"a": ["x", "y"], "n": {"k": 5}}
    assert resolve_vars({"f": ["${a}", "z"], "g": "${n.k}", "h": "plain"}, v) == {"f": ["x", "y", "z"], "g": 5,
                                                                              "h": "plain"}


def test_unknown_placeholder_is_an_error():
    with pytest.raises(KeyError, match="nope"):
        resolve_vars({"f": "${nope}"}, {"a": 1})


# --------------------------------------------------------------------------- validator catches mistakes
def test_valid_example_passes():
    assert validate_rule(VALID) == []


@pytest.mark.parametrize("rule, fragment", [
    (broken(level="severe"), "level"),
    (broken(id="not-a-uuid"), "id"),
    (broken(hypothesis="6"), "hypothesis"),
    (broken(attack=["TA0005"]), "technique"),
    (broken(detections__0__telemetry="carrier_pigeon"), "telemetry"),
    (broken(detections__0__condition="tool and missing"), "missing"),
    (broken(detections__0__selections={"tool": {"process_colour": "x"}}), "process_colour"),
    (broken(detections__0__selections={"tool": {"process_name|fuzzy": "x"}}), "fuzzy"),
    (broken(tests=[VALID["tests"][0]]), "no_match"),
    (broken(tests=[VALID["tests"][1]]), "match"),
])
def test_validator_reports_each_mistake(rule, fragment):
    errors = validate_rule(rule)
    assert errors and any(fragment in e for e in errors), errors


def test_event_log_detection_needs_a_channel():
    rule = broken(detections__0__telemetry="event_log",
                  detections__0__selections={"tool": {"event_id": 1102}})
    rule["tests"] = [{"detection": "process", "match": True, "event": {"event_id": 1102}},
                     {"detection": "process", "match": False, "event": {"event_id": 1100}}]
    assert any("channel" in e for e in validate_rule(rule))
