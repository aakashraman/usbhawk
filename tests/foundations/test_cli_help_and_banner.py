"""The USBHawk command line: banner, help with examples for every command, and the installed command.

The banner is for people, never for machines: help always shows it; during a run it goes to stderr only when stderr
is an interactive terminal, and never with -q or USBHAWK_NO_BANNER=1. JSON / CSV on stdout must stay clean.
"""

import json
import pathlib
import tomllib

import pytest

from usbhawk import __version__
from usbhawk.banner import ART, TAGLINE, banner
from usbhawk.cli import main

from conftest import sample

ROOT = pathlib.Path(__file__).resolve().parents[2]
ART_LINE = ART.strip("\n").splitlines()[2]          # a line only the ASCII art contains


class TTY:
    """Wraps a captured stream so it claims to be an interactive terminal."""
    def __init__(self, stream):
        self._s = stream

    def isatty(self):
        return True

    def __getattr__(self, name):
        return getattr(self._s, name)


def run(argv, capsys):
    try:
        code = main(argv)
    except SystemExit as exc:                      # argparse exits after --help
        code = exc.code
    out, err = capsys.readouterr()
    return code, out, err


# --------------------------------------------------------------------------- banner
def test_banner_text():
    b = banner()
    assert ART_LINE in b and TAGLINE in b and __version__ in b
    assert TAGLINE == "USB forensics for threat hunting & incident response"


def test_top_level_help_shows_banner_hunts_and_examples(capsys):
    code, out, _ = run(["--help"], capsys)
    assert code == 0 and ART_LINE in out
    for cmd in ("sessions", "tamper", "detections", "graph", "devices"):
        assert cmd in out
    assert "Examples:" in out and "usbhawk sessions --triage" in out


def test_no_command_prints_help_instead_of_an_error(capsys):
    code, out, _ = run([], capsys)
    assert code == 0 and ART_LINE in out and "Examples:" in out


@pytest.mark.parametrize("argv, guide", [
    (["sessions", "--help"], "docs/hunt-exfil-sessions.md"),
    (["tamper", "--help"], "docs/hunt-usb-tamper.md"),
    (["detections", "--help"], "docs/hunt-detection-rules.md"),
    (["graph", "--help"], "docs/hunt-fleet-device-graph.md"),
    (["devices", "--help"], None),
    (["detections", "build", "--help"], None),
    (["detections", "run", "--help"], None),
])
def test_every_command_help_has_examples(argv, guide, capsys):
    code, out, _ = run(argv, capsys)
    assert code == 0 and "Examples:" in out and "usbhawk " + argv[0] in out
    if guide:
        assert guide in out


def test_version(capsys):
    code, out, _ = run(["--version"], capsys)
    assert code == 0 and out.strip() == f"usbhawk {__version__}"


# --------------------------------------------------------------------------- banner during runs
def test_banner_on_an_interactive_terminal(capsys, monkeypatch):
    monkeypatch.setattr("sys.stderr", TTY(__import__("sys").stderr))
    code, out, err = run(["detections", "list"], capsys)
    assert code == 0 and ART_LINE in err and ART_LINE not in out


def test_no_banner_when_output_is_not_a_terminal(capsys):
    code, out, err = run(["detections", "list"], capsys)
    assert code == 0 and ART_LINE not in err and ART_LINE not in out


def test_no_banner_with_quiet_or_env(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr("sys.stderr", TTY(__import__("sys").stderr))
    code, _out, err = run(["graph", "--runs", str(tmp_path), "-q"], capsys)
    assert ART_LINE not in err
    monkeypatch.setenv("USBHAWK_NO_BANNER", "1")
    code, _out, err = run(["detections", "list"], capsys)
    assert ART_LINE not in err


def test_json_on_stdout_stays_clean_with_a_banner(capsys, monkeypatch):
    monkeypatch.setattr("sys.stderr", TTY(__import__("sys").stderr))
    code, out, err = run(["devices", "--system", sample("SYSTEM")], capsys)
    assert code == 0 and ART_LINE in err
    lines = [l for l in out.splitlines() if l.strip()]
    assert lines and all(json.loads(l)["key"] for l in lines)       # every stdout line is pure JSON


# --------------------------------------------------------------------------- name
def test_one_command_is_installed():
    scripts = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
    assert scripts == {"usbhawk": "usbhawk.cli:main"}


def test_output_datasets_use_the_new_name(tmp_path, capsys):
    """SIEM field names: event.dataset usbhawk.* and the usbhawk field group."""
    from usbhawk.tamper import Finding
    doc = Finding("log_cleared", "high", "why", {}, None, "NW-FIN-WS042").to_dict()
    assert doc["event"]["dataset"] == "usbhawk.tamper" and "usbhawk" in doc
