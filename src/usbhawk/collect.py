"""Locate artifacts in a triage folder (KAPE output, Velociraptor collection, or a mounted image)
and run every parser in the right order (SYSTEM before SOFTWARE before NTUSER before logs)."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from .model import Evidence
from .parsers import evtx_logs, file_events, registry, setupapi

log = logging.getLogger(__name__)


@dataclass
class ArtifactSet:
    system: str | None = None
    software: str | None = None
    ntuser: list[tuple[str, str]] = field(default_factory=list)     # (path, username)
    partition_diag: list[str] = field(default_factory=list)
    security: list[str] = field(default_factory=list)
    system_log: list[str] = field(default_factory=list)
    setupapi: list[str] = field(default_factory=list)
    file_events: list[str] = field(default_factory=list)
    # Expected files that are absent, e.g. setupapi.dev.log when Windows\INF was collected (module #3)
    missing: list[str] = field(default_factory=list)
    # Other copies of a hive that were found but not used, with the reason (RegBack, Windows.old, empty files)
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v and k not in ("missing", "skipped")}


def _hive_rank(path: str, low_dir: str) -> tuple[int, str]:
    """How good a candidate SYSTEM/SOFTWARE file is: (rank, reason). Higher wins; 0 is never used.

    A KAPE or Velociraptor collection often holds several files with the same name: the live hive in
    Windows\\System32\\config, the RegBack copies next to it (0-byte placeholders since Windows 10 1803, otherwise an
    older backup), and the previous installation's hives in Windows.old. Only the live hive describes the host now.
    """
    try:
        if os.path.getsize(path) == 0:
            return 0, "empty file"
    except OSError:
        return 0, "unreadable"
    d = "/" + low_dir.strip("/") + "/"
    if "/regback/" in d:
        return 1, "RegBack backup copy (older than the live hive)"
    if "/windows.old/" in d:
        return 1, "Windows.old (a previous Windows installation)"
    if d.endswith("/system32/config/"):
        return 4, ""
    if "/config/" in d:
        return 3, ""
    return 2, ""                     # a hive copied by hand into a flat folder


def discover(root: str) -> ArtifactSet:
    arts = ArtifactSet()
    inf_dir_seen = False
    hives: dict[str, list[tuple[int, str, str]]] = {"system": [], "software": []}
    for dirpath, dirs, files in os.walk(root):
        dirs.sort()                                        # same choice on every run and every OS
        low_dir = dirpath.replace("\\", "/").lower()
        inf_dir_seen = inf_dir_seen or low_dir.endswith("/windows/inf")
        for f in sorted(files):
            lf = f.lower()
            p = os.path.join(dirpath, f)
            if lf in hives:
                rank, why = _hive_rank(p, low_dir)
                hives[lf].append((rank, p, why))
            elif lf == "ntuser.dat":
                user = os.path.basename(dirpath) or "unknown"
                arts.ntuser.append((p, user))
            elif lf.endswith(".evtx"):
                if "partition" in lf and "diagnostic" in lf:
                    arts.partition_diag.append(p)
                elif lf == "security.evtx":
                    arts.security.append(p)
                elif lf == "system.evtx":
                    arts.system_log.append(p)
            elif lf.startswith("setupapi.dev") and lf.endswith(".log"):
                arts.setupapi.append(p)
    for name, found in hives.items():
        usable = [c for c in found if c[0] > 0]
        best = max(usable, key=lambda c: c[0], default=None)       # first found wins a tie (sorted walk)
        if best:
            setattr(arts, name, best[1])
        for rank, p, why in found:
            if best is None or p != best[1]:
                arts.skipped.append((p, why or "another copy; using " + best[1]))
    # Windows always keeps the current setupapi.dev.log (Windows 11 also rotates it into setupapi.dev.<date>.log
    # archives); an INF folder without the current file was emptied (USBOblivion deletes it). Archives alone do not
    # count: a cleaner that deletes the live log may leave older archives behind.
    current = any(os.path.basename(p).lower() == "setupapi.dev.log" for p in arts.setupapi)
    if inf_dir_seen and not current:
        arts.missing.append("setupapi.dev.log")
    return arts


def load(arts: ArtifactSet, *, verbose=print) -> Evidence:
    ev = Evidence()

    def run(label, fn, *args):
        try:
            out = fn(*args)
            verbose(f"  parsed {label}" + (f" ({out} records)" if isinstance(out, int) else ""))
        except Exception as exc:  # one bad artifact must never sink the whole triage
            msg = f"{label}: {type(exc).__name__}: {exc}"
            ev.warnings.append(msg)
            verbose(f"  [!] {msg}")

    def old(p: str) -> str:
        """Mark evidence from Windows.old: the previous Windows installation of the same PC (older history)."""
        if "/windows.old/" in "/" + p.replace("\\", "/").lower():
            ev.host.windows_old_logs = True
            return " [Windows.old: previous installation]"
        return ""

    for path, why in arts.skipped:
        verbose(f"  skipped {path}: {why}")
    if arts.system:
        run(f"SYSTEM {arts.system}", registry.parse_system, arts.system, ev)
    if arts.software:
        run(f"SOFTWARE {arts.software}", registry.parse_software, arts.software, ev)
    for path, user in arts.ntuser:
        run(f"NTUSER {user}{old(path)}", registry.parse_ntuser, path, ev, user)
    registry.link_drive_letters(ev)
    for p in arts.partition_diag:
        run(f"Partition/Diagnostic {p}{old(p)}", evtx_logs.parse_partition_diagnostic, p, ev)
    for p in arts.system_log:
        run(f"System.evtx {p}{old(p)}", evtx_logs.parse_system_log, p, ev)
    for p in arts.setupapi:
        run(f"setupapi {p}{old(p)}", setupapi.parse_setupapi, p, ev)
    for p in arts.security:
        run(f"Security.evtx {p}{old(p)}", evtx_logs.parse_security, p, ev)
    for p in arts.file_events:
        run(f"file events {p}", file_events.load_file_events, p, ev)
    registry.link_mbr_volumes(ev)          # needs both MountedDevices and the 1006 MBR signatures
    ev.collection_gaps = list(arts.missing)
    if not ev.host.hostname:
        ev.host.hostname = "unknown-host"
    return ev
