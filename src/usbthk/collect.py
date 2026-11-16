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

    def summary(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v}


def discover(root: str) -> ArtifactSet:
    arts = ArtifactSet()
    for dirpath, _dirs, files in os.walk(root):
        low_dir = dirpath.replace("\\", "/").lower()
        for f in files:
            lf = f.lower()
            p = os.path.join(dirpath, f)
            if lf == "system" and ("config" in low_dir or arts.system is None):
                arts.system = p
            elif lf == "software" and ("config" in low_dir or arts.software is None):
                arts.software = p
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

    if arts.system:
        run(f"SYSTEM {arts.system}", registry.parse_system, arts.system, ev)
    if arts.software:
        run(f"SOFTWARE {arts.software}", registry.parse_software, arts.software, ev)
    for path, user in arts.ntuser:
        run(f"NTUSER {user}", registry.parse_ntuser, path, ev, user)
    registry.link_drive_letters(ev)
    for p in arts.partition_diag:
        run(f"Partition/Diagnostic {p}", evtx_logs.parse_partition_diagnostic, p, ev)
    for p in arts.system_log:
        run(f"System.evtx {p}", evtx_logs.parse_system_log, p, ev)
    for p in arts.setupapi:
        run(f"setupapi {p}", setupapi.parse_setupapi, p, ev)
    for p in arts.security:
        run(f"Security.evtx {p}", evtx_logs.parse_security, p, ev)
    for p in arts.file_events:
        run(f"file events {p}", file_events.load_file_events, p, ev)
    if not ev.host.hostname:
        ev.host.hostname = "unknown-host"
    return ev
