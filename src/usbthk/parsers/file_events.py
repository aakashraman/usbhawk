"""Generic file-activity CSV importer, so EDR telemetry can feed the session scorer.

Works with exports such as:
  * MDE  DeviceFileEvents         (Timestamp, FolderPath, ActionType, FileSize, InitiatingProcessAccountName ...)
  * Sysmon EID 11 from Splunk     (_time, TargetFilename, Image, User)
  * Falcon / LogScale exports     (@timestamp / timestamp, TargetFileName, UserName ...)
  * LECmd / JLECmd CSV            (SourceCreated / TargetCreated, LocalPath, VolumeSerialNumber ...)
Column names are matched case-insensitively against the alias lists below.
"""

from __future__ import annotations

import csv
import re

from ..model import FILE_DELETE, FILE_READ, FILE_WRITE, Event, Evidence
from ..util import to_utc

ALIASES = {
    "ts": ["timestamp", "@timestamp", "_time", "time", "utctime", "eventtime", "sourcecreated",
           "targetaccessed", "date"],
    "path": ["folderpath", "targetfilename", "path", "file_path", "filepath", "localpath",
             "targetfilepath", "objectname", "file.path"],
    "action": ["actiontype", "action", "eventtype", "event_simplename", "operation"],
    "user": ["initiatingprocessaccountname", "accountname", "user", "username", "user.name"],
    "process": ["initiatingprocessfilename", "image", "processname", "process", "process.name"],
    "size": ["filesize", "size", "file.size", "bytes"],
    "vsn": ["volumeserialnumber", "drivevolumeserialnumber", "vsn"],
}
LETTER_RE = re.compile(r"^([A-Za-z]:)")


def _pick(header: list[str], key: str) -> str | None:
    lower = {h.lower().strip(): h for h in header}
    for alias in ALIASES[key]:
        if alias in lower:
            return lower[alias]
    return None


def load_file_events(path: str, ev: Evidence) -> int:
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh)
        header = reader.fieldnames or []
        cols = {k: _pick(header, k) for k in ALIASES}
        if not cols["ts"] or not cols["path"]:
            raise ValueError(f"{path}: need a timestamp column and a path column, got {header}")
        n = 0
        for row in reader:
            ts = to_utc(row.get(cols["ts"]))
            fpath = (row.get(cols["path"]) or "").strip()
            if not ts or not fpath:
                continue
            action = (row.get(cols["action"]) or "") if cols["action"] else ""
            a = action.lower()
            kind = FILE_DELETE if "delet" in a else FILE_READ if ("read" in a or "open" in a) else FILE_WRITE
            size = None
            if cols["size"]:
                try:
                    size = int(float(row.get(cols["size"]) or 0)) or None
                except ValueError:
                    size = None
            m = LETTER_RE.match(fpath)
            ev.add(Event(ts=ts, kind=kind, source="file_events_csv",
                         user=(row.get(cols["user"]) or None) if cols["user"] else None,
                         details={"path": fpath, "drive_letter": m.group(1).upper() if m else None,
                                  "process": row.get(cols["process"]) if cols["process"] else None,
                                  "size": size, "action": action or None,
                                  "vsn": (row.get(cols["vsn"]) or "").replace("-", "").upper() or None
                                  if cols["vsn"] else None}))
            n += 1
    return n
