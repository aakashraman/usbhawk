# Execution evidence: Prefetch, Amcache, UserAssist

**Why.** `usbhawk tamper` sees cleanup tools only through BAM, which exists from Windows 10 1709 and keeps about a
week. Older hosts and older activity are invisible.

**Evidence (NIST CFReDS Data Leakage).** The answer key shows Eraser and CCleaner were installed and run, proven by
Prefetch, UserAssist and Shimcache. USBHawk reported no `cleanup_tool_execution` because Windows 7 has no BAM.

**Approach.** Parse UserAssist (NTUSER, ROT13 names, run count, last run) and Shimcache (SYSTEM) natively with
regipy; read Prefetch and Amcache through a CSV import of PECmd / AmcacheParser output (as file events already are)
before writing native parsers. Feed every execution into the existing `CLEANUP_TOOLS` match, so the tamper rules and
the detection rules keep one tool list.

**Tests.** Synthetic UserAssist / Shimcache entries for a listed tool fire, an unlisted tool does not, ROT13 decoding,
and a PECmd CSV fixture with fictional paths.
