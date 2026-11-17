# LNK and JumpList file attribution

**Why.** Shortcut (LNK) files and JumpLists record files opened from a volume, with the volume serial and label. They
show what was opened from or written to a stick, even without EDR. Today USBHawk imports them only as LECmd / JLECmd
CSV through `--file-events`.

**Evidence (NIST CFReDS Data Leakage).** The answer key traces the confidential documents opened from RM#1 and copied
to RM#2 through LNK and JumpList entries.

**Approach.** A native parser (or the `LnkParse3` library, MIT) for `Recent\*.lnk` and
`AutomaticDestinations\*.automaticDestinations-ms`, emitting file events with VSN, label, path and times; session
attachment already matches by VSN. Also adds ShellBags later for folders browsed on the stick.

**Tests.** LNK fixtures built in the test (no real user files), VSN-to-session matching, and a JumpList with several
entries.
