# Windows 7: last connection from key timestamps

**Why.** Windows 8 and later record every device's last arrival and removal as device properties (`0066`, `0067`).
Windows 7 records only the first install (`0064`), so USBHawk shows one session per stick on Win7 hosts and misses
every later visit. Many training cases and older estates are Windows 7.

**Evidence (NIST CFReDS Data Leakage, Win7 SP1).** The answer key has four connections; USBHawk reports the two first
installs correctly (RM#1 2015-03-23 18:31:09 UTC, RM#2 2015-03-24 13:58:31 UTC). The later two survive only as key
last-write times:

| Answer key (EDT) | Key last-write (UTC) | Key |
|---|---|---|
| RM#1 second connect, 03-24 09:38 | 2015-03-24 13:38:00 | `Enum\USB\VID_0781&PID_5571\<serial>`, `DeviceClasses\{53f56307...}\##?#USBSTOR#...<serial>`, MountPoints2 `{volume}` |
| RM#2 second connect, 03-24 15:38 | 2015-03-24 19:38:09 | `Enum\USB\VID_0781&PID_5571\<serial>` |

**Approach.** When a device has no `0066`, add a `connect` event at the latest of the `DeviceClasses` disk-interface
key and the `Enum\USB` instance key last-write times, sourced `registry:lastwrite` and marked approximate (a key can be
rewritten by a driver update). Never use it when `0066` exists. Session building already handles a connect without a
removal (`no-end`).

**Tests.** Synthetic Win7 hive model: first install plus a later last-write gives two sessions; with `0066` present the
last-write is ignored; a last-write equal to the first install adds nothing. Re-run the NIST validation and update
`docs/TESTING.md`.
