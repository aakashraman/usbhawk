# `.reg` export support

**Why.** Some evidence arrives as `regedit` exports (`.reg` text) instead of hive files, and public datasets use the
format too.

**Evidence.** The Mendeley "Windows Registry Data Sets" (Hyuk-Yoon Kwon, CC BY 4.0, doi:10.17632/ghkms3cgbg.1) hold
`.reg` exports from several PCs; one has 9 `Enum\USBSTOR` instances (a 4-bay enclosure and SanDisk sticks). Exports
have no key last-write times and, in this set, no FILETIME device properties, so they give an inventory but no
timeline.

**Approach.** A small `.reg` reader (UTF-16 and UTF-8, `hex(...)` value types, line continuations) that exposes the
same key / value interface the registry parser uses, so `parse_system` / `parse_software` run unchanged; timestamps
absent rather than guessed, and the output says so.

**Tests.** A fictional `.reg` fixture with USBSTOR, USB, MountedDevices and a hex property; parity with the same keys
read from a hive model. Cite the dataset in docs if it is used for a demo; never bundle it.
