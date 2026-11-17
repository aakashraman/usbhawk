# Velociraptor artifact and KAPE module

**Why.** A fleet hunt needs the same small set of files from every host. Collection should be one click, not a
script per machine.

**Approach.** A Velociraptor artifact that collects SYSTEM, SOFTWARE, every NTUSER.DAT, the Security, System and
Partition/Diagnostic logs and `setupapi.dev.log`, and optionally runs `usbhawk.exe sessions/tamper --out` on the
endpoint; a KAPE target (`USBHawk.tkape`) for the same files and a module (`USBHawk.mkape`) that runs the exe on a
collection. Output folders per host feed `usbhawk graph` directly.

**Tests.** Collect a lab VM with each tool, run USBHawk on the result, compare with `scripts/collect_local.ps1`.
