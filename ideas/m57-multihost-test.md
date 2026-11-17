# Multi-host test on M57-Patents

**Why.** The fleet graph is lab-verified on two real hosts and tested on a fictional four-host fleet. A public
multi-host case would show it on real data anyone can reproduce.

**Approach.** Digital Corpora's M57-Patents scenario has several employee workstations imaged over weeks. Fetch the
images on demand (add them to `scripts/fetch_demo_datasets.py` with published hashes), extract each host's hives and
logs, run `usbhawk sessions/tamper --out` per host and `usbhawk graph`. Check the licence and terms before adding.

**Tests.** Document the result in `docs/TESTING.md`; turn anything surprising into a fictional regression test.
