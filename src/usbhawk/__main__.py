"""`python -m usbhawk ...`: the same CLI as the `usbhawk` command (and the entry point of the standalone exe)."""

import sys

from usbhawk.cli import main

if __name__ == "__main__":
    sys.exit(main())
