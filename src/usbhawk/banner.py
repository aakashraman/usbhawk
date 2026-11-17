"""The USBHawk banner. Shown in help, and at the start of a run on an interactive terminal only.

Never printed to stdout during a run (JSON / CSV stay machine-readable), never when stderr is piped or redirected,
and never with -q or USBHAWK_NO_BANNER=1. Rendered once with figlet's "slant" font and stored as text, so there is
no runtime dependency.
"""

from __future__ import annotations

import os
import sys

from . import __version__

ART = r"""
   __  _______ ____  __  __               __
  / / / / ___// __ )/ / / /___ __      __/ /__
 / / / /\__ \/ __  / /_/ / __ `/ | /| / / //_/
/ /_/ /___/ / /_/ / __  / /_/ /| |/ |/ / ,<
\____//____/_____/_/ /_/\__,_/ |__/|__/_/|_|
"""
TAGLINE = "USB forensics for threat hunting & incident response"


def banner() -> str:
    return f"{ART.strip(chr(10))}\n   {TAGLINE}   v{__version__}\n"


def show_banner(quiet: bool = False) -> None:
    """Print the banner to stderr, but only for a person at a terminal."""
    if quiet or os.environ.get("USBHAWK_NO_BANNER"):
        return
    stream = sys.stderr
    try:
        interactive = stream.isatty()
    except (AttributeError, ValueError):
        interactive = False
    if interactive:
        print(banner(), file=stream)
