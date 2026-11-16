"""Download public (MIT-licensed) sample artifacts into tests/data for regression tests.

    python scripts/fetch_test_samples.py
"""

import lzma
import os
import urllib.request

DEST = os.path.join(os.path.dirname(__file__), "..", "tests", "data")
REGIPY = "https://raw.githubusercontent.com/mkorman90/regipy/master/regipy_tests/data/{}.xz"
P4D = ("https://raw.githubusercontent.com/theAtropos4n6/Partition-4DiagnosticParser/main/"
       "sampleFile/Microsoft-Windows-Partition%254Diagnostic.evtx")

FILES = {
    "SYSTEM": REGIPY.format("SYSTEM"),
    "SOFTWARE": REGIPY.format("SOFTWARE"),
    "NTUSER.DAT": REGIPY.format("NTUSER.DAT"),
    "SYSTEM_WIN_10_1709": REGIPY.format("SYSTEM_WIN_10_1709"),
    "Microsoft-Windows-Partition%4Diagnostic.evtx": P4D,
}


def main():
    os.makedirs(DEST, exist_ok=True)
    for name, url in FILES.items():
        out = os.path.join(DEST, name)
        if os.path.exists(out):
            print(f"have  {name}")
            continue
        print(f"fetch {name}")
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
        if url.endswith(".xz"):
            data = lzma.decompress(data)
        with open(out, "wb") as fh:
            fh.write(data)
    print(f"done -> {os.path.abspath(DEST)}")


if __name__ == "__main__":
    main()
