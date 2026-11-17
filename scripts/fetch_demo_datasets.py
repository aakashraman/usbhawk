"""Download public forensic datasets for USBHawk demos and prepare triage folders (never bundled, never committed).

    python scripts/fetch_demo_datasets.py --list
    python scripts/fetch_demo_datasets.py evtx-attack                  # 1.2 MB
    python scripts/fetch_demo_datasets.py nist-leakage                 # 5.1 GB download, ~45 GB free space while unpacking
    python scripts/fetch_demo_datasets.py nist-leakage --dest D:\\cases --keep-image

Every file is checked against its published hash. Steps are idempotent: a verified download or an existing output
is skipped, so an interrupted run can simply be started again. Each dataset keeps its own licence and terms; see
the credits printed for it (and examples/README.md).

The NIST image is unpacked with 7-Zip (`7z` / `7zz` on the PATH, or C:\\Program Files\\7-Zip\\7z.exe), which also
reads the NTFS partition, so only the registry hives, event logs and setupapi logs USBHawk needs are copied out.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

NIST = "https://cfreds-archive.nist.gov/data_leakage_case"
EVTX = "https://raw.githubusercontent.com/sbousseaden/EVTX-ATTACK-SAMPLES/master/Defense%20Evasion"

DATASETS = {
    "evtx-attack": {
        "folder": "evtx-attack-samples",
        "size": "1.2 MB",
        "files": [
            (f"{EVTX}/DE_1102_security_log_cleared.evtx", "DE_1102_security_log_cleared.evtx",
             "sha256", "a0615707b547a2ac254688fd725c3c590f62440fc9b7947c2843dd40498a39e8"),
            (f"{EVTX}/DE_104_system_log_cleared.evtx", "DE_104_system_log_cleared.evtx",
             "sha256", "5579cdca073ee4864ea82d656aa2d25400b5c1e85b8e688db5d85f6dc558c2af"),
        ],
        "credit": "EVTX-ATTACK-SAMPLES by Samir Bousseaden, https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES "
                  "(GPL-3.0). Real Security 1102 and System 104 log-clearing records.",
        "try": ["usbhawk detections run --evtx {dir}"],
    },
    "nist-leakage": {
        "folder": "nist-data-leakage",
        "size": "5.1 GB download; about 45 GB free space while unpacking, 80 MB triage folder afterwards",
        "files": [
            (f"{NIST}/leakage-answers.pdf", "leakage-answers.pdf",
             "sha256", "218165427fcb2f490b44eccf7fbc9bf3700b938ea976004051a067e79e0da62b"),
            (f"{NIST}/images/pc/cfreds_2015_data_leakage_pc.7z.001", "cfreds_2015_data_leakage_pc.7z.001",
             "sha1", "f07632faa66a47088deb07bdb45cc568e4bf650b"),
            (f"{NIST}/images/pc/cfreds_2015_data_leakage_pc.7z.002", "cfreds_2015_data_leakage_pc.7z.002",
             "sha1", "5dee46abf6fa833268e5ae199a13854ccf42689b"),
            (f"{NIST}/images/pc/cfreds_2015_data_leakage_pc.7z.003", "cfreds_2015_data_leakage_pc.7z.003",
             "sha1", "1687686f819092e05047f195f102d8fa0c38ed66"),
        ],
        "credit": "NIST CFReDS Data Leakage Case (2015), https://cfreds-archive.nist.gov/data_leakage_case/"
                  "data-leakage-case.html. A scripted insider case on Windows 7 with two USB sticks; the answer "
                  "key is leakage-answers.pdf.",
        "try": ["usbhawk sessions --triage {dir}/triage --out {dir}/run",
                "usbhawk tamper --triage {dir}/triage --out {dir}/run",
                "usbhawk devices --triage {dir}/triage",
                "usbhawk graph --runs {dir}/run device 4C530012450531101593"],
    },
}

# What USBHawk reads, as paths inside the Windows partition (7-Zip wildcards).
TRIAGE_PATHS = ["Windows/System32/config/SYSTEM", "Windows/System32/config/SOFTWARE", "Users/*/NTUSER.DAT",
                "Windows/System32/winevt/Logs/*.evtx", "Windows/inf/setupapi*.log"]
IMAGE = "cfreds_2015_data_leakage_pc.dd"
WINDOWS_PARTITION = "1.ntfs"           # the image holds 0.ntfs (System Reserved), 1.ntfs (C:) and unallocated space


def say(msg: str) -> None:
    print(msg, flush=True)


def file_hash(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, algo: str, digest: str) -> None:
    if dest.exists():
        say(f"  verify {dest.name}")
        if file_hash(dest, algo) == digest:
            return
        say(f"  {dest.name}: hash mismatch, downloading again")
    tmp = dest.with_suffix(dest.suffix + ".part")
    say(f"  fetch  {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "usbhawk-demo-fetch"})
    with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as fh:
        total = int(r.headers.get("Content-Length") or 0)
        done, step = 0, 0
        for chunk in iter(lambda: r.read(1 << 20), b""):
            fh.write(chunk)
            done += len(chunk)
            if total > 50 * 2**20 and done * 20 // total > step:
                step = done * 20 // total
                say(f"         {done / 2**20:,.0f} / {total / 2**20:,.0f} MB")
    got = file_hash(tmp, algo)
    if got != digest:
        tmp.unlink()
        raise SystemExit(f"error: {dest.name}: {algo} {got} does not match the published {digest}")
    tmp.replace(dest)


def seven_zip() -> str:
    for name in ("7z", "7zz", "7za"):
        if shutil.which(name):
            return shutil.which(name)
    win = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe"
    if win.exists():
        return str(win)
    raise SystemExit("error: 7-Zip not found. Install it (https://www.7-zip.org) or put 7z on the PATH, then run again.")


def run_7z(args: list[str], cwd: Path) -> None:
    out = subprocess.run([seven_zip(), *args], cwd=cwd, capture_output=True, text=True, errors="replace")
    if out.returncode != 0:
        raise SystemExit(f"error: 7-Zip failed ({out.returncode}):\n{out.stdout[-2000:]}{out.stderr[-2000:]}")


def prepare_nist(d: Path, keep_image: bool) -> None:
    triage = d / "triage"
    if (triage / "Windows" / "System32" / "config" / "SYSTEM").exists():
        say(f"  triage folder already prepared: {triage}")
        return
    image = d / "image" / IMAGE
    if not image.exists():
        say("  unpack the disk image (21 GB, several minutes)")
        run_7z(["x", "-y", f"-o{d / 'image'}", str(d / "cfreds_2015_data_leakage_pc.7z.001")], d)
    part = d / "partition" / WINDOWS_PARTITION
    if not part.exists():
        say("  copy out the Windows partition (21 GB)")
        run_7z(["x", "-y", f"-o{d / 'partition'}", str(image), WINDOWS_PARTITION], d)
    say("  copy out registry hives, event logs and setupapi logs")
    triage.mkdir(exist_ok=True)
    run_7z(["x", "-y", str(part), *TRIAGE_PATHS], triage)
    if not keep_image:
        say("  remove the unpacked image and partition (the verified downloads stay; --keep-image keeps them)")
        shutil.rmtree(d / "partition", ignore_errors=True)
        shutil.rmtree(d / "image", ignore_errors=True)


def fetch(name: str, root: Path, keep_image: bool) -> None:
    ds = DATASETS[name]
    d = root / ds["folder"]
    d.mkdir(parents=True, exist_ok=True)
    say(f"{name}: {ds['size']} -> {d}")
    for url, fname, algo, digest in ds["files"]:
        download(url, d / fname, algo, digest)
    if name == "nist-leakage":
        prepare_nist(d, keep_image)
    say(f"  credit: {ds['credit']}")
    say("  try:")
    for cmd in ds["try"]:
        say("    " + cmd.format(dir=d).replace("/", os.sep))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("datasets", nargs="*", metavar="DATASET",
                    help=f"one or more of: {', '.join(sorted(DATASETS))}")
    ap.add_argument("--dest", default=str(Path.home() / "usbhawk-datasets"),
                    help="folder for the datasets (default: ~/usbhawk-datasets; keep it outside the repository)")
    ap.add_argument("--keep-image", action="store_true", help="keep the unpacked 21 GB NIST image and partition")
    ap.add_argument("--list", action="store_true", help="list the datasets and exit")
    args = ap.parse_args(argv)
    if args.list or not args.datasets:
        for name, ds in sorted(DATASETS.items()):
            say(f"{name:13} {ds['size']}\n{'':13} {ds['credit']}")
        return 0
    unknown = [n for n in args.datasets if n not in DATASETS]
    if unknown:
        ap.error(f"unknown dataset(s): {', '.join(unknown)} (choose from {', '.join(sorted(DATASETS))})")
    for name in args.datasets:
        fetch(name, Path(args.dest).expanduser().resolve(), args.keep_image)
    return 0


if __name__ == "__main__":
    sys.exit(main())
