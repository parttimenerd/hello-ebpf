#!/usr/bin/python3

"""
This script downloads jextract and uses it to generate the bcc and bpf bindings.

The main libbcc/libbpf class is BPF.java and is located in the package.

Why do we need this script?
---------------------------
We want to use Project Panama to call libbcc/libbpf from Java, we
use jextract for this.
But we have to download jextract as it's probably not installed
and also jextract has some issues with the libbcc/libbpf header files.
So we have to slightly modify the libbcc/libbpf header files before
passing them to jextract (but we combine all header files into
one).

Running the whole script takes less than a second when jextract is
already downloaded, so it can be run every time in your build
script.

License
-------
MIT
"""

import subprocess
import sys
import time
from pathlib import Path
import urllib.request
import os
import shutil
import tarfile

BIN_FOLDER = Path(__file__).parent.parent / "bin"
JEXTRACT_PATH = BIN_FOLDER / "jextract-22"
JEXTRACT_TOOL_PATH = JEXTRACT_PATH / "bin" / "jextract"
JEXTRACT_VERSION = "3-13"


def download_jextract():
    # download jextract
    shutil.rmtree(JEXTRACT_PATH, ignore_errors=True)
    print("Downloading jextract")
    url = (f"https://download.java.net/java/early_access/jextract/22/3/"
           f"/openjdk-22-jextract+{JEXTRACT_VERSION}_linux-x64_bin.tar.gz")
    os.makedirs(BIN_FOLDER, exist_ok=True)
    urllib.request.urlretrieve(url, BIN_FOLDER / "jextract.tar.gz")
    # extract jextract
    tar = tarfile.open(BIN_FOLDER / "jextract.tar.gz")
    tar.extractall(BIN_FOLDER)
    tar.close()

    # make jextract executable
    os.chmod(JEXTRACT_PATH, 0o755)
    # remove tar.gz
    (BIN_FOLDER / "jextract.tar.gz").unlink()
    print("Downloaded jextract")
    # set st_mtime to now
    JEXTRACT_PATH.touch()


def ensure_jextract_in_path():
    # download jextract if it doesn't exist or
    # if it is older than 10 days
    if not JEXTRACT_PATH.exists() or (
            JEXTRACT_PATH.stat().st_mtime < (
            time.time() - 10 * 24 * 60 * 60)):
        download_jextract()


ensure_jextract_in_path()

def create_combined_lib_header(header: Path, combined_header: Path):
    os.makedirs(header.parent, exist_ok=True)
    subprocess.check_output(
        f"clang -C -E {header} -o {combined_header}", shell=True)


def create_modified_lib_header(header: Path, combined_header: Path, modified_header: Path):
    r"""
    Find lines that match regexp
    "union.* __attribute__\(\(aligned\(8\)\)\);" and
    replace "__attribute__((aligned(8)))" with
    "var{counter} __attribute__((aligned(8)))"
    Store the file in MODIFIED_BPF_HEADER
    """
    create_combined_lib_header(header, combined_header)
    with open(combined_header) as f:
        lines = f.readlines()
    combined_header.unlink()
    with open(modified_header, "w") as f:
        counter = 0
        for line in lines:
            if "union" in line and "__attribute__((aligned(8)));" in line:
                line = line.replace("__attribute__((aligned(8)));",
                                    f"var{counter} __attribute__((aligned(8)));\n")
                counter += 1
            f.write(line)


def assert_java22():
    """ assert that we are running JDK 22+ by calling java -version """
    try:
        output = subprocess.check_output("java -version", shell=True,
                                         stderr=subprocess.STDOUT).decode()
        assert any(f"version \"{v}" in output for v in range(22, 30)), \
            "Please run this script with JDK 22+"
    except FileNotFoundError:
        print("Please install JDK 22+ and run this script with JDK 22+")
        sys.exit(1)


def run_jextract(header: Path, mod_header_folder: Path,
        dest_path: Path, package: str = "", name: str = "BPF",
                 delete_dest_path: bool = False):
    assert_java22()
    print("Running jextract")
    os.makedirs(mod_header_folder, exist_ok=True)
    combined_header = mod_header_folder / "combined_lib.h"
    modified_header = mod_header_folder / "mod_lib.h"
    create_modified_lib_header(header, combined_header, modified_header)
    del_path = dest_path
    if package:
        del_path = dest_path / package.replace(".", "/")
    if delete_dest_path:
        shutil.rmtree(del_path, ignore_errors=True)
    os.makedirs(dest_path, exist_ok=True)
    subprocess.check_call(
        f"{JEXTRACT_TOOL_PATH} "
        f"--output {dest_path} {'-t ' + package if package else ''} "
        f"--header-class-name {name} {modified_header}",
        shell=True)


if __name__ == "__main__":
    if len(sys.argv) == 6:
        run_jextract(Path(sys.argv[4]),
                     Path(sys.argv[5]),
                     Path(sys.argv[1]),
                     sys.argv[2],
                     sys.argv[3])
    else:
        print("Usage: python3 jextract_bindings.py <destination_path> <package> <Lib class> <header> <mod_header_folder>")
        sys.exit(1)