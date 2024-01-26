#!/usr/bin/env python3

"""
Usage:
    python3 find_and_get_kernel.py <version> <destination_path>

Obtain the linux headers deb package for the given kernel version from
https://kernel.ubuntu.com/mainline/v<version>/<arch>/,
and place them in <destination_path>/lib/modules/<version>/build.

Doesn't have any dependencies except for python3 and dpkg-deb.
"""

import os
import shutil
import zipfile
from urllib.request import urlretrieve
from pathlib import Path
import re
import argparse

BASEDIR = Path(__file__).parent
CACHEDIR = BASEDIR / ".cache"


def get_arch() -> str:
    import platform
    if platform.machine() == "x86_64":
        return "amd64"
    elif platform.machine() == "aarch64":
        return "arm64"
    else:
        raise Exception("Unknown architecture")


def download_file(url: str, name: str) -> Path:
    name = name.replace("/", "_")
    os.makedirs(BASEDIR / ".cache", exist_ok=True)
    path = CACHEDIR / name
    if not path.exists():
        print(f"Downloading {url}")
        urlretrieve(url, path)
    return path


def ci_version_to_mainline_version(version: str) -> str:
    if re.match(r"^\d+\.\d+$", version):
        return version
    if re.match(r"^\d+\.\d+\.\d+$", version):
        return version[:3]
    raise Exception(f"Unsupported version format: {version}")


def get_deb_url(arch: str, version: str) -> str:
    version = ci_version_to_mainline_version(version)
    url = f"https://kernel.ubuntu.com/mainline/v{version}/{arch}"
    with download_file(url, f"index{arch}{version}").open() as f:
        # find <a href="linux-headers-6.6.0-060600-generic_6.6.0-060600.202311151808_amd64.deb">
        for line in f:
            m = re.search(fr'<a href="linux-headers-.*{arch}.deb">',
                          line)
            if m:
                file = m.group(0).split('"')[1]
                return f"https://kernel.ubuntu.com/mainline/v{version}/{arch}/{file}"


def download_deb(arch: str, version: str) -> Path:
    url = get_deb_url(arch, version)
    return download_file(url, url.split("/")[-1])


def unpack_deb_repack_in_cache(arch: str, version: str) -> Path:
    """
    Download the linux headers deb package and repackage it into a zip file.

    The zip file contains `/lib` and `/usr` folders on the top level.

    Returns: path to the zip file
    """
    # unpack deb into tmp folder via dpkg-deb
    # zip tmp folder and store in .cache/arch-version.zip
    # only unpack deb and zip if not already in cache
    zip_path = CACHEDIR / f"{arch}-{version}.zip"
    if not zip_path.exists():
        deb_path = download_deb(arch, version)
        tmp_path = CACHEDIR / f"{arch}-{version}"
        os.makedirs(tmp_path, exist_ok=True)
        os.system(f"dpkg-deb -x {deb_path} {tmp_path}")
        zip_dir = CACHEDIR / f"{arch}-{version}"
        excluded_folders = []
        for folder in tmp_path.glob("lib/modules/*/build/*"):
            if folder.name in ["drivers", "scripts"]:
                excluded_folders.append(folder.relative_to(tmp_path))
            elif folder.name == "arch":
                for arch_folder in folder.glob("*"):
                    if arch_folder.name not in ["x86", "arm64"]:
                        excluded_folders.append(
                            arch_folder.relative_to(tmp_path))
            elif folder.name == "tools":
                for tools_folder in folder.glob("*"):
                    if tools_folder.name != "bpf":
                        excluded_folders.append(tools_folder.relative_to(tmp_path))
        exclude_file = tmp_path / "exclude.txt"
        with exclude_file.open("w") as f:
            for folder in excluded_folders:
                f.write(f"{folder}/\n")

        os.system(
            f"cd {zip_dir}; zip -D -qr {zip_path} {tmp_path.relative_to(zip_dir)} -x@{exclude_file}")
        shutil.rmtree(tmp_path)
        deb_path.unlink()
    return zip_path


def copy_headers_into_dest(arch: str, version: str, dest_root: Path):
    """
    Download the linux headers and move the "zip.zip:/lib/modules/*/build" folder
    to "dest_root/lib/modules/*/build".
    """
    zip_path = unpack_deb_repack_in_cache(arch, version)
    with zipfile.ZipFile(zip_path) as zip_file:
        for name in zip_file.namelist():
            if not name.startswith("lib/modules"):
                continue
            inner_name = "/".join(name.split("/")[3:])
            if inner_name.startswith("build"):
                dest_file = dest_root / "lib" / "modules" / version / inner_name
                os.makedirs(dest_file.parent, exist_ok=True)
                with dest_file.open("wb") as f:
                    f.write(zip_file.read(name))


if __name__ == '__main__':
    argparse = argparse.ArgumentParser()
    argparse.add_argument("version", help="Kernel version")
    argparse.add_argument("destination", help="Destination folder")
    args = argparse.parse_args()
    print(
        f"Downloading headers for {args.version} (arch {get_arch()}) into {args.destination}")
    copy_headers_into_dest(get_arch(),
                           args.version,
                           Path(args.destination))
