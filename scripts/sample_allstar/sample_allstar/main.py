
from typing import List
from urllib.request import urlopen, urlretrieve
from urllib.parse import urljoin
import argparse
import json
import tqdm
import multiprocessing
import functools
import pickle
import os
import urllib

PACKAGE_LIST_URL = "https://allstar.jhuapl.edu/repo/jessie-list-p{package_num}-final.txt"

BASE_BINARY_DIR = "https://allstar.jhuapl.edu/repo/p{package_num}/{arch}/{package_name}/"

PKG_LIST_FILE = "./index.json"


def PACKAGE_RANGE(): return range(1, 5)


class Package:
    def __init__(self, pnum: int, pname: str) -> None:
        self.pnum = pnum
        self.pname = pname


def collect_full_package_list() -> List[Package]:
    tot = []
    for pkg_num in PACKAGE_RANGE():
        nurl = PACKAGE_LIST_URL.format(package_num=str(pkg_num))
        data = urlopen(nurl)
        for line in data:
            tot.append(Package(pkg_num, line.decode().strip()))
    return tot


class Binary:
    def __init__(self, pkg: Package, bin_name: str, file_path: str, arch: str) -> None:
        self.pkg = pkg
        self.bin_name = bin_name
        self.file_path = file_path
        self.arch = arch

    def get_target_url(self):
        base_bin_dir = BASE_BINARY_DIR.format(
            package_num=self.pkg.pnum, arch=self.arch, package_name=self.pkg.pname)
        return urljoin(base_bin_dir, self.file_path)

    def download_to_dir(self, target_dir: str, template=str):
        to_name = template.format(name=self.bin_name)
        out_file = os.path.join(target_dir, to_name)

        urlretrieve(self.get_target_url(), filename=out_file)


def get_list_of_binaries(pkg: Package,  arch: str) -> List[Binary]:
    base_bin = BASE_BINARY_DIR.format(
        package_num=pkg.pnum, arch=arch, package_name=pkg.pname)
    pkg_list = urljoin(base_bin, PKG_LIST_FILE)
    try:
        lst = json.loads(urlopen(pkg_list, timeout=2).read())
    except json.decoder.JSONDecodeError:
        return []
    except urllib.error.URLError:
        return []

    return [Binary(pkg, b['name'], b['file'], arch) for b in lst['binaries']]


if __name__ == "__main__":
    prog = argparse.ArgumentParser("sample binaries")
    prog.add_argument('-a', '--arches', nargs='+',
                      help='Target architectures', default=["amd64"], type=str)
    prog.add_argument("target_directory", type=str)

    args = prog.parse_args()
    pkgs = collect_full_package_list()

    with multiprocessing.Pool() as p:
        for arch in args.arches:
            bins = [b for bin_list in p.imap_unordered(
                functools.partial(get_list_of_binaries, arch=arch), tqdm.tqdm(pkgs, total=len(pkgs))) for b in bin_list]

            pt = os.path.join(args.target_directory, f"bin_list_{arch}.pkl")
            with open(pt, "wb") as f:
                pickle.dump(bins, f)
