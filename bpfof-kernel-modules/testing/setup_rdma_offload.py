#!/usr/bin/env python3

import sys
import logging
import argparse
import requests

from yanniszark_common.cmdutils import run


log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser("Setup RDMA offload for NVMEoF")
    return parser.parse_args()


def download(url):
    r = requests.get(url)
    return r.content


def download_to_file(url, path):
    with open(path, "wb") as f:
        f.write(download(url))


def disable_iommu():
    with open("/etc/default/grub", "r") as f:
        grubcfg_lines = f.readlines()
    edited_lines = []
    for line in grubcfg_lines:
        if line.startswith("GRUB_CMDLINE_LINUX_DEFAULT="):
            if "iommu=off" in line:
                log.info("iommu is already disabled")
                return
            # Add iommu=off to the end of the line
            line = line.strip()
            line = line[:-1] + " iommu=off\""
        edited_lines.append(line)
    with open("/etc/default/grub", "w") as f:
        f.writelines(edited_lines)
    run(["sudo", "update-grub"])
    log.info("Updated grub config")
    log.info("Please reboot for changes to take effect")


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    log.info("Disabling iommu")
    disable_iommu()
    log.info("Installing the Mellanox NVMEoF RDMA offload driver")
    log.info("This will restart the machine")
    # Download and run Haoyu's script from:
    # https://raw.githubusercontent.com/lei-houjyu/rocksdb/rubble/rubble/install-mlnx-ofed.sh
    download_to_file("https://raw.githubusercontent.com/lei-houjyu/rocksdb/rubble/rubble/install-mlnx-ofed.sh", "/tmp/install-mlnx-ofed.sh")
    # chmod +x
    run(["chmod", "+x", "/tmp/install-mlnx-ofed.sh"])
    # Run with sudo
    run(["sudo", "bash", "/tmp/install-mlnx-ofed.sh"])


if __name__ == "__main__":
    sys.exit(main())
