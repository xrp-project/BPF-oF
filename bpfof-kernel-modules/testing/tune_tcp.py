#!/usr/bin/env python3

import sys
import logging
import argparse

from yanniszark_common.cmdutils import run


log = logging.getLogger(__name__)


def write_file(filepath: str, contents: str):
    with open(filepath, "w") as f:
        f.write(contents)


def parse_args():
    parser = argparse.ArgumentParser("Tune TCP settings for NVMEoF/TCP")
    return parser.parse_args()


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    sysctl_overrides = {
        "net.core.rmem_default": "100000000",  # 100MB
        "net.core.rmem_max": "1000000000",  # 100MB
        "net.core.wmem_default": "100000000",  # 100MB
        "net.core.wmem_max": "1000000000",  # 1GB
        "net.core.optmem_max": "1000000000",  # 1GB
        "net.ipv4.tcp_rmem": "10000000 10000000 1000000000",
        "net.ipv4.tcp_wmem": "10000000 10000000 1000000000",
        "net.core.netdev_max_backlog": "40000",
        "net.ipv4.tcp_window_scaling": "0",
    }
    for key, value in sysctl_overrides.items():
        run(["sysctl", "-w", "%s=%s" % (key, value)])
    log.info("Successfully tuned TCP settings for NVMEoF/TCP")


if __name__ == "__main__":
    sys.exit(main())
