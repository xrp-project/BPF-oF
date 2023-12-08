#!/usr/bin/env python3

import sys
import logging
import pathlib
import argparse

from yanniszark_common.cmdutils import run


log = logging.getLogger(__name__)


def mkdir_p(dir):
    pathlib.Path(dir).mkdir(parents=True, exist_ok=True)


def write_file(filepath: str, contents: str):
    with open(filepath, "w") as f:
        f.write(contents)


def parse_args():
    parser = argparse.ArgumentParser("Setup NVMEoF/TCP host")
    parser.add_argument("--target-ip", default="192.168.53.3", type=str,
                        help="IP of the target machine.")
    parser.add_argument("--target-port", default="4420", type=str,
                        help="Port of the target machine.")
    parser.add_argument("--transport-type", default="tcp",
                        choices=["tcp", "rdma"],
                        help="Transport type to use.")
    return parser.parse_args()


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    # From https://blogs.oracle.com/linux/post/nvme-over-tcp
    target_ip = args.target_ip
    target_port = args.target_port
    transport_type = args.transport_type

    log.info("Loading necessary kernel modules for NVMEoF with transport %s...",
             transport_type)
    if transport_type == "tcp":
        run(["modprobe", "nvme"])
        run(["modprobe", "nvme-tcp"])
    elif transport_type == "rdma":
        run(["modprobe", "nvme"])
        run(["modprobe", "nvme-rdma"])
    else:
        raise ValueError("Unknown transport type: %s" % transport_type)

    log.info("Connecting with target at '%s:%s'", target_ip, target_port)
    run(["nvme", "discover", "-t", transport_type, "-a", target_ip,
         "-s", target_port])
    connect_cmd = ["nvme", "connect", "-t", transport_type,
                   "-n", "nvmet-test", "-a", target_ip, "-s", target_port]
    if transport_type == "tcp":
        connect_cmd += ["--queue-size", "1024"]
    run(connect_cmd)


if __name__ == "__main__":
    sys.exit(main())
