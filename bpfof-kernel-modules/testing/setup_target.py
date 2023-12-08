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
    parser = argparse.ArgumentParser("Setup NVMEoF target")
    parser.add_argument("--disk", default="/dev/nvme0n1",
                        help="Disk to use as the target device.")
    parser.add_argument("--target-ip", default="192.168.53.3", type=str,
                        help="IP of the target machine.")
    parser.add_argument("--target-port", default="4420", type=str,
                        help="Port of the target machine.")
    parser.add_argument("--transport-type", default="tcp",
                        choices=["tcp", "rdma"],
                        help="Transport type to use.")
    parser.add_argument("--rdma-offload", default=False, action="store_true",
                        help="Enable RDMA offload on the target.")
    return parser.parse_args()


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    # From https://blogs.oracle.com/linux/post/nvme-over-tcp
    disk = args.disk
    target_ip = args.target_ip
    target_port = args.target_port
    transport_type = args.transport_type
    rdma_offload_enabled = args.rdma_offload

    if rdma_offload_enabled and transport_type != "rdma":
        raise ValueError("RDMA offload is only supported with RDMA transport.")

    log.info("Loading necessary kernel modules for NVMEoF with %s transport...",
             transport_type)
    if transport_type == "tcp":
        run(["modprobe", "nvme_tcp"])
        run(["modprobe", "nvmet"])
        run(["modprobe", "nvmet-tcp"])
    elif transport_type == "rdma":
        if rdma_offload_enabled:
            run(["modprobe", "-r", "nvme"])
            run(["modprobe", "nvme", "num_p2p_queues=2"])
        run(["modprobe", "nvmet"])
        run(["modprobe", "nvmet-rdma"])
        run(["modprobe", "nvme-rdma"])
    else:
        raise ValueError("Unknown transport type: %s" % transport_type)

    log.info("Exposing disk '%s' at '%s:%s'", disk, target_ip, target_port)
    mkdir_p("/sys/kernel/config/nvmet/subsystems/nvmet-test")
    write_file("/sys/kernel/config/nvmet/subsystems/nvmet-test/attr_allow_any_host", "1")
    if rdma_offload_enabled:
        log.info("Enabling RDMA offload on the target.")
        write_file("/sys/kernel/config/nvmet/subsystems/nvmet-test/attr_offload", "1")
    mkdir_p("/sys/kernel/config/nvmet/subsystems/nvmet-test/namespaces/1")
    write_file("/sys/kernel/config/nvmet/subsystems/nvmet-test/namespaces/1/device_path",
               disk)
    write_file("/sys/kernel/config/nvmet/subsystems/nvmet-test/namespaces/1/enable",
               "1")
    mkdir_p("/sys/kernel/config/nvmet/ports/1")
    write_file("/sys/kernel/config/nvmet/ports/1/addr_traddr", target_ip)
    write_file("/sys/kernel/config/nvmet/ports/1/addr_trtype", transport_type)
    write_file("/sys/kernel/config/nvmet/ports/1/addr_trsvcid", target_port)
    write_file("/sys/kernel/config/nvmet/ports/1/addr_adrfam", "ipv4")
    run(["ln", "-sf", "/sys/kernel/config/nvmet/subsystems/nvmet-test/",
         "/sys/kernel/config/nvmet/ports/1/subsystems/nvmet-test"])


if __name__ == "__main__":
    sys.exit(main())
