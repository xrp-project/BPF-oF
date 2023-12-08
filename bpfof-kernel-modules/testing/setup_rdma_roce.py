#!/usr/bin/env python3

import sys
import logging
import argparse

from subprocess import check_output
from yanniszark_common.cmdutils import run


log = logging.getLogger(__name__)


def apt_get_install(pkgs):
    if isinstance(pkgs, str):
        pkgs = [pkgs]
    run(["apt-get", "update"])
    run(["apt-get", "install", "-y"] + pkgs)


def parse_args():
    parser = argparse.ArgumentParser("Setup RDMA RoCE.")
    parser.add_argument("--net-if", default="ens3", type=str,
                        help="Network interface to use.")
    parser.add_argument("--roce-if-name", default="rxe_0", type=str,
                        help="Name of the RoCE interface that will be"
                             " created.")
    return parser.parse_args()


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    net_if = args.net_if
    roce_if_name = args.roce_if_name

    log.info("Installing necessary packages...")
    # sudo apt-get install libibverbs1 ibverbs-utils librdmacm1 libibumad3 ibverbs-providers rdma-core
    pkgs = ["libibverbs1", "ibverbs-utils", "librdmacm1", "libibumad3",
            "ibverbs-providers", "rdma-core", "perftest"]
    apt_get_install(pkgs)

    log.info("Loading necessary kernel modules...")
    # sudo modprobe rdma_rxe
    check_output(["modprobe", "rdma_rxe"])

    log.info("Creating RoCE interface '%s'...", roce_if_name)
    # rdma link add rxe_0 type rxe netdev ens33
    cmd = ["rdma", "link", "add", roce_if_name,
           "type", "rxe", "netdev", net_if]
    check_output(cmd)

    log.info("Done.")


if __name__ == "__main__":
    sys.exit(main())
