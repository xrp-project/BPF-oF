#!/usr/bin/env python3

import sys
import logging
import argparse

from yanniszark_common.cmdutils import run


log = logging.getLogger(__name__)

BLK_SIZE = 512
HUGEPAGE_SIZE = 2 * 1024 * 1024


def parse_args():
    parser = argparse.ArgumentParser(
        "Create or read a test file with 3 512-blocks for XRP.")
    parser.add_argument("--filename", default="xrp-test-file",
                        help="Name of the generated file.")
    parser.add_argument("--mode", choices=["read", "create"], default="create",
                        help="Operation mode. Create or read the file.")
    parser.add_argument("--syscall", choices=["read_bpfof", "read_xrp"],
                        default="read_xrp",
                        help="Which syscall to use to read the file.")
    parser.add_argument("--use-hugepages", action="store_true", default=False,
                        help="Use hugepage resubmission")
    # Add your arguments here
    return parser.parse_args()


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    filename = args.filename
    if args.mode == "create":
        log.info("Writing file '%s'...", filename)
        multiplier = BLK_SIZE if not args.use_hugepages else HUGEPAGE_SIZE
        block_1 = BLK_SIZE * b'\x01'
        block_2 = multiplier * b'\x02'
        block_3 = multiplier * b'\x03'

        with open(filename, "wb") as f:
            f.write(block_1)
            f.write(block_2)
            f.write(block_3)
    else:
        log.info("Reading file '%s'...", filename)
        # xrp_read is implemented in C because I don't know how to allocate a
        # memory-aligned buffer in Python (surprisingly difficult!).
        if args.syscall == "read_bpfof":
            run(["make", "simple_read_bpfof.out"])
            run(["./simple_read_bpfof.out", filename])
        elif args.syscall == "read_xrp":
            run(["make", "simple_xrp.out"])
            run(["./simple_xrp.out", filename])
        else:
            raise ValueError("Unknown syscall: {}".format(args.syscall))


if __name__ == "__main__":
    sys.exit(main())
