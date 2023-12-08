#!/usr/bin/env python3

import os
import sys
import mmap
import random
import logging
import argparse

from subprocess import check_output

log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser("Create a file with 2+ extents and issue a read that crosses the extent boundary")
    parser.add_argument("--file", default="multi_extent_file.txt", type=str,
                        help="File to create")
    parser.add_argument("--direct-reader", required=True, type=str,
                        help="Path to the direct reader binary")
    return parser.parse_args()


def randbytes(size):
    return bytearray(random.getrandbits(8) for _ in range(size))


def create_multiextend_file(path):
    chunk_size = 5 * 1024 * 1024  # 5MB
    total_size = 500 * 1024 * 1024  # 1000MB

    for _ in range(0, total_size, chunk_size):
        data = randbytes(chunk_size)
        with open(path, 'ab') as f:
            f.write(data)
            f.flush()
            for _ in range(5):
                os.fsync(f.fileno())
        get_file_extents(path)


def get_file_extents(path):
    command = ["filefrag", "-v", "-s", path]
    output = check_output(command, text=True)
    lines = output.splitlines()
    extents = []

    for line in lines:
        if "extents found" in line:
            break
        if line.startswith("  "):
            line = line.strip()
            parts = line.split()
            extent = {
                "idx": int(parts[0][:-1]),
                "logical_start": int(parts[1][:-2]),
                "logical_end": int(parts[2][:-1]),
                "physical_start": int(parts[3][:-2]),
                "physical_end": int(parts[4][:-1]),
            }
            extent["length"] = extent["logical_end"] - extent["logical_start"] + 1
            extents.append(extent)

    return extents


def direct_io_read(direct_reader_cmd: str, filename:str,  offset: int, len: int):
    check_output([direct_reader_cmd, filename, str(offset), str(len)])

def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    path = args.file
    # log.info("Creating file %s", path)
    # create_multiextend_file(path)
    log.info("Getting extents for file %s", path)
    extents = get_file_extents(path)
    log.info("Extents: %s", extents)
    if (len(extents) < 2):
        log.error("File %s does not have 2+ extents", path)
        return 1
    if extents[1]["physical_start"] - extents[0]["physical_end"] < 2:
        log.error("Extents are not separated by a hole")
        return 1
    log.info("Preparing 4k read that crosses the boundary")
    read_offset = extents[0]["logical_end"] * 4096 + 2048
    read_length = 4096
    log.info("Reading %d bytes at offset %d", read_length, read_offset)
    direct_io_read(args.direct_reader, path, read_offset, read_length)


if __name__ == "__main__":
    sys.exit(main())
