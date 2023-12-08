#!/usr/bin/env python3

import sys
import logging
import argparse

from glob import glob
from typing import List
from multiprocessing import cpu_count


log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        "Prepare machine for benchmarking!",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--num-cpus", type=int, default=cpu_count(),
                        help="Number of CPUs to use. The rest are disabled.")
    parser.add_argument("--hyperthreading", action="store_true", default=False,
                        help="Control hyperthreading. Disabled by default.")
    return parser.parse_args()


def write_file(path, value):
    with open(path, "w") as f:
        f.write(value)


def get_online_cpus() -> List[int]:
    with open("/sys/devices/system/cpu/online", "r") as f:
        cpustr = f.readlines()
    if len(cpustr) != 1:
        raise RuntimeError("Unexpected format of /sys/devices/system/cpu/online")
    cpustr = cpustr[0].strip()
    cpus = []
    for cpu_group in cpustr.split(","):
        if "-" in cpu_group:
            start, end = cpu_group.split("-")
            cpus.extend(range(int(start), int(end) + 1))
        else:
            cpus.append(int(cpu_group))
    return cpus


def bring_all_cpus_online():
    log.info("Bringing all CPUs online...")
    write_file("/sys/devices/system/cpu/smt/control", "on")
    for cpu_path in glob("/sys/devices/system/cpu/cpu*/online"):
        write_file(cpu_path, "1")


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    log.info("Preparing machine for benchmarking...")
    bring_all_cpus_online()

    if args.hyperthreading:
        log.info("Enabling hyperthreading...")
        write_file("/sys/devices/system/cpu/smt/control", "on")
    else:
        log.info("Disabling hyperthreading...")
        write_file("/sys/devices/system/cpu/smt/control", "off")

    online_cpus = get_online_cpus()
    if args.num_cpus > len(online_cpus):
        raise RuntimeError("Not enough CPUs online!")
    want_cpus = online_cpus[:args.num_cpus]
    log.info("Using CPUs: %s", want_cpus)
    dont_want_cpus = online_cpus[args.num_cpus:]
    log.info("Disabling CPUs: %s", dont_want_cpus)
    for cpu in dont_want_cpus:
        write_file("/sys/devices/system/cpu/cpu%s/online" % cpu, "0")


if __name__ == "__main__":
    sys.exit(main())
