#!/usr/bin/env python3

import os
import sys
import logging
import argparse

from subprocess import check_output

log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser("Decode kernel stacktrace from dmesg")
    parser.add_argument("--output-file", default="kernel_stacktrace",
                        help="Output file containing the parsed stacktrace.")
    parser.add_argument("--linux-repo-path", default="/mydata/linux/linux",
                        help="Path to local Linux repo. It is assumed that"
                        " vmlinux is already built for the correct kernel.")
    return parser.parse_args()


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()

    dmesg_lines = check_output(["dmesg"], encoding="utf-8").splitlines()
    stacktrace_lines = dmesg_lines
    # in_stacktrace = False
    # for line in dmesg_lines:
    #     if "Call Trace:" in line:
    #         in_stacktrace = True
    #         stacktrace_lines.append(line)
    #     elif in_stacktrace and "RIP:" in line:
    #         break
    #     elif in_stacktrace:
    #         stacktrace_lines.append(line)
    tmp_file = "/tmp/kernel_stacktrace"
    with open("/tmp/kernel_stacktrace", "w") as f:
        f.write("\n".join(stacktrace_lines) + "\n")
    decode_stacktrace = os.path.join(args.linux_repo_path,
                                     "scripts/decode_stacktrace.sh")
    vmlinux = os.path.join(args.linux_repo_path, "vmlinux")
    out = check_output([decode_stacktrace, vmlinux, args.linux_repo_path],
                       stdin=open(tmp_file), encoding="utf-8")
    with open(args.output_file, "w") as f:
        f.write(out)


if __name__ == "__main__":
    sys.exit(main())
