#!/usr/bin/env python3

import os
import sys
import fabric
import logging
import argparse

from typing import List

log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser("Setup NVMEoF for given host-target!")
    parser.add_argument("--host-ip", type=str, required=True,
                        help="IP address of the host machine.")
    parser.add_argument("--target-ip", type=str, required=True,
                        help="IP address of the target machine.")
    return parse_args()


def run_script_remotely(ip: str, cmd: List[str], root=False):
    """Run a local script on a remote machine."""
    log.info("Running command on %s: %s", ip, cmd)
    # 1. Move the local script to the remote machine
    # 2. Run the command on the remote machine
    with fabric.Connection(ip) as conn:
        local_path = cmd[0]
        if cmd[0] in ["python", "python3"]:
            local_path = cmd[1]
        if not os.path.exists(local_path):
            raise ValueError("Script path does not exist: %s" % local_path)
        remote_path = os.path.join("/tmp", os.path.basename(local_path))
        conn.put(local_path, remote=remote_path)
        conn.run(["chmod", "+x", remote_path])
    run_remotely(ip, cmd, root=root)


def run_remotely(ip: str, cmd: List[str], root=False):
    """Run a command on a remote machine."""
    with fabric.Connection(ip) as conn:
        if root:
            cmd = ["sudo"] + cmd
        res = conn.run(cmd)
    return res


def setup_target(ip: str):
    # Get internal IP address
    internal_ip = run_remotely(ip, ["getent", "hosts", "nvmeof-target"]).stdout.splitlines()[0].split()[0]
    disk = "/dev/nvme1n1"
    # Setup target
    run_script_remotely(ip, ["./setup_target.sh", "--target-ip", internal_ip,
                             "--disk", disk], root=True)


def setup_host(ip: str):
    # Get internal IP address
    internal_ip = run_remotely(ip, ["getent", "hosts", "nvmeof-host"]).stdout.splitlines()[0].split()[0]
    disk = "/dev/nvme2n1"
    # Setup target
    run_script_remotely(ip, ["./setup_target.sh", "--target-ip", internal_ip,
                             "--disk", disk], root=True)


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    host_ip = args.host_ip
    target_ip = args.target_ip
    setup_target(target_ip)
    setup_host(host_ip)


if __name__ == "__main__":
    sys.exit(main())
