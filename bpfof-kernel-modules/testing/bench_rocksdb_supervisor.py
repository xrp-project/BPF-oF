#!/usr/bin/env python3

import os
import sys
import time
import json
import logging
import argparse

from typing import List, Union
from yanniszark_common.cmdutils import run
from cloudlab_client.client import CloudlabClient, CloudlabNode
from subprocess import check_output, DEVNULL, CalledProcessError, Popen, PIPE, TimeoutExpired

log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser("Supervise a RocksDB benchmark. Restart"
                                     " the benchmark if the machines crash.")
    parser.add_argument("--cloudlab-experiment", type=str, required=True,
                        help="Name of the Cloudlab experiment.")
    parser.add_argument("--transport", choices=["tcp", "rdma", "local"],
                        default="tcp", help="Transport type to use")
    parser.add_argument("--rdma-offload", action="store_true", default=False,
                        help="Enable RDMA offload")
    parser.add_argument("--rdma-offload-machines", action="store_true",
                        default=False, help="Machine type r6525")
    parser.add_argument("--first-time", default=False, action="store_true",
                        help="Whether this is the first time running the benchmark")
    parser.add_argument("--db", choices=["rocksdb", "rocksdb_bloom",
                                         "rocksdb_trace_cluster41",
                                         "rocksdb_trace_cluster45"],
                        default="rocksdb", help="Which database to use")
    parser.add_argument("--bench-script", type=str, default=None,
                        help="Benchmark script on host. Inferred if not set.")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    return parser.parse_args()


PROFILE_SETTINGS = {
    "optane-plus-client": {
        "host": "client-node",
        "target": "optane-node",
        "target_disk": "/dev/nvme0n1",
    },
    "nvmeof-bench": {
        "host": "nvmeof-host",
        "target": "nvmeof-target",
        "target_disk": "/dev/nvme1n1",
    }
}


def async_remote_run(hostname: str, cmd: Union[str, List[str]]) -> Popen:
    if isinstance(cmd, str):
        cmd = [cmd]
    process = Popen(["ssh", "-A", hostname] + cmd, text=True,
                    stdout=PIPE, stderr=PIPE)
    return process


def remote_check_output(hostname: str, cmd: Union[str, List[str]],
                        connect_timeout=None, retries=0) -> str:
    if isinstance(cmd, str):
        cmd = [cmd]
    while retries >= 0:
        retries -= 1
        try:
            ssh_prefix = ["ssh", "-A"]
            if connect_timeout:
                ssh_prefix += ["-o", "ConnectTimeout=%s" % connect_timeout]
            ssh_prefix += [hostname]
            process = run(ssh_prefix + cmd, text=True, capture_output=True,
                          timeout=connect_timeout)
            return process.stdout
        except TimeoutExpired as e:
            log.debug("Command timed out: %s" % " ".join(e.cmd))
            raise e
        except CalledProcessError as e:
            log.error("Command failed: %s" % " ".join(e.cmd))
            log.error("Return code: %s" % e.returncode)
            log.error("Stdout: %s" % e.stdout)
            log.error("Stderr: %s" % e.stderr)
            raise e


def has_machine_crashed(hostname: str) -> bool:
    try:
        out = remote_check_output(hostname, "dmesg", connect_timeout=30)
        for line in out.splitlines():
            if "------------[ cut here ]------------" in line:
                return True
        return False
    except (TimeoutExpired, CalledProcessError):
        return True


def wait_until_machine_reachable(hostname: str) -> None:
    while True:
        try:
            out = remote_check_output(hostname, ["echo", "success"],
                                      connect_timeout=10)
            if out.strip() != "success":
                log.debug("Got unexpected output from ssh: %s" % out)
                continue
            time.sleep(30)
            return
        except Exception as e:
            log.debug("Got exception while waiting: %s" % e)
            log.info("Waiting for %s to be reachable..." % hostname)
            time.sleep(20)


def fix_target(hostname: str, disk_path: str, db="rocksdb") -> None:
    log.info("Fixing target...")

    log.info("Running fsck on %s..." % disk_path)
    cmd = ["sudo", "fsck", "-y", disk_path]
    remote_check_output(hostname, cmd, retries=1)

    mountpoint = "/nvme"
    log.info("Mounting %s at %s..." % (disk_path, mountpoint))
    cmd = ["sudo", "mkdir", "-p", mountpoint]
    remote_check_output(hostname, cmd)
    cmd = ["sudo", "mount", disk_path, mountpoint]
    remote_check_output(hostname, cmd)

    log.info("Recreating databases...")
    temp_db = "rocksdb_temp"
    temp_db_path = os.path.join(mountpoint, temp_db)
    db_path = os.path.join(mountpoint, db)
    cmd = ["rm", "-rf", temp_db_path]
    remote_check_output(hostname, cmd)
    cmd = ["rsync", "-avpl", "--delete", "--recursive",
           db_path + "/", temp_db_path]
    log.info("Running rsync command: %s" % " ".join(cmd))
    remote_check_output(hostname, cmd)

    log.info("Unmounting %s..." % mountpoint)
    cmd = ["sudo", "umount", mountpoint]
    remote_check_output(hostname, cmd)


def start_host_benchmark(hostname: str, bench_type="tcp_ssd",
                         bench_script=None,
                         rdma_offload=False) -> Popen:
    phd_repo_path = "/mydata/phd"
    testing_dir = os.path.join(phd_repo_path,
                               "projects/nvmeof-xrp/src/xrp-metadata/testing")
    if bench_script:
        bench_script = os.path.join(testing_dir, bench_script)
    elif bench_type == "tcp_ssd":
        bench_script = os.path.join(testing_dir, "nvmeof_tcp_ssd.sh")
    elif bench_type == "rdma_ssd" and rdma_offload:
        bench_script = os.path.join(testing_dir, "nvmeof_rdma_ssd_offload.sh")
    elif bench_type == "rdma_ssd":
        bench_script = os.path.join(testing_dir, "nvmeof_rdma_ssd.sh")
    elif bench_type == "tcp_optane":
        bench_script = os.path.join(testing_dir, "nvmeof_tcp_optane.sh")
    elif bench_type == "local_ssd":
        bench_script = os.path.join(testing_dir, "local_ssd.sh")
    else:
        raise ValueError("Invalid bench_type: %s" % bench_type)
    log.info("Starting host benchmark...")
    return async_remote_run(hostname, bench_script)


def setup_host(hostname: str, cloudlab_profile: str, transport: str,
               rdma_offload=False, rdma_offload_machines=False) -> None:
    phd_repo_path = "/mydata/phd"
    testing_dir = os.path.join(phd_repo_path,
                               "projects/nvmeof-xrp/src/xrp-metadata/testing")
    quick_start_script = os.path.join(testing_dir, "quick_start.py")
    log.info("Setting up host...")
    cmd = ["python3", quick_start_script,
           "--mode", "host",
           "--transport", transport,
           "--environment", "cloudlab-" + cloudlab_profile,
           "--use-hugepages", "True",
           "--application", "rocksdb"]
    if rdma_offload:
        cmd += ["--rdma-offload"]
    if rdma_offload_machines:
        cmd += ["--rdma-offload-machines"]
    remote_check_output(hostname, cmd)


def setup_target(hostname: str, cloudlab_profile: str, transport: str,
                 rdma_offload=False, rdma_offload_machines=False) -> None:
    phd_repo_path = "/mydata/phd"
    testing_dir = os.path.join(phd_repo_path,
                               "projects/nvmeof-xrp/src/xrp-metadata/testing")
    quick_start_script = os.path.join(testing_dir, "quick_start.py")
    log.info("Setting up target...")
    cmd = ["python3", quick_start_script,
           "--mode", "target",
           "--transport", transport,
           "--environment",  "cloudlab-" + cloudlab_profile,
           "--use-hugepages", "True",
           "--application", "rocksdb"]
    if rdma_offload:
        cmd += ["--rdma-offload"]
    if rdma_offload_machines:
        cmd += ["--rdma-offload-machines"]
    remote_check_output(hostname, cmd)


def run_and_monitor_nvmeof(
        host_node: CloudlabNode,
        target_node: CloudlabNode,
        transport: str,
        cloudlab_client: CloudlabClient,
        experiment_name: str,
        profile_name: str,
        bench_type: str,
        db: str,
        target_disk: str,
        bench_script: str = None,
        rdma_offload=False,
        rdma_offload_machines=False):
    while (True):
        log.info("Setting up machines...")
        setup_target(target_node.address, profile_name, transport,
                     rdma_offload=rdma_offload,
                     rdma_offload_machines=rdma_offload_machines)
        setup_host(host_node.address, profile_name, transport,
                   rdma_offload=rdma_offload,
                   rdma_offload_machines=rdma_offload_machines)

        log.info("Starting benchmark...")
        bench_process = start_host_benchmark(host_node.address, bench_type,
                                             bench_script=bench_script,
                                             rdma_offload=rdma_offload)

        log.info("Checking that the experiment is in a good state...")
        while not any(map(has_machine_crashed,
                          [host_node.address, target_node.address])):
            return_code = bench_process.poll()
            if return_code is not None:
                log.info("Benchmark exited with code %s" % return_code)
                if return_code != 0:
                    stdout, stderr = bench_process.communicate()
                    log.error("Benchmark exited with bad code!")
                    log.error("Stdout: %s" % stdout)
                    log.error("Stderr: %s" % stderr)
                    return 1
                return
            log.debug("No machines have crashed, sleeping...")
            time.sleep(60)
        log.warning("A machine has crashed, fixing it...")
        log.info("Rebooting experiments nodes...")
        cloudlab_client.experiment_nodes_restart(experiment_name)

        log.info("Waiting for the nodes to reboot...")
        wait_until_machine_reachable(target_node.address)
        wait_until_machine_reachable(host_node.address)

        log.info("Fixing target...")
        fix_target(target_node.address,
                   target_disk,
                   db=db)


def run_and_monitor_local(
        target_node: CloudlabNode,
        cloudlab_client: CloudlabClient,
        experiment_name: str,
        profile_name: str,
        bench_type: str,
        db: str,
        target_disk: str):
    while (True):
        log.info("Setting up machines...")
        setup_target(target_node.address, profile_name, "local")

        log.info("Starting benchmark...")
        bench_process = start_host_benchmark(target_node.address, bench_type)

        log.info("Checking that the experiment is in a good state...")
        while not any(map(has_machine_crashed, [target_node.address])):
            return_code = bench_process.poll()
            if return_code is not None:
                log.info("Benchmark exited with code %s" % return_code)
                if return_code != 0:
                    stdout, stderr = bench_process.communicate()
                    log.error("Benchmark exited with bad code!")
                    log.error("Stdout: %s" % stdout)
                    log.error("Stderr: %s" % stderr)
                    return 1
                return
            log.debug("No machines have crashed, sleeping...")
            time.sleep(60)
        log.warning("A machine has crashed, fixing it...")
        log.info("Rebooting experiments nodes...")
        cloudlab_client.experiment_nodes_restart(experiment_name)

        log.info("Waiting for the nodes to reboot...")
        wait_until_machine_reachable(target_node.address)

        log.info("Fixing target...")
        fix_target(target_node.address,
                   target_disk,
                   db=db)


def main():
    global log
    args = parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.debug:
        log.setLevel(logging.DEBUG)
    if args.rdma_offload and args.transport != "rdma":
        raise ValueError("RDMA offload is only supported with RDMA transport.")
    log.info("Using DB: %s" % args.db)
    log.info("Logging in to CloudLab...")
    username = os.environ.get("CLOUDLAB_USERNAME", "yannisz")
    if "CLOUDLAB_PASSWORD" not in os.environ:
        raise ValueError("CLOUDLAB_PASSWORD environment variable not set")
    password = os.environ.get("CLOUDLAB_PASSWORD")
    cloudlab_client = CloudlabClient()
    cloudlab_client.login(username, password)

    log.info("Getting and verifying experiment...")
    experiment_name = args.cloudlab_experiment
    experiment = cloudlab_client.experiment_get(experiment_name)
    experiment_nodes = cloudlab_client.experiment_list_nodes(experiment_name)
    experiment_node_names = [n.name for n in experiment_nodes]
    if experiment.profile_name not in ["optane-plus-client", "nvmeof-bench"]:
        raise ValueError("Unknown profile name: %s" % experiment.profile_name)
    if set(experiment_node_names) != set([PROFILE_SETTINGS[experiment.profile_name]["host"], PROFILE_SETTINGS[experiment.profile_name]["target"]]):
        raise ValueError("Unexpected nodes: %s" % experiment_node_names)

    host_node = [n for n in experiment_nodes
                 if n.name == PROFILE_SETTINGS[experiment.profile_name]["host"]][0]
    target_node = [n for n in experiment_nodes
                   if n.name == PROFILE_SETTINGS[experiment.profile_name]["target"]][0]

    if args.transport == "tcp":
        if experiment.profile_name == "optane-plus-client":
            bench_type = "tcp_optane"
        elif experiment.profile_name == "nvmeof-bench":
            bench_type = "tcp_ssd"
        else:
            raise ValueError("Unknown profile name: %s" % experiment.profile_name)
    elif args.transport == "rdma":
        if experiment.profile_name == "optane-plus-client":
            bench_type = "rdma_optane"
        elif experiment.profile_name == "nvmeof-bench":
            bench_type = "rdma_ssd"
        else:
            raise ValueError("Unknown profile name: %s" % experiment.profile_name)
    elif args.transport == "local":
        if experiment.profile_name == "optane-plus-client":
            bench_type = "local_optane"
        elif experiment.profile_name == "nvmeof-bench":
            bench_type = "local_ssd"
        else:
            raise ValueError("Unknown profile name: %s" % experiment.profile_name)
    log.info("Using bench_type %s" % bench_type)

    target_disk = PROFILE_SETTINGS[experiment.profile_name]["target_disk"]
    if args.rdma_offload_machines:
        target_disk = "/dev/nvme0n1"

    log.info("Rebooting experiment nodes to get to a known good state...")
    cloudlab_client.experiment_nodes_restart(experiment_name)
    log.info("Waiting for the nodes to reboot...")
    wait_until_machine_reachable(target_node.address)
    wait_until_machine_reachable(host_node.address)
    if not args.first_time:
        log.info("Testing fixing target...")
        fix_target(target_node.address, target_disk, db=args.db)
    log.info("Starting benchmark with supervisor...")
    if args.transport != "local":
        run_and_monitor_nvmeof(host_node, target_node, args.transport,
                               cloudlab_client, experiment_name,
                               experiment.profile_name, bench_type, args.db,
                               target_disk,
                               bench_script=args.bench_script,
                               rdma_offload=args.rdma_offload,
                               rdma_offload_machines=args.rdma_offload_machines)
    else:
        run_and_monitor_local(target_node, cloudlab_client, experiment_name,
                              experiment.profile_name, bench_type, args.db,
                              target_disk)


if __name__ == "__main__":
    sys.exit(main())
