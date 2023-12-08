#!/usr/bin/env python3

import os
import sys
import json
import logging
import argparse

from typing import Union, List
from contextlib import suppress
from yanniszark_common.cmdutils import run
from yanniszark_common.blkutils import has_filesystem
from subprocess import check_output, CalledProcessError, TimeoutExpired


log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        "Quick start script to setup BPFoF")
    parser.add_argument("--mode", choices=["host", "target"], required=True,
                        help="Mode to run in")
    parser.add_argument("--transport", choices=["tcp", "rdma", "local"],
                        default="tcp",
                        help="Transport type to use")
    parser.add_argument("--environment",
                        required=True,
                        choices=["vm", "cloudlab-nvmeof-bench",
                                 "cloudlab-optane-plus-client"],
                        help="Environment the script is running in")
    parser.add_argument("--rdma-offload-machines", action="store_true",
                        default=False, help="Machine type r6525")
    parser.add_argument("--rdma-offload", action="store_true", default=False,
                        help="Enable RDMA offload")
    parser.add_argument("--use-hugepages", default=True,
                        help="Use hugepages for the target.")
    parser.add_argument("--application", default="simple-xrp",
                        choices=["simple-xrp", "simple-xrp-hugepage",
                                 "bpf-kv", "rocksdb"])
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Enable debug mode.")
    # Add your arguments here
    return parser.parse_args()


def remote_check_output(cmd: Union[str, List[str]], ip: str,
                        connect_timeout=None, retries=0) -> str:
    if isinstance(cmd, str):
        cmd = [cmd]
    while retries >= 0:
        retries -= 1
        try:
            ssh_prefix = ["ssh", "-A"]
            ssh_prefix += ["-o", "StrictHostKeyChecking=no"]
            if connect_timeout:
                ssh_prefix += ["-o", "ConnectTimeout=%s" % connect_timeout]
            ssh_prefix += [ip]
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


def parse_cpu_string(cpu_string: str):
    parts = cpu_string.split(",")
    cpu_list = []
    for part in parts:
        if "-" in part:
            start, end = part.split("-")
            cpu_list.extend(list(range(int(start), int(end) + 1)))
        else:
            cpu_list.append(int(part))
    return cpu_list


def disable_extra_numa_cpus(ip: str = None):
    cmd = ["lscpu", "--json"]
    if ip:
        out = remote_check_output(cmd, ip)
    else:
        out = check_output(cmd, text=True)
    lscpu_json = json.loads(out)
    numa0_cpus = []
    online_cpus = []
    for field in lscpu_json["lscpu"]:
        if field["field"] == "NUMA node0 CPU(s):":
            numa0_cpus = parse_cpu_string(field["data"])
        elif field["field"] == "On-line CPU(s) list:":
            online_cpus = parse_cpu_string(field["data"])
    if len(numa0_cpus) == 0:
        raise RuntimeError("Could not find NUMA node0 CPU(s)")
    if len(online_cpus) == 0:
        raise RuntimeError("Could not find On-line CPU(s) list")
    for cpu in online_cpus:
        if cpu not in numa0_cpus:
            if ip:
                cmd = ["sudo", "sh", "-c", "\"echo 0 > /sys/devices/system/cpu/cpu%d/online\"" % cpu]
                remote_check_output(cmd, ip)
            else:
                cmd = ["sudo", "sh", "-c", "echo 0 > /sys/devices/system/cpu/cpu%d/online" % cpu]
                check_output(cmd, text=True)


def disable_hyperthreading(ip=None):
    # echo off | sudo tee /sys/devices/system/cpu/smt/control
    cmd = ["sudo sh -c \"echo off | tee /sys/devices/system/cpu/smt/control\""]
    if ip:
        remote_check_output(cmd, ip)
    else:
        check_output(cmd, shell=True)


def get_script_dir():
    return os.path.dirname(os.path.realpath(__file__))


def get_xrp_metadata_and_testing_dirs():
    cwd_testing = get_script_dir()
    assert os.path.basename(cwd_testing) == "testing", "Script must be run from testing directory"
    cwd = os.path.dirname(cwd_testing)
    assert os.path.basename(cwd) == "xrp-metadata", "Script must be run from xrp-metadata/testing directory"
    return cwd, cwd_testing


def setup_rdma_roce():
    cmd = ["sudo",
           os.path.expanduser("~/xrp-metadata/testing/setup_rdma_roce.py")]
    run(cmd)


def setup_host(disk: str, target_ip: str, transport: str, sync_dir: str):
    cwd, cwd_testing = get_xrp_metadata_and_testing_dirs()
    run(["sudo", "python3", "./setup_host.py",
        "--target-ip", target_ip, "--transport", transport],
        cwd=cwd_testing)
    run(["sudo", "mkdir", "-p", "/nvme"])
    run(["sudo", "mount", disk, "/nvme"])
    with suppress(Exception):
        run(["sudo", "rmmod", "xrp_metadata_host"], cwd=cwd)
    run(["make"], cwd=cwd)
    run(["sudo", "insmod", "./xrp_metadata_host.ko", "ip=%s" %
        target_ip, "sync_dir=%s" % sync_dir], cwd=cwd)


def allocate_hugepages(num_hugepages=100):
    cmd = ["sudo", "sh", "-c",
           "echo %s > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages" % num_hugepages]
    check_output(cmd)


def setup_rocksdb_databases(disk: str):
    if not has_filesystem(disk):
        log.info("Disk %s doesn't have FS. Formatting..." % disk)
        run(["sudo", "mkfs.ext4", disk])
    run(["sudo", "mkdir", "-p", "/nvme"])
    run(["sudo", "mount", disk, "/nvme"])
    run(["sudo", "chown", "-R", "%s:" % os.getlogin(), "/nvme"])
    if os.path.exists("/nvme/rocksdb"):
        log.info("RocksDB database already exists. Skipping setup.")
        run(["sudo", "umount", "/nvme"])
        return

    log.info("Setting up RocksDB databases...")
    log.info("Installing and setting up rclone...")
    run(["sudo", "apt-get", "install", "-y", "rclone"])
    run(["rclone", "config", "create", "b2", "b2",
         "account", "<redacted>",
         "key", "<redacted>"])
    b2_to_local_paths = {
        "rocksdb_single_init": "rocksdb",
        "bloom_db": "rocksdb_bloom",
    }

    log.info("Syncing databases...")
    for b2_path, local_path in b2_to_local_paths.items():
        cmd = ["rclone", "sync",
               "--transfers", str(os.cpu_count()),
               "--checkers", str(os.cpu_count()),
               os.path.join("b2:bpfof-paper", b2_path),
               os.path.join("/nvme", local_path)]
        run(cmd)
    run(["rsync", "-avpl", "--delete", "/nvme/rocksdb/", "/nvme/rocksdb_temp"])
    log.info("Syncing done. Unmounting...")
    run(["sudo", "umount", "/nvme"])


def setup_target(disk: str, target_ip: str, transport: str, prog_path: str,
                 bpf_fs_path: str, use_hugepages: bool, rdma_offload=False):
    cwd, cwd_testing = get_xrp_metadata_and_testing_dirs()
    cmd = ["sudo", "python3", "./setup_target.py", "--disk", disk,
           "--target-ip", target_ip, "--transport", transport]
    if rdma_offload:
        cmd.append("--rdma-offload")
    run(cmd, cwd=cwd_testing)
    run(["make"], cwd=cwd_testing)
    run(["sudo", "./xrp_loader.out", prog_path, os.path.dirname(bpf_fs_path)],
        cwd=cwd_testing)
    with suppress(Exception):
        run(["sudo", "rmmod", "xrp_metadata_target"], cwd=cwd)
    run(["make"], cwd=cwd)
    use_hugepages_str = "1" if use_hugepages else "0"
    run(["sudo", "insmod", "./xrp_metadata_target.ko",
         "bpf_pathname=%s" % bpf_fs_path,
         "use_hugepages=%s" % use_hugepages_str], cwd=cwd)


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    if args.rdma_offload and not args.rdma_offload_machines:
        raise ValueError("RDMA offload is only supported on r6525 machines")
    if args.rdma_offload and args.transport != "rdma":
        raise ValueError("RDMA offload is only supported with RDMA transport")
    transport = args.transport
    if args.application == "simple-xrp":
        prog_path = "simple_xrp.o"
        bpf_fs_path = "/sys/fs/bpf/simple_xrp/xrp_prog"
        sync_dir = "/nvme"
    elif args.application == "simple-xrp-hugepage":
        prog_path = "simple_xrp_hugepage.o"
        bpf_fs_path = "/sys/fs/bpf/simple_xrp/xrp_prog"
        sync_dir = "/nvme"
    elif args.application == "bpf-kv":
        prog_path = "/mydata/BPF-KV/xrp-bpf/get.o"
        bpf_fs_path = "/sys/fs/bpf/bpf-kv/oliver_agg"
        sync_dir = "/nvme"
    elif args.application == "rocksdb":
        prog_path = "/mydata/rocksdb/ebpf/parser.o"
        bpf_fs_path = "/sys/fs/bpf/rocksdb/prog"
        sync_dir = "/nvme/rocksdb_temp"
    else:
        raise ValueError("Invalid application")

    if args.environment == "vm":
        target_ip = "192.168.53.3"
        target_disk = "/dev/nvme0n1"
        host_disk = "/dev/nvme0n1"
    elif args.environment == "cloudlab-nvmeof-bench" and args.rdma_offload_machines:
        target_ip = check_output(["getent", "hosts", "nvmeof-target"]).split()[0].decode()
        target_disk = "/dev/nvme0n1"
        host_disk = "/dev/nvme1n1"
    elif args.environment == "cloudlab-nvmeof-bench":
        target_ip = check_output(["getent", "hosts", "nvmeof-target"]).split()[0].decode()
        target_disk = "/dev/nvme1n1"
        host_disk = "/dev/nvme2n1"
    elif args.environment == "cloudlab-optane-plus-client":
        target_ip = check_output(["getent", "hosts", "optane-node"]).split()[0].decode()
        target_disk = "/dev/nvme0n1"
        host_disk = "/dev/nvme2n1"
    else:
        raise ValueError("Invalid environment: '%s'" % args.environment)

    if transport == "rdma" and args.environment == "vm":
        setup_rdma_roce()

    cwd, cwd_testing = get_xrp_metadata_and_testing_dirs()

    ########
    # Host #
    ########
    if args.mode == "host":
        setup_host(host_disk, target_ip, transport, sync_dir)
        if args.environment in ["cloudlab-nvmeof-bench",
                                "cloudlab-optane-plus-client"]:
            if transport == "tcp":
                # Pin threads
                cloudlab_profile = args.environment[len("cloudlab-"):]
                log.info("Pinning TCP connections to cores...")
                pin_script = os.path.join(cwd_testing,
                                          "pin_nvmeof_tcp_connection.py")
                cmd = ["python3", pin_script,
                       "--disk-path", host_disk,
                       "--cores", "5",
                       "--target-ip", target_ip,
                       "--cloudlab-profile", cloudlab_profile]
                run(cmd)
            elif transport == "rdma":
                # Disable hyperthreading and extra NUMAs
                disable_hyperthreading()
                disable_hyperthreading(target_ip)
                disable_extra_numa_cpus()
                disable_extra_numa_cpus(target_ip)


    ##########
    # Target #
    ##########
    elif args.mode == "target":
        if transport == "local" and args.application == "rocksdb":
            setup_rocksdb_databases(target_disk)
            allocate_hugepages()
            run(["sudo", "mount", target_disk, "/nvme"])
            return
        if args.application == "rocksdb":
            setup_rocksdb_databases(target_disk)
        setup_target(target_disk, target_ip, transport, prog_path, bpf_fs_path,
                     args.use_hugepages, rdma_offload=args.rdma_offload)
        if args.environment == "cloudlab-optane-plus-client":
            prepare_bench_script = os.path.join(cwd_testing,
                                                "prepare_bench.py")
            run(["sudo", "python3", prepare_bench_script, "--num-cpus", "10"])
    else:
        raise ValueError("Invalid mode")

    if args.debug:
        cmd = ['sudo sh -c \'echo "file drivers/nvme/* +p" > /proc/dynamic_debug/control\'']
        run(cmd, shell=True)


if __name__ == "__main__":
    sys.exit(main())
