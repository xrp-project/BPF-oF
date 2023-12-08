#!/usr/bin/env python3

import sys
import json
import fabric
import logging
import argparse

from time import sleep
from typing import List
from subprocess import check_output, Popen, DEVNULL

log = logging.getLogger(__name__)


def get_default_target_ip():
    # getent hosts nvmeof-target | awk '{print $1}'
    ip = None
    try:
        ip = check_output(["getent", "hosts", "nvmeof-target"]).split()[0].decode()
    except Exception:
        pass
    try:
        ip = check_output(["getent", "hosts", "optane-node"]).split()[0].decode()
    except Exception:
        pass
    return ip


def remote_check_output(cmd: List[str], ip: str, pty=False) -> str:
    with fabric.Connection(ip) as conn:
        return conn.run(" ".join(cmd), hide=True, pty=pty).stdout


def get_cloudlab_data_nic(ip=None) -> str:
    # ip addr show to 10.10.1.0/24
    cmd = ["ip", "addr", "show", "to", "10.10.1.0/24"]
    if ip:
        out = remote_check_output(cmd, ip)
    else:
        out = check_output(cmd, encoding="utf-8")

    return out.split()[1][:-1]


def get_nic_pci_addr(nic: str, ip=None) -> str:
    # ethtool -i eth0
    cmd = ["ethtool", "-i", nic]
    if ip:
        out = remote_check_output(cmd, ip)
    else:
        out = check_output(cmd, encoding="utf-8")
    for line in out.splitlines():
        if line.startswith("bus-info"):
            return line.split()[1]
    raise RuntimeError("Could not find PCI address for NIC %s" % nic)


def get_mellanox_interrupt_list(nic_pci: str, ip=None) -> List[str]:
    # cat /proc/interrupts | grep $PCI_ADDR | grep comp | awk '{print $1}' | sed 's/://'
    cmd = ["cat", "/proc/interrupts"]
    if ip:
        out = remote_check_output(cmd, ip)
    else:
        out = check_output(cmd, encoding="utf-8")
    interrupts = []
    for line in out.splitlines():
        if nic_pci in line:
            if "async" in line:
                log.info("Skipping async interrupt: %s (for Mellanox NICS)", line)
                continue
            interrupts.append(line.split()[0][:-1])
    return interrupts


def get_broadcom_interrupt_list(nic_name: str, ip=None) -> List[str]:
    # cat /proc/interrupts | grep $PCI_ADDR | grep comp | awk '{print $1}' | sed 's/://'
    cmd = ["cat", "/proc/interrupts"]
    if ip:
        out = remote_check_output(cmd, ip)
    else:
        out = check_output(cmd, encoding="utf-8")
    interrupts = []
    for line in out.splitlines():
        if nic_name in line:
            interrupts.append(line.split()[0][:-1])
    return interrupts


def get_target_irq(host_core: int, disk_path: str, ip: str, search_str: str) -> int:
    cmd = ["sudo", "taskset", "-c", str(host_core), "fio", "--filename=%s" % disk_path,
           "--direct=1", "--rw=randread", "--bs=512b", "--ioengine=psync",
           "--iodepth=1", "--numjobs=1", "--time_based", "--group_reporting",
           "--name=iops-test-job", "--eta-newline=1", "--readonly",
           "--runtime=15"]
    for retry in range(5):
        # Don't capture output
        p = Popen(cmd, stdout=DEVNULL, stderr=DEVNULL)
        # Find out the TCP connection that is actively being used
        sleep(13)
        out = remote_check_output(["irqstat", "-t", "1", "-i", "2", "--rows", "2"],
                                  ip, pty=True)
        # Example output:
        # interactive commands -- t: view totals, 0-9: view node, any other key: quit
        # Fri Apr  7 16:19:47 2023
        # IRQs / 1 second(s)
        # IRQ#  TOTAL  NODE0   NODE1  NAME
        #  568  21914  21914       0  IR-PCI-MSI 26216456-edge eno12409np1-TxRx
        p.wait()
        for line in out.splitlines():
            line = line.strip()
            if search_str in line:
                return int(line.split()[0])
        log.info("Could not find the target irq in the output, retrying...")
    raise RuntimeError("Could not find the target irq after 5 retries")


def get_nvmeof_tcp_client_port_for_core(core: int, disk_path: str) -> str:
    cmd = ["sudo", "taskset", "-c", str(core), "fio", "--filename=%s" % disk_path,
           "--direct=1", "--rw=randread", "--bs=4096b", "--ioengine=psync",
           "--iodepth=1", "--numjobs=1", "--time_based", "--group_reporting",
           "--name=iops-test-job", "--eta-newline=1", "--readonly",
           "--runtime=15"]
    for retry in range(5):
        # Don't capture output
        p = Popen(cmd, stdout=DEVNULL, stderr=DEVNULL)
        # Find out the TCP connection that is actively being used
        sleep(15)
        out = check_output(["sudo", "ss", "-t"], encoding="utf-8")
        p.wait()
        candidate_lines = []
        for line in out.splitlines():
            # Pattern: ESTAB  0       0              10.10.1.1:4420          10.10.1.2:34108
            if "ESTAB" in line and "4420" in line:
                traffic_1 = line.split()[1]
                traffic_2 = line.split()[2]
                if traffic_1 == "0" and traffic_2 == "0":
                    continue
                candidate_lines.append(line)
        if len(candidate_lines) == 0:
            log.info("Could not find any active TCP connections, retrying...")
            continue
        if len(candidate_lines) > 1:
            raise RuntimeError(
                "Found more than one active TCP connection. Lines: %s" % candidate_lines)
        line = candidate_lines[0]
        ip_port_1 = line.split()[3]
        ip_port_2 = line.split()[4]
        port_1 = ip_port_1.split(":")[1]
        port_2 = ip_port_2.split(":")[1]
        if port_1 != "4420" and port_2 != "4420":
            raise RuntimeError(
                "Unexpected port numbers: %s, %s" % (port_1, port_2))
        if port_1 == "4420":
            return port_2
        return port_1
    raise RuntimeError("Could not find the client port after 5 retries")


def reset_flow_steering(nic: str, num_queues: int, ip=None):
    cmd = ["ethtool", "-u", nic]
    if ip:
        out = remote_check_output(cmd, ip)
    else:
        out = check_output(cmd, encoding="utf-8")
    filter_ids = []
    for line in out.splitlines():
        if line.startswith("Filter:"):
            filter_id = line.split()[1]
            filter_ids.append(filter_id)
    for filter_id in filter_ids:
            cmd = ["sudo", "ethtool", "-U", nic, "delete", filter_id]
            if ip:
                remote_check_output(cmd, ip)
            else:
                check_output(cmd, encoding="utf-8")
    cmd = ["sudo", "ethtool", "--set-channels", nic, "combined",
           str(num_queues)]
    if ip:
        remote_check_output(cmd, ip)
    else:
        check_output(cmd, encoding="utf-8")


def install_flow_steering(nic: str, client_port: str, core: int, irq: int,
                          ip=None, install_rule=True):
    if install_rule:
        #   sudo ethtool -U $NIC flow-type tcp4 dst-port 4420 src-port $CLIENT_PORT action $IDX
        cmd_1 = ["sudo", "ethtool", "-U", nic, "flow-type", "tcp4",
                "dst-port", "4420", "src-port", client_port, "action", str(core)]
        cmd_2 = ["sudo", "ethtool", "-U", nic, "flow-type", "tcp4",
                "dst-port", client_port, "src-port", "4420", "action", str(core)]
        for cmd in [cmd_1, cmd_2]:
            if ip:
                remote_check_output(cmd, ip)
            else:
                check_output(cmd, encoding="utf-8")
    # Pin the IRQs to the core
    # sudo sh -c "echo '0000,00000001' > /proc/irq/$IRQ/smp_affinity"
    # Read the existing mask
    irq_affinity_file = "/proc/irq/%s/smp_affinity" % irq
    cmd = ["cat", irq_affinity_file]
    if ip:
        out = remote_check_output(cmd, ip)
    else:
        out = check_output(cmd, encoding="utf-8")
    parts = out.strip().split(",")
    if len(parts) == 1:
        first_part = ""
        mask_len = len(parts[0])
    elif len(parts) > 1:
        first_part = ",".join(["0" * len(parts[i]) for i in range(0, len(parts)-1)]) + ","
        mask_len = len(parts[1])
    else:
        raise RuntimeError("Unexpected irq mask: %s in file %s" %
                           (out, irq_affinity_file))
    # First part is "0" times the length of the first part
    cpu_mask = 0
    cpu_mask |= 1 << core
    hex_cpu_mask = hex(cpu_mask)[2:]
    padded_hex_cpu_mask = '{:0>{}}'.format(hex_cpu_mask, mask_len)
    if ip:
        remote_check_output(
            ["sudo", "sh", "-c", "\"echo '%s%s' > /proc/irq/%s/smp_affinity\"" % (first_part, padded_hex_cpu_mask, irq)], ip)
    else:
        check_output(
            ["sudo", "sh", "-c", "echo '%s%s' > /proc/irq/%s/smp_affinity" % (first_part, padded_hex_cpu_mask, irq)])


def disable_irqbalance(ip=None):
    cmds = [
        ["sudo", "systemctl", "stop", "irqbalance"],
        ["sudo", "systemctl", "disable", "irqbalance"],
    ]
    for cmd in cmds:
        if ip:
            remote_check_output(cmd, ip)
        else:
            check_output(cmd, encoding="utf-8")


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


def get_online_cores(ip=None):
    cmd = ["lscpu", "--json"]
    if ip:
        out = remote_check_output(cmd, ip)
    else:
        out = check_output(cmd, encoding="utf-8")
    lscpu_json = json.loads(out)
    online_cpus = []
    for field in lscpu_json["lscpu"]:
        if field["field"] == "On-line CPU(s) list:":
            online_cpus = parse_cpu_string(field["data"])
    if len(online_cpus) == 0:
        raise RuntimeError("Could not find On-line CPU(s) list")
    return online_cpus


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


def parse_args():
    parser = argparse.ArgumentParser(
        "Pin one TCP connection per core for NVMEoF-TCP.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--disk-path", required=True,
                        help="Path to the NVMEoF disk. E.g. /dev/nvme0n1")
    parser.add_argument("--target-ip", default=get_default_target_ip(),
                        required=True, help="IP address of the NVMEoF target.")
    parser.add_argument("--cores", default=1, type=int,
                        help="Number of cores to pin the connections to.")
    parser.add_argument("--cloudlab-profile", default="nvmeof-bench",
                        choices=["nvmeof-bench", "optane-plus-client"],
                        help="Cloudlab profile name. Used to determine the NIC"
                             " types.")
    return parser.parse_args()


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    # Disable paramiko logging
    logging.getLogger("paramiko").setLevel(logging.ERROR)
    args = parse_args()
    if args.cloudlab_profile == "nvmeof-bench":
        log.info("Running in nvmeof-bench profile")
        pin_for_nvmeof_bench_profile(args)
    elif args.cloudlab_profile == "optane-plus-client":
        log.info("Running in optane-plus-client profile")
        pin_for_optane_plus_client_profile(args)
    else:
        raise RuntimeError("Unknown profile: %s" % args.cloudlab_profile)

def pin_for_optane_plus_client_profile(args):
    cores = args.cores
    log.info("Cores: %d", cores)
    target_ip = args.target_ip
    log.info("Target IP: %s", target_ip)
    log.info("Disabling hyperthreading")
    disable_hyperthreading()
    disable_hyperthreading(target_ip)
    # Disable all CPUs of the second NUMA node in the remote machine
    log.info("Disabling extra NUMA CPUs for target")
    disable_extra_numa_cpus(target_ip)
    log.info("Disabling irqbalance")
    disable_irqbalance()
    disable_irqbalance(target_ip)
    host_nic = get_cloudlab_data_nic()
    target_nic = get_cloudlab_data_nic(target_ip)
    log.info("Host NIC: %s", host_nic)
    log.info("Target NIC: %s", target_nic)
    host_nic_pci = get_nic_pci_addr(host_nic)
    target_nic_pci = get_nic_pci_addr(target_nic, target_ip)
    log.info("Host NIC PCI: %s", host_nic_pci)
    log.info("Target NIC PCI: %s", target_nic_pci)
    host_interrupts = get_mellanox_interrupt_list(host_nic_pci)
    target_interrupts = get_broadcom_interrupt_list(target_nic, target_ip)
    log.info("Host interrupts: %s", host_interrupts)
    log.info("Target interrupts: %s", target_interrupts)
    log.info("Resetting flow steering rules")
    reset_flow_steering(host_nic, cores)
    log.info("Not resetting flow steering rules on target, not supported")
    host_online_cores = get_online_cores()
    log.info("Host online cores: %s", host_online_cores)
    target_online_cores = get_online_cores(target_ip)
    log.info("Target online cores: %s", target_online_cores)
    used_target_irqs = set()
    for idx in range(cores):
        # Find out the TCP connection for this core
        client_port = get_nvmeof_tcp_client_port_for_core(host_online_cores[idx], args.disk_path)
        log.info("Client port for core %d: %s", host_online_cores[idx], client_port)
        # Install flow-steering rules
        log.info("Installing flow steering for core %d", host_online_cores[idx])
        log.info("Installing flow steering for host NIC %s", host_nic)
        install_flow_steering(host_nic, client_port, host_online_cores[idx], host_interrupts[idx])
        log.info("Not installing flow steering for target NIC %s, not supported", target_nic)
        target_irq = get_target_irq(host_online_cores[idx], args.disk_path, target_ip, target_nic)
        if target_irq in used_target_irqs:
            log.info("Target IRQ %s already used, skipping", target_irq)
            continue
        log.info("Pinning target IRQ %s to target core %s",
                 target_irq, target_online_cores[idx])
        install_flow_steering(target_nic, client_port,
                              target_online_cores[idx], target_irq, ip=target_ip,
                              install_rule=False)
        used_target_irqs.add(target_irq)


def pin_for_nvmeof_bench_profile(args):
    cores = args.cores
    log.info("Cores: %d", cores)
    target_ip = args.target_ip
    log.info("Target IP: %s", target_ip)
    log.info("Disabling hyperthreading")
    disable_hyperthreading()
    disable_hyperthreading(target_ip)
    log.info("Disabling extra NUMA CPUs for host and target")
    disable_extra_numa_cpus()
    disable_extra_numa_cpus(target_ip)
    log.info("Disabling irqbalance")
    disable_irqbalance()
    disable_irqbalance(target_ip)
    host_nic = get_cloudlab_data_nic()
    target_nic = get_cloudlab_data_nic(target_ip)
    log.info("Host NIC: %s", host_nic)
    log.info("Target NIC: %s", target_nic)
    host_nic_pci = get_nic_pci_addr(host_nic)
    target_nic_pci = get_nic_pci_addr(target_nic, target_ip)
    log.info("Host NIC PCI: %s", host_nic_pci)
    log.info("Target NIC PCI: %s", target_nic_pci)
    host_interrupts = get_mellanox_interrupt_list(host_nic_pci)
    target_interrupts = get_mellanox_interrupt_list(target_nic_pci, target_ip)
    log.info("Host interrupts: %s", host_interrupts)
    log.info("Target interrupts: %s", target_interrupts)
    log.info("Resetting flow steering rules")
    reset_flow_steering(host_nic, cores)
    reset_flow_steering(target_nic, cores, ip=target_ip)
    host_online_cores = get_online_cores()
    log.info("Host online cores: %s", host_online_cores)
    target_online_cores = get_online_cores(target_ip)
    log.info("Target online cores: %s", target_online_cores)
    for idx in range(cores):
        # Find out the TCP connection for this core
        client_port = get_nvmeof_tcp_client_port_for_core(host_online_cores[idx], args.disk_path)
        log.info("Client port for core %d: %s", host_online_cores[idx], client_port)
        # Install flow-steering rules
        log.info("Installing flow steering for host core %d", host_online_cores[idx])
        log.info("Installing flow steering for host NIC %s", host_nic)
        install_flow_steering(host_nic, client_port, host_online_cores[idx], host_interrupts[idx])
        log.info("Installing flow steering for target core %s", target_online_cores[idx])
        log.info("Installing flow steering for target NIC %s", target_nic)
        install_flow_steering(target_nic, client_port,
                              target_online_cores[idx], target_interrupts[idx], ip=target_ip)


if __name__ == "__main__":
    sys.exit(main())

